// DRLB TCP load balancer
// Copyright (c) 2016-2026 DataReel Software Development
// GNU General Public License version 3 or later, see the COPYING file.
//
// Port multiplexer (mode = MUX), new in 2.2. Many local TCP and UDP
// ports ([MUXPORT]) are carried over one TLS tunnel connection to a peer
// DRLB, which delivers each channel to its destination ([MUXDEST]), load
// balanced over [LBNODE]s. Both ends can have ports and destinations, so
// channels go both ways over the same tunnel.
//
// Wire protocol DRMX version 1: after the TLS handshake every message is
// a frame with a 12 byte header in network byte order
//
//   version u8 | type u8 | channel u16 | stream u32 | length u16 | flags u16
//
// followed by length payload bytes. The first frame from each side is
// HELLO, which lists the channels that side delivers (its [MUXDEST]s)
// with the channel ids the other side uses in OPEN. Streams opened by the
// side that connected the tunnel have odd ids, streams opened by the
// side that accepted it have even ids. TCP streams are flow controlled
// per stream with WINDOW credit, so a slow service only stops its own
// stream. UDP datagrams travel one per DGRAM frame and are dropped, not
// queued without limit, when the tunnel is congested.
//
// One event loop thread (epoll, non-blocking sockets and OpenSSL) owns
// the tunnels and every local socket. Blocking work (DNS, backend connect
// with retries, the tunnel TLS handshake) runs in short worker threads
// that hand their result back to the loop.

#include "drlb.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <deque>
#include <map>
#include <sstream>
#include <thread>
#include <unordered_map>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

namespace drlb {

namespace {

// Frame types
enum : uint8_t {
  F_HELLO = 1, F_OPEN = 2, F_OPEN_OK = 3, F_OPEN_FAIL = 4, F_DATA = 5, F_WINDOW = 6,
  F_FIN = 7, F_RST = 8, F_DGRAM = 9, F_PING = 10, F_PONG = 11, F_GOAWAY = 12
};
const uint8_t DRMX_VERSION = 1;
const size_t HDR = 12;
const size_t MAX_PAYLOAD = 65535;

struct Tunnel;
struct Stream;
struct PortRt;
void port_release_held(PortRt &p, bool expire);

enum HandleType { H_EVENT, H_TUNNEL_LISTEN, H_TUNNEL, H_PORT_TCP, H_PORT_UDP, H_STREAM };
struct Handle {
  HandleType type;
  void *ptr;
};

struct Stream {
  uint32_t id = 0;
  Tunnel *t = nullptr;
  bool initiator = false; // Opened on this side (from a [MUXPORT])
  bool udp = false;
  int fd = -1;            // Local socket; for an initiator UDP flow the port socket is used
  uint64_t key = 0;
  uint32_t events = 0;
  bool in_epoll = false;
  PortRt *port = nullptr;
  MuxDest *dest = nullptr;
  Node *node = nullptr;
  bool connecting = false; // Destination connect running in a worker
  bool local_eof = false;  // Local side closed its write side, FIN sent
  bool remote_eof = false; // FIN received
  bool shut_wr = false;    // shutdown(SHUT_WR) done on the local socket
  bool dead = false;
  long long send_credit = 0;  // Bytes we may still send to the peer
  long long unreturned = 0;   // Bytes received, credit not yet returned
  long long consumed = 0;     // Bytes written locally, to return with WINDOW
  std::string rbuf;           // Data from the peer waiting for the local socket
  size_t roff = 0;
  std::deque<std::string> dq; // UDP datagrams waiting for the destination connect
  size_t dq_bytes = 0;
  struct sockaddr_in addr;    // Initiator UDP flow: the local client address
  uint64_t flow_key = 0;
  time_t last_active = 0;
  std::string client;         // Client address and port, for logs and LB_ASSIGNED

  size_t rbuf_size() const { return rbuf.size() - roff; }
};

struct RemoteChannel {
  uint16_t id;
  int udp;
};

struct Tunnel {
  uint64_t id = 0;
  int fd = -1;
  uint64_t key = 0;
  SSL *ssl = nullptr;
  bool connector = false; // This side connected the tunnel
  int slot = -1;          // Connector slot
  std::string label;      // Remote address, or the [MUXTUNNEL] name
  std::string peer_name;  // From HELLO
  bool hello_rx = false;
  bool dead = false;
  bool goaway_sent = false;
  bool congested = false;
  bool more = false;              // Read stopped at the per turn limit
  bool read_wants_write = false;  // SSL_read returned WANT_WRITE
  bool write_wants_read = false;  // SSL_write returned WANT_READ
  uint32_t events = 0;
  bool in_epoll = false;
  std::string in;
  size_t in_off = 0;
  std::string out;
  size_t out_off = 0;
  std::unordered_map<uint32_t, Stream *> streams;
  std::map<std::string, RemoteChannel> remote_channels;
  uint32_t next_stream = 1;
  long long peer_window = 262144;
  time_t created = 0, last_rx = 0, last_ping = 0, up_since = 0;
  long rtt_ms = -1;
  unsigned long long bytes_tx = 0, bytes_rx = 0;
  unsigned long streams_total = 0;

  size_t out_size() const { return out.size() - out_off; }
};

struct PortRt {
  MuxPort *cfg = nullptr;
  int fd = -1;
  uint64_t key = 0;
  unsigned long rr = 0;
  std::unordered_map<uint64_t, Stream *> flows; // UDP flows by client address
  struct Held { int fd; std::string client; time_t since; };
  std::deque<Held> held; // TCP clients waiting for a tunnel (mux_hold_secs)
};

// Connector slot: one tunnel connection to a [MUXTUNNEL] peer
struct Slot {
  const MuxTunnelConfig *tc = nullptr;
  int state = 0; // 0 down, 1 connecting, 2 up
  time_t next_try = 0;
  time_t last_try = 0;
  int backoff = 0;
  uint64_t tunnel_id = 0;
  std::string last_error;
};

// Result of a worker
struct Completion {
  int kind = 0; // 1 destination connect, 2 tunnel connected, 3 tunnel accepted
  uint64_t tunnel_id = 0;
  uint32_t stream_id = 0;
  int fd = -1;
  SSL *ssl = nullptr;
  Node *node = nullptr;
  int slot = -1;
  std::string label;
  std::string error;
};

int epfd = -1;
std::atomic<int> event_fd{-1};
std::thread loop_thread;
std::atomic<int> workers{0};
std::atomic<int> handshakes{0}; // Tunnel TLS handshakes running in workers
std::atomic<bool> loop_stop{false};

std::unordered_map<uint64_t, Handle> handles;
uint64_t next_key = 1;
std::unordered_map<uint64_t, Tunnel *> tunnels;
uint64_t next_tunnel_id = 1;
std::vector<PortRt> ports;
std::vector<Slot> slots;
int tunnel_listen_fd = -1;
uint64_t tunnel_listen_key = 0;
std::vector<Tunnel *> dead_tunnels;
std::vector<Stream *> dead_streams;
std::vector<Tunnel *> dirty; // Tunnels with output to flush

std::mutex cq_lock;
std::vector<Completion> cq;

std::mutex report_lock;
std::string tunnel_report;

std::string ssl_errors()
{
  std::string out;
  unsigned long e;
  while((e = ERR_get_error()) != 0) {
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    if(!out.empty()) out += "; ";
    out += buf;
  }
  return out;
}

void put16(char *p, uint16_t v) { p[0] = (char)(v >> 8); p[1] = (char)v; }
void put32(char *p, uint32_t v) { p[0] = (char)(v >> 24); p[1] = (char)(v >> 16); p[2] = (char)(v >> 8); p[3] = (char)v; }
uint16_t get16(const char *p) { return (uint16_t)(((uint8_t)p[0] << 8) | (uint8_t)p[1]); }
uint32_t get32(const char *p)
{
  return ((uint32_t)(uint8_t)p[0] << 24) | ((uint32_t)(uint8_t)p[1] << 16) | ((uint32_t)(uint8_t)p[2] << 8) | (uint8_t)p[3];
}

bool valid_name(const std::string &s)
{
  if(s.empty() || s.size() > 64) return false;
  for(char c : s) {
    if(!(isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.')) return false;
  }
  return true;
}

std::string addr_string(const struct sockaddr_in &a)
{
  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &a.sin_addr, ip, sizeof(ip));
  return std::string(ip) + " " + std::to_string(ntohs(a.sin_port));
}

std::string tname(const Tunnel *t)
{
  return "Tunnel " + t->label + (t->peer_name.empty() ? "" : " (" + t->peer_name + ")");
}

std::string sname(const Stream *s)
{
  std::string ch = s->port ? s->port->cfg->channel : (s->dest ? s->dest->channel : "?");
  return "[" + ch + " " + std::to_string(s->id) + "]: ";
}

void set_nonblock(int fd)
{
  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void post(Completion &&c)
{
  {
    std::lock_guard<std::mutex> lock(cq_lock);
    cq.push_back(std::move(c));
  }
  uint64_t one = 1;
  int fd = event_fd;
  if(fd >= 0 && write(fd, &one, sizeof(one)) < 0) { } // Counter overflow cannot happen here
}

// epoll registration. An object with no events is taken out of epoll,
// because EPOLLHUP is reported even with an empty event mask.
uint64_t add_handle(HandleType type, void *ptr)
{
  uint64_t k = next_key++;
  handles[k] = Handle{type, ptr};
  return k;
}

void set_events(int fd, uint64_t key, uint32_t ev, uint32_t &cur, bool &in_epoll)
{
  if(fd < 0) return;
  if(ev == 0) {
    if(in_epoll) {
      epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
      in_epoll = false;
    }
    cur = 0;
    return;
  }
  if(in_epoll && ev == cur) return;
  struct epoll_event e;
  memset(&e, 0, sizeof(e));
  e.events = ev;
  e.data.u64 = key;
  if(epoll_ctl(epfd, in_epoll ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, fd, &e) == 0) {
    in_epoll = true;
    cur = ev;
  }
}

void remove_fd(int fd, uint64_t key, bool &in_epoll)
{
  if(fd >= 0 && in_epoll) epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
  in_epoll = false;
  handles.erase(key);
}

// ---------------------------------------------------------------------
// Frames

void mark_dirty(Tunnel *t)
{
  if(t->dead) return;
  dirty.push_back(t);
}

void update_stream_events(Stream *s);

void check_congestion(Tunnel *t)
{
  bool c = t->out_size() > (size_t)cfg.mux.tunnel_buffer;
  if(c == t->congested) return;
  if(!c && t->out_size() > (size_t)cfg.mux.tunnel_buffer / 2) return; // Resume below half
  t->congested = c;
  for(auto &kv : t->streams) update_stream_events(kv.second);
}

void put_frame(Tunnel *t, uint8_t type, uint16_t channel, uint32_t sid, const char *data, size_t len)
{
  if(t->dead) return;
  if(len > MAX_PAYLOAD) len = MAX_PAYLOAD;
  char h[HDR];
  h[0] = (char)DRMX_VERSION;
  h[1] = (char)type;
  put16(h + 2, channel);
  put32(h + 4, sid);
  put16(h + 8, (uint16_t)len);
  put16(h + 10, 0);
  t->out.append(h, HDR);
  if(len) t->out.append(data, len);
  t->bytes_tx += HDR + len;
  mark_dirty(t);
  if(!t->congested && t->out_size() > (size_t)cfg.mux.tunnel_buffer) check_congestion(t);
}

void put_frame(Tunnel *t, uint8_t type, uint32_t sid, const std::string &payload)
{
  put_frame(t, type, 0, sid, payload.data(), payload.size());
}

void put_window(Tunnel *t, uint32_t sid, uint32_t credit)
{
  char b[4];
  put32(b, credit);
  put_frame(t, F_WINDOW, 0, sid, b, 4);
}

std::string hello_payload()
{
  std::ostringstream m;
  m << "DRMX 1\n"
    << "peer " << cfg.mux.peer_name << "\n"
    << "version " << VersionString << "\n"
    << "window " << cfg.mux.stream_window << "\n";
  for(size_t i = 0; i < cfg.mux.dests.size(); i++) {
    const MuxDest *d = cfg.mux.dests[i].get();
    m << "chan " << (i + 1) << " " << (d->udp ? "udp" : "tcp") << " " << d->channel << "\n";
  }
  return m.str();
}

// ---------------------------------------------------------------------
// Streams

void update_stream_events(Stream *s)
{
  if(s->dead || s->fd < 0 || s->connecting) return;
  if(s->udp && s->initiator) return; // Uses the port socket
  uint32_t ev = 0;
  if(s->udp) {
    ev = EPOLLIN;
  }
  else {
    if(!s->local_eof && s->send_credit > 0 && !s->t->congested) ev |= EPOLLIN | EPOLLRDHUP;
    if(s->rbuf_size() > 0) ev |= EPOLLOUT;
  }
  set_events(s->fd, s->key, ev, s->events, s->in_epoll);
}

void close_stream(Stream *s, bool send_rst, const std::string &reason)
{
  if(s->dead) return;
  s->dead = true;
  if(cfg.log_level >= 2) {
    log_message(sname(s) + "Stream closed" + (reason.empty() ? "" : ": " + reason) + (s->client.empty() ? "" : ", client " + s->client));
  }
  if(send_rst && s->t && !s->t->dead) put_frame(s->t, F_RST, s->id, reason);
  if(s->fd >= 0 && !(s->udp && s->initiator)) {
    remove_fd(s->fd, s->key, s->in_epoll);
    close(s->fd);
  }
  s->fd = -1;
  if(s->node) {
    s->node->remove_connection();
    s->node = nullptr;
  }
  if(s->port) {
    s->port->cfg->streams_open--;
    if(s->udp) s->port->flows.erase(s->flow_key);
  }
  if(s->dest) s->dest->streams_open--;
  if(s->t) s->t->streams.erase(s->id);
  dead_streams.push_back(s);
}

void maybe_finish(Stream *s)
{
  if(!s->dead && !s->udp && s->local_eof && s->remote_eof && s->rbuf_size() == 0 && !s->connecting) {
    close_stream(s, false, "");
  }
}

void stream_write(Stream *s)
{
  if(s->dead || s->fd < 0 || s->connecting) return;
  while(s->rbuf_size() > 0) {
    ssize_t n = send(s->fd, s->rbuf.data() + s->roff, s->rbuf_size(), MSG_NOSIGNAL);
    if(n < 0) {
      if(errno == EINTR) continue;
      if(errno == EAGAIN || errno == EWOULDBLOCK) break;
      close_stream(s, true, "local write error, " + errno_string(errno));
      return;
    }
    s->roff += (size_t)n;
    s->consumed += n;
    if(s->port) s->port->cfg->bytes_in += (unsigned long long)n;
    if(s->dest) s->dest->bytes_out += (unsigned long long)n;
    s->last_active = time(nullptr);
  }
  if(s->roff == s->rbuf.size()) {
    s->rbuf.clear();
    s->roff = 0;
  }
  else if(s->roff > 65536 && s->roff > s->rbuf.size() / 2) {
    s->rbuf.erase(0, s->roff);
    s->roff = 0;
  }
  // Return credit in batches of a quarter window
  if(s->consumed > 0 && (s->consumed >= cfg.mux.stream_window / 4 || (s->rbuf_size() == 0 && s->consumed >= 4096))) {
    put_window(s->t, s->id, (uint32_t)s->consumed);
    s->unreturned -= s->consumed;
    s->consumed = 0;
  }
  if(s->rbuf_size() == 0 && s->remote_eof && !s->shut_wr) {
    shutdown(s->fd, SHUT_WR);
    s->shut_wr = true;
  }
  update_stream_events(s);
  maybe_finish(s);
}

// Local TCP socket readable: one frame per turn, so streams share the tunnel
void stream_read(Stream *s)
{
  if(s->dead || s->fd < 0 || s->local_eof || s->connecting) return;
  if(s->send_credit <= 0 || s->t->congested) {
    update_stream_events(s);
    return;
  }
  size_t want = (size_t)std::min<long long>(s->send_credit, cfg.mux.frame_size);
  char buf[65536];
  ssize_t n;
  do {
    n = recv(s->fd, buf, want, 0);
  } while(n < 0 && errno == EINTR);
  if(n > 0) {
    put_frame(s->t, F_DATA, 0, s->id, buf, (size_t)n);
    s->send_credit -= n;
    if(s->port) s->port->cfg->bytes_out += (unsigned long long)n;
    if(s->dest) s->dest->bytes_in += (unsigned long long)n;
    s->last_active = time(nullptr);
    if(s->send_credit <= 0) update_stream_events(s);
    return;
  }
  if(n == 0) {
    s->local_eof = true;
    put_frame(s->t, F_FIN, s->id, std::string());
    update_stream_events(s);
    maybe_finish(s);
    return;
  }
  if(errno == EAGAIN || errno == EWOULDBLOCK) return;
  close_stream(s, true, "local read error, " + errno_string(errno));
}

// Datagram from the destination socket (the side that delivers a UDP channel)
void dest_udp_read(Stream *s)
{
  char buf[65536];
  for(int i = 0; i < 64 && !s->dead; i++) {
    ssize_t n = recv(s->fd, buf, sizeof(buf), 0);
    if(n < 0) {
      if(errno == EINTR || errno == ECONNREFUSED) continue; // ICMP port unreachable
      return;
    }
    s->last_active = time(nullptr);
    if(s->t->out_size() > (size_t)cfg.mux.tunnel_buffer + (size_t)cfg.mux.udp_queue_bytes) {
      s->dest->udp_dropped++;
      continue;
    }
    put_frame(s->t, F_DGRAM, 0, s->id, buf, (size_t)n);
    s->dest->bytes_in += (unsigned long long)n;
  }
}

void udp_deliver(Stream *s, const char *data, size_t len)
{
  s->last_active = time(nullptr);
  if(s->initiator) {
    ssize_t n = sendto(s->port->fd, data, len, MSG_DONTWAIT, (struct sockaddr *)&s->addr, sizeof(s->addr));
    if(n < 0) s->port->cfg->udp_dropped++;
    else s->port->cfg->bytes_in += len;
    return;
  }
  if(s->connecting) {
    if(s->dq.size() >= 256 || s->dq_bytes + len > (size_t)cfg.mux.udp_queue_bytes) {
      s->dest->udp_dropped++;
      return;
    }
    s->dq.emplace_back(data, len);
    s->dq_bytes += len;
    return;
  }
  ssize_t n = send(s->fd, data, len, MSG_DONTWAIT | MSG_NOSIGNAL);
  if(n < 0) s->dest->udp_dropped++;
  else s->dest->bytes_out += len;
}

// ---------------------------------------------------------------------
// Destination selection, in a worker thread (blocking calls allowed)

int udp_connect(const Node *n, std::string &error_message)
{
  struct addrinfo hints, *res = nullptr;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  int rv = getaddrinfo(n->hostname.c_str(), nullptr, &hints, &res);
  if(rv != 0 || !res) {
    error_message = std::string("Cannot resolve host name, ") + gai_strerror(rv);
    if(res) freeaddrinfo(res);
    return -1;
  }
  struct sockaddr_in sin;
  memcpy(&sin, res->ai_addr, sizeof(sin));
  freeaddrinfo(res);
  sin.sin_port = htons((uint16_t)n->port_number);
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if(fd < 0) {
    error_message = "socket() failed, " + errno_string(errno);
    return -1;
  }
  if(connect(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    error_message = errno_string(errno);
    close(fd);
    return -1;
  }
  return fd;
}

Node *assigned_node(MuxDest *d, const std::string &client_ip)
{
  std::string hostname, err;
  bool looked_up = false;
  for(const auto &rule : cfg.rules) {
    bool match = regexec(&rule->regex, client_ip.c_str(), 0, nullptr, 0) == 0;
    if(!match && cfg.resolve_assigned_hostnames) {
      if(!looked_up) {
        if(ip_to_hostname(client_ip, hostname, err) != 0) hostname.clear();
        looked_up = true;
      }
      if(!hostname.empty() && hostname != client_ip) match = regexec(&rule->regex_icase, hostname.c_str(), 0, nullptr, 0) == 0;
    }
    if(!match) continue;
    for(Node *n : d->nodes) if(n->node_name == rule->node_name) return n;
  }
  return nullptr;
}

// Candidate order for one connection, as in the load balancer: round
// robin over live nodes; weighted and distributed pick the node furthest
// below its share of the channel's connections (weight, or load percent),
// then the others; assigned tries the rules file node first.
std::vector<Node *> candidates(MuxDest *d, const std::string &client_ip)
{
  std::vector<Node *> order;
  Scheme s = d->scheme;
  if(s == LB_ASSIGNED) {
    Node *a = assigned_node(d, client_ip);
    if(a) order.push_back(a);
    s = d->assigned_default;
    if(s == LB_NONE) return order;
  }
  time_t now = time(nullptr);
  std::vector<Node *> live;
  for(Node *n : d->nodes) if(n->down_until <= now) live.push_back(n);
  if(live.empty()) live = d->nodes;
  if(live.empty()) return order;
  size_t start = d->rr.fetch_add(1, std::memory_order_relaxed) % live.size();
  std::vector<Node *> rot;
  for(size_t i = 0; i < live.size(); i++) rot.push_back(live[(start + i) % live.size()]);
  if(s == LB_WEIGHTED || s == LB_DISTRIB) {
    std::stable_sort(rot.begin(), rot.end(), [](Node *a, Node *b) {
      double wa = a->weight > 0 ? a->weight : 1, wb = b->weight > 0 ? b->weight : 1;
      return (a->num_connections + 1) / wa < (b->num_connections + 1) / wb;
    });
  }
  for(Node *n : rot) if(order.empty() || order[0] != n) order.push_back(n);
  return order;
}

void dest_connect_worker(uint64_t tunnel_id, uint32_t sid, MuxDest *d, std::string client)
{
  Completion c;
  c.kind = 1;
  c.tunnel_id = tunnel_id;
  c.stream_id = sid;
  std::string client_ip = client.substr(0, client.find(' '));
  std::string seq = "[" + d->channel + " " + std::to_string(sid) + "]: ";
  unsigned retries = cfg.retries;
  while(c.fd < 0) {
    std::vector<Node *> order = candidates(d, client_ip);
    for(Node *n : order) {
      if(n->max_connections >= 1 && n->num_connections >= n->max_connections) {
        if(cfg.log_level >= 2) log_message(seq + n->node_name + " is at max_connections");
        continue;
      }
      std::string err;
      int fd = d->udp ? udp_connect(n, err) : connect_to_node(n, cfg.connect_timeout_secs, err);
      if(fd >= 0) {
        n->add_connection();
        n->down_until = 0;
        c.fd = fd;
        c.node = n;
        if(cfg.log_level >= 2) {
          log_message(seq + n->node_name + " connected to " + n->hostname + " port " + std::to_string(n->port_number) +
                      (client.empty() ? "" : " for client " + client));
        }
        break;
      }
      if(cfg.dead_node_secs > 0) n->down_until = time(nullptr) + cfg.dead_node_secs;
      if(cfg.log_level >= 1) {
        log_message(seq + "ERROR - " + n->node_name + " cannot connect to " + n->hostname + " port " +
                    std::to_string(n->port_number) + ", " + err);
      }
      c.error = n->node_name + ": " + err;
    }
    if(c.fd >= 0 || order.empty() || retries == 0 || loop_stop) break;
    retries--;
    if(cfg.retry_wait > 0) sleep_secs(cfg.retry_wait);
  }
  if(c.fd < 0 && c.error.empty()) c.error = "no destination node available";
  post(std::move(c));
  workers--;
}

// ---------------------------------------------------------------------
// Tunnel handshake workers

void handshake_info(SSL *ssl, std::string &info)
{
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
  const char *g = SSL_get0_group_name(ssl);
#else
  // OpenSSL 1.1.1 to 3.1 (the RHEL 8 FIPS build): name the group from
  // the ephemeral key exchange key
  const char *g = nullptr;
  EVP_PKEY *key = nullptr;
  if(SSL_get_peer_tmp_key(ssl, &key) != 1) key = nullptr;
  if(!key && SSL_get_tmp_key(ssl, &key) != 1) key = nullptr;
  if(key) {
    int nid = EVP_PKEY_base_id(key);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    static thread_local char name[80];
    size_t len = 0;
    if(nid == EVP_PKEY_EC && EVP_PKEY_get_group_name(key, name, sizeof(name), &len) == 1) g = name;
#else
    if(nid == EVP_PKEY_EC) {
      const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(key);
      const EC_GROUP *grp = ec ? EC_KEY_get0_group(ec) : nullptr;
      if(grp) nid = EC_GROUP_get_curve_name(grp);
    }
#endif
    if(!g) g = OBJ_nid2sn(nid);
    EVP_PKEY_free(key);
  }
#endif
  info = std::string(SSL_get_version(ssl)) + " " + SSL_get_cipher_name(ssl) + " group " + (g ? g : "none");
}

void tunnel_connect_worker(int slot, MuxTunnelConfig tc)
{
  Completion c;
  c.kind = 2;
  c.slot = slot;
  c.label = (tc.name.empty() ? tc.remote_host : tc.name) + " " + tc.remote_host + ":" + std::to_string(tc.remote_port);
  Node n;
  n.hostname = tc.remote_host;
  n.port_number = tc.remote_port;
  std::string err;
  int fd = connect_to_node(&n, cfg.connect_timeout_secs, err);
  if(fd < 0) {
    c.error = err;
  }
  else if(!cfg.mux.plain) {
    const SSLConfig &ssl = cfg.ssl;
    set_socket_timeouts(fd, ssl.ssl_handshake_timeout_secs, ssl.ssl_handshake_timeout_secs);
    ERR_clear_error();
    SSL *s = SSL_new(ssl.client_ctx);
    if(!s || SSL_set_fd(s, fd) != 1) {
      c.error = "Cannot open the TLS session, " + ssl_errors();
    }
    else {
      const std::string &host = tc.ssl_hostname.empty() ? tc.remote_host : tc.ssl_hostname;
      unsigned char addr[16];
      bool is_ip = inet_pton(AF_INET, host.c_str(), addr) == 1 || inet_pton(AF_INET6, host.c_str(), addr) == 1;
      if(!is_ip) SSL_set_tlsext_host_name(s, host.c_str());
      if(ssl.ssl_verify_backend_cert) {
        X509_VERIFY_PARAM *param = SSL_get0_param(s);
        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if(is_ip) X509_VERIFY_PARAM_set1_ip_asc(param, host.c_str());
        else SSL_set1_host(s, host.c_str());
        SSL_set_verify(s, SSL_VERIFY_PEER, nullptr);
      }
      else {
        SSL_set_verify(s, SSL_VERIFY_NONE, nullptr);
      }
      if(SSL_connect(s) != 1) {
        long vr = SSL_get_verify_result(s);
        c.error = std::string("TLS handshake failed") +
                  (vr != X509_V_OK ? std::string(", certificate check: ") + X509_verify_cert_error_string(vr) : "");
        std::string e = ssl_errors();
        if(!e.empty()) c.error += ", " + e;
      }
      else {
        c.ssl = s;
        s = nullptr;
      }
    }
    if(s) SSL_free(s);
    if(!c.ssl) {
      close(fd);
      fd = -1;
    }
  }
  if(fd >= 0) set_socket_timeouts(fd, 0, 0);
  c.fd = fd;
  post(std::move(c));
  workers--;
}

void tunnel_accept_worker(int fd, std::string label)
{
  struct Done { ~Done() { handshakes--; } } done;
  Completion c;
  c.kind = 3;
  c.label = label;
  if(!cfg.mux.plain) {
    const SSLConfig &ssl = cfg.ssl;
    set_socket_timeouts(fd, ssl.ssl_handshake_timeout_secs, ssl.ssl_handshake_timeout_secs);
    ERR_clear_error();
    SSL *s = SSL_new(ssl.server_ctx);
    if(!s || SSL_set_fd(s, fd) != 1) {
      c.error = "Cannot open the TLS session, " + ssl_errors();
    }
    else if(SSL_accept(s) != 1) {
      long vr = SSL_get_verify_result(s);
      c.error = std::string("TLS handshake failed") +
                (vr != X509_V_OK ? std::string(", client certificate check: ") + X509_verify_cert_error_string(vr) : "");
      std::string e = ssl_errors();
      if(!e.empty()) c.error += ", " + e;
    }
    else {
      c.ssl = s;
      s = nullptr;
    }
    if(s) SSL_free(s);
    if(!c.ssl) {
      close(fd);
      fd = -1;
    }
  }
  if(fd >= 0) set_socket_timeouts(fd, 0, 0);
  c.fd = fd;
  post(std::move(c));
  workers--;
}

template <class F, class... A> bool spawn(F f, A... a)
{
  workers++;
  try {
    std::thread(f, a...).detach();
  }
  catch(const std::system_error &e) {
    workers--;
    log_message(std::string("ERROR - Cannot start a worker thread: ") + e.what());
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------
// Tunnels

void close_tunnel(Tunnel *t, const std::string &reason)
{
  if(t->dead) return;
  log_message(tname(t) + " closed: " + reason + " (" + std::to_string(t->streams.size()) + " streams reset)");
  // Streams end with the tunnel; their local sockets are closed
  std::vector<Stream *> list;
  for(auto &kv : t->streams) list.push_back(kv.second);
  t->dead = true;
  for(Stream *s : list) close_stream(s, false, "tunnel closed");
  t->streams.clear();
  remove_fd(t->fd, t->key, t->in_epoll);
  dead_tunnels.push_back(t);
  tunnels.erase(t->id);
  if(t->slot >= 0) {
    Slot &sl = slots[t->slot];
    sl.state = 0;
    sl.tunnel_id = 0;
    sl.backoff = sl.backoff <= 0 ? cfg.mux.retry_secs : std::min(sl.backoff * 2, 60);
    if(t->up_since) sl.backoff = cfg.mux.retry_secs; // It worked; start over
    sl.next_try = time(nullptr) + sl.backoff;
  }
}

void free_tunnel(Tunnel *t)
{
  if(t->ssl) {
    SSL_free(t->ssl);
    t->ssl = nullptr;
  }
  if(t->fd >= 0) close(t->fd);
  t->fd = -1;
  delete t;
}

void tunnel_events(Tunnel *t)
{
  if(t->dead) return;
  uint32_t ev = EPOLLIN | EPOLLRDHUP;
  if((t->out_size() > 0 && !t->write_wants_read) || t->read_wants_write) ev |= EPOLLOUT;
  set_events(t->fd, t->key, ev, t->events, t->in_epoll);
}

void tunnel_flush(Tunnel *t)
{
  if(t->dead) return;
  t->write_wants_read = false;
  while(t->out_size() > 0) {
    size_t len = std::min<size_t>(t->out_size(), 262144);
    const char *p = t->out.data() + t->out_off;
    int n;
    if(t->ssl) {
      ERR_clear_error();
      n = SSL_write(t->ssl, p, (int)len);
      if(n <= 0) {
        int e = SSL_get_error(t->ssl, n);
        if(e == SSL_ERROR_WANT_WRITE) break;
        if(e == SSL_ERROR_WANT_READ) { t->write_wants_read = true; break; }
        close_tunnel(t, "TLS write failed, " + ssl_errors());
        return;
      }
    }
    else {
      n = (int)send(t->fd, p, len, MSG_NOSIGNAL);
      if(n < 0) {
        if(errno == EINTR) continue;
        if(errno == EAGAIN || errno == EWOULDBLOCK) break;
        close_tunnel(t, "write failed, " + errno_string(errno));
        return;
      }
    }
    t->out_off += (size_t)n;
  }
  if(t->out_off == t->out.size()) {
    t->out.clear();
    t->out_off = 0;
  }
  else if(t->out_off > 1048576 || t->out_off > t->out.size() / 2) {
    t->out.erase(0, t->out_off);
    t->out_off = 0;
  }
  if(t->congested) check_congestion(t);
  tunnel_events(t);
}

Tunnel *pick_tunnel(PortRt &p, uint16_t &channel)
{
  std::vector<std::pair<Tunnel *, uint16_t>> c;
  for(auto &kv : tunnels) {
    Tunnel *t = kv.second;
    if(t->dead || !t->hello_rx || t->goaway_sent) continue;
    if(!p.cfg->peer.empty() && t->peer_name != p.cfg->peer) continue;
    if(t->streams.size() >= (size_t)cfg.mux.max_streams) continue;
    auto it = t->remote_channels.find(p.cfg->channel);
    if(it == t->remote_channels.end() || it->second.udp != p.cfg->udp) continue;
    c.emplace_back(t, it->second.id);
  }
  if(c.empty()) return nullptr;
  // Same order every time (by tunnel id), then round robin
  std::sort(c.begin(), c.end(), [](auto &a, auto &b) { return a.first->id < b.first->id; });
  auto &pick = c[p.rr++ % c.size()];
  channel = pick.second;
  return pick.first;
}

Stream *new_stream(Tunnel *t, uint32_t id)
{
  Stream *s = new Stream;
  s->id = id;
  s->t = t;
  s->send_credit = t->peer_window;
  s->last_active = time(nullptr);
  t->streams[id] = s;
  t->streams_total++;
  return s;
}

bool next_id(Tunnel *t, uint32_t &id)
{
  if(t->next_stream > 0xFFFFFF00u) {
    close_tunnel(t, "stream ids used up, reconnecting");
    return false;
  }
  id = t->next_stream;
  t->next_stream += 2;
  return true;
}

// Refuse a peer after HELLO: tell it why, so its log says so too
void reject_tunnel(Tunnel *t, const std::string &reason)
{
  put_frame(t, F_GOAWAY, 0, std::string("refused, ") + reason);
  tunnel_flush(t);
  close_tunnel(t, reason);
}

int hello_rx(Tunnel *t, const char *data, size_t len)
{
  std::string text(data, len);
  std::istringstream in(text);
  std::string line;
  bool magic = false;
  while(std::getline(in, line)) {
    std::vector<std::string> v = split(line, ' ');
    if(v.empty() || v[0].empty()) continue;
    if(v[0] == "DRMX") {
      if(v.size() < 2 || v[1] != "1") {
        close_tunnel(t, "peer speaks an unsupported DRMX version");
        return 1;
      }
      magic = true;
    }
    else if(v[0] == "peer" && v.size() == 2) t->peer_name = v[1];
    else if(v[0] == "window" && v.size() == 2) {
      long w = to_long(v[1]);
      if(w < 65536 || w > 16777216) {
        close_tunnel(t, "bad window in HELLO");
        return 1;
      }
      t->peer_window = w;
    }
    else if(v[0] == "chan" && v.size() == 4) {
      long id = to_long(v[1]);
      if(id < 1 || id > 65535 || (v[2] != "tcp" && v[2] != "udp") || !valid_name(v[3])) {
        close_tunnel(t, "bad channel in HELLO: " + line);
        return 1;
      }
      t->remote_channels[v[3]] = RemoteChannel{(uint16_t)id, v[2] == "udp"};
    }
    // Other lines (version) are informational; unknown lines are skipped
  }
  if(!magic || !valid_name(t->peer_name)) {
    close_tunnel(t, "bad HELLO");
    return 1;
  }
  // The tunnel listener checks the peer name against mux_allowed_peers,
  // and that the name is in the peer's certificate
  if(!t->connector && !cfg.mux.allowed_peers.empty()) {
    bool listed = false;
    for(const std::string &p : cfg.mux.allowed_peers) if(p == t->peer_name) listed = true;
    if(!listed) {
      reject_tunnel(t, "peer " + t->peer_name + " is not in mux_allowed_peers");
      return 1;
    }
    if(t->ssl) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
      X509 *cert = SSL_get1_peer_certificate(t->ssl);
#else
      X509 *cert = SSL_get_peer_certificate(t->ssl);
#endif
      bool ok = cert && X509_check_host(cert, t->peer_name.c_str(), 0, 0, nullptr) == 1;
      if(cert) X509_free(cert);
      if(!ok) {
        reject_tunnel(t, "peer name " + t->peer_name + " is not in its certificate");
        return 1;
      }
    }
  }
  t->hello_rx = true;
  t->up_since = time(nullptr);
  if(t->slot >= 0) {
    slots[t->slot].state = 2;
    slots[t->slot].backoff = 0;
  }
  std::string chans;
  for(auto &kv : t->remote_channels) chans += (chans.empty() ? "" : ", ") + kv.first + (kv.second.udp ? "/udp" : "/tcp");
  log_message(tname(t) + " is up, peer delivers: " + (chans.empty() ? "no channels" : chans));
  for(PortRt &p : ports) if(!p.held.empty()) port_release_held(p, false);
  for(PortRt &p : ports) {
    if(!p.cfg->peer.empty() && p.cfg->peer != t->peer_name) continue;
    auto it = t->remote_channels.find(p.cfg->channel);
    if(it == t->remote_channels.end()) {
      if(!p.cfg->peer.empty() || cfg.log_level >= 1) {
        log_message("WARNING - " + tname(t) + ": peer has no [MUXDEST] for channel " + p.cfg->channel);
      }
    }
    else if(it->second.udp != p.cfg->udp) {
      log_message("WARNING - " + tname(t) + ": channel " + p.cfg->channel + " is " + (it->second.udp ? "UDP" : "TCP") +
                  " on the peer and " + (p.cfg->udp ? "UDP" : "TCP") + " here");
    }
  }
  return 0;
}

void peer_open(Tunnel *t, uint16_t channel, uint32_t sid, const char *data, size_t len)
{
  bool peer_parity_odd = !t->connector; // The connector opens odd ids
  if(sid == 0 || ((sid & 1) == 1) != peer_parity_odd || t->streams.count(sid)) {
    close_tunnel(t, "protocol error: bad stream id " + std::to_string(sid) + " in OPEN");
    return;
  }
  if(channel < 1 || channel > cfg.mux.dests.size()) {
    put_frame(t, F_OPEN_FAIL, sid, "unknown channel");
    return;
  }
  if(t->streams.size() >= (size_t)cfg.mux.max_streams) {
    put_frame(t, F_OPEN_FAIL, sid, "too many streams");
    return;
  }
  MuxDest *d = cfg.mux.dests[channel - 1].get();
  Stream *s = new_stream(t, sid);
  s->dest = d;
  s->udp = d->udp;
  s->connecting = true;
  std::string client(data, std::min<size_t>(len, 64));
  for(char &c : client) if(!(isalnum((unsigned char)c) || c == '.' || c == ':' || c == ' ')) c = '_';
  s->client = client;
  d->streams_total++;
  d->streams_open++;
  if(cfg.log_level >= 2) log_message(sname(s) + "Stream open from " + t->peer_name + (client.empty() ? "" : ", client " + client));
  if(!spawn(dest_connect_worker, t->id, sid, d, client)) {
    s->connecting = false;
    d->open_fail++;
    put_frame(t, F_OPEN_FAIL, sid, "cannot start a connect thread");
    close_stream(s, false, "cannot start a connect thread");
  }
}

void handle_frame(Tunnel *t, uint8_t type, uint16_t channel, uint32_t sid, const char *data, size_t len)
{
  t->last_rx = time(nullptr);
  if(!t->hello_rx && type != F_HELLO) {
    close_tunnel(t, "protocol error: frame before HELLO");
    return;
  }
  Stream *s = nullptr;
  if(sid != 0) {
    auto it = t->streams.find(sid);
    if(it != t->streams.end()) s = it->second;
  }
  switch(type) {
    case F_HELLO:
      if(t->hello_rx) { close_tunnel(t, "protocol error: second HELLO"); return; }
      hello_rx(t, data, len);
      return;
    case F_OPEN:
      peer_open(t, channel, sid, data, len);
      return;
    case F_OPEN_OK:
      return; // The initiator already sends within the initial window
    case F_OPEN_FAIL:
      if(s && s->initiator) {
        s->port->cfg->refused++;
        if(cfg.log_level >= 1) log_message(sname(s) + "Peer could not open the stream: " + std::string(data, len));
        close_stream(s, false, "");
      }
      return;
    case F_DATA:
      if(!s) return; // Closed on this side, the RST is on its way
      if(s->udp || s->remote_eof) { close_tunnel(t, "protocol error: DATA on stream " + std::to_string(sid)); return; }
      s->unreturned += (long long)len;
      if(s->unreturned > cfg.mux.stream_window) { close_tunnel(t, "protocol error: peer sent past the stream window"); return; }
      s->rbuf.append(data, len);
      s->last_active = t->last_rx;
      stream_write(s);
      return;
    case F_WINDOW:
      if(len != 4) { close_tunnel(t, "protocol error: bad WINDOW"); return; }
      if(!s) return;
      s->send_credit += get32(data);
      if(s->send_credit > (1LL << 31)) { close_tunnel(t, "protocol error: window overflow"); return; }
      update_stream_events(s);
      return;
    case F_FIN:
      if(!s || s->udp) return;
      s->remote_eof = true;
      stream_write(s);
      return;
    case F_RST:
      if(s) close_stream(s, false, "reset by peer" + (len ? ", " + std::string(data, std::min<size_t>(len, 200)) : std::string()));
      return;
    case F_DGRAM:
      if(!s) return;
      if(!s->udp) { close_tunnel(t, "protocol error: DGRAM on a TCP stream"); return; }
      udp_deliver(s, data, len);
      return;
    case F_PING:
      put_frame(t, F_PONG, 0, 0, data, len);
      return;
    case F_PONG:
      if(len == 8) {
        uint64_t sent = ((uint64_t)get32(data) << 32) | get32(data + 4);
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t now = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        if(now >= sent) t->rtt_ms = (long)(now - sent);
      }
      return;
    case F_GOAWAY:
      close_tunnel(t, "peer closed the tunnel" + (len ? ": " + std::string(data, std::min<size_t>(len, 200)) : std::string()));
      return;
    default:
      close_tunnel(t, "protocol error: unknown frame type " + std::to_string(type));
  }
}

void parse_frames(Tunnel *t)
{
  while(!t->dead && t->in.size() - t->in_off >= HDR) {
    const char *h = t->in.data() + t->in_off;
    uint8_t ver = (uint8_t)h[0], type = (uint8_t)h[1];
    uint16_t channel = get16(h + 2);
    uint32_t sid = get32(h + 4);
    size_t len = get16(h + 8);
    if(ver != DRMX_VERSION || get16(h + 10) != 0) {
      close_tunnel(t, ver != DRMX_VERSION ? "not a DRLB tunnel peer or wrong protocol version" : "protocol error: bad flags");
      return;
    }
    if(t->in.size() - t->in_off < HDR + len) break;
    t->in_off += HDR + len;
    handle_frame(t, type, channel, sid, h + HDR, len);
  }
  if(t->dead) return;
  if(t->in_off == t->in.size()) {
    t->in.clear();
    t->in_off = 0;
  }
  else if(t->in_off > 65536) {
    t->in.erase(0, t->in_off);
    t->in_off = 0;
  }
}

void tunnel_read(Tunnel *t)
{
  if(t->dead) return;
  t->read_wants_write = false;
  t->more = false;
  char buf[65536];
  size_t total = 0;
  while(!t->dead) {
    int n;
    if(t->ssl) {
      ERR_clear_error();
      n = SSL_read(t->ssl, buf, sizeof(buf));
      if(n <= 0) {
        int e = SSL_get_error(t->ssl, n);
        if(e == SSL_ERROR_WANT_READ) break;
        if(e == SSL_ERROR_WANT_WRITE) { t->read_wants_write = true; break; }
        if(e == SSL_ERROR_ZERO_RETURN) close_tunnel(t, "closed by peer");
        else {
          std::string err = ssl_errors();
          close_tunnel(t, err.empty() ? "connection lost" : "TLS read failed, " + err);
        }
        return;
      }
    }
    else {
      n = (int)recv(t->fd, buf, sizeof(buf), 0);
      if(n < 0) {
        if(errno == EINTR) continue;
        if(errno == EAGAIN || errno == EWOULDBLOCK) break;
        close_tunnel(t, "read failed, " + errno_string(errno));
        return;
      }
      if(n == 0) {
        close_tunnel(t, "closed by peer");
        return;
      }
    }
    t->in.append(buf, (size_t)n);
    t->bytes_rx += (unsigned long long)n;
    total += (size_t)n;
    parse_frames(t);
    if(total >= 1048576) { // Let the other sockets have a turn
      t->more = true;
      break;
    }
  }
  if(!t->dead) tunnel_events(t);
}

void tunnel_up(Completion &c)
{
  Slot *sl = c.slot >= 0 ? &slots[c.slot] : nullptr;
  if(c.fd < 0) {
    if(sl) {
      sl->state = 0;
      sl->backoff = sl->backoff <= 0 ? cfg.mux.retry_secs : std::min(sl->backoff * 2, 60);
      sl->next_try = time(nullptr) + sl->backoff;
      if(sl->last_error != c.error || cfg.log_level >= 1) {
        log_message("ERROR - Tunnel " + c.label + " connect failed: " + c.error + ", retry in " + std::to_string(sl->backoff) + " secs");
      }
      sl->last_error = c.error;
    }
    else {
      log_message("ERROR - Tunnel from " + c.label + " refused: " + c.error);
    }
    return;
  }
  if(loop_stop) {
    if(c.ssl) SSL_free(c.ssl);
    close(c.fd);
    return;
  }
  Tunnel *t = new Tunnel;
  t->id = next_tunnel_id++;
  t->fd = c.fd;
  t->ssl = c.ssl;
  t->connector = sl != nullptr;
  t->slot = c.slot;
  t->label = c.label;
  t->next_stream = t->connector ? 1 : 2;
  t->created = t->last_rx = t->last_ping = time(nullptr);
  set_nonblock(t->fd);
  int one = 1;
  setsockopt(t->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  setsockopt(t->fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
  if(t->ssl) SSL_set_mode(t->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  t->key = add_handle(H_TUNNEL, t);
  tunnels[t->id] = t;
  if(sl) {
    sl->tunnel_id = t->id;
    sl->last_error.clear();
  }
  std::string info = "plain TCP, not encrypted";
  if(t->ssl) handshake_info(t->ssl, info);
  log_message(tname(t) + (t->connector ? " connected, " : " accepted, ") + info);
  put_frame(t, F_HELLO, 0, hello_payload());
  tunnel_flush(t);
}

void dest_connected(Completion &c)
{
  Stream *s = nullptr;
  auto it = tunnels.find(c.tunnel_id);
  if(it != tunnels.end()) {
    auto st = it->second->streams.find(c.stream_id);
    if(st != it->second->streams.end()) s = st->second;
  }
  if(!s || s->dead || !s->connecting) { // Reset or tunnel gone while connecting
    if(c.fd >= 0) close(c.fd);
    if(c.node) c.node->remove_connection();
    return;
  }
  s->connecting = false;
  if(c.fd < 0) {
    s->dest->open_fail++;
    put_frame(s->t, F_OPEN_FAIL, s->id, c.error);
    close_stream(s, false, "cannot connect, " + c.error);
    return;
  }
  s->fd = c.fd;
  s->node = c.node;
  set_nonblock(s->fd);
  if(!s->udp) {
    int one = 1;
    setsockopt(s->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  }
  s->key = add_handle(H_STREAM, s);
  put_frame(s->t, F_OPEN_OK, s->id, std::string());
  if(s->udp) {
    while(!s->dq.empty()) {
      std::string d = std::move(s->dq.front());
      s->dq.pop_front();
      udp_deliver(s, d.data(), d.size());
    }
    s->dq_bytes = 0;
    update_stream_events(s);
  }
  else {
    stream_write(s); // Data that came with the OPEN, and a FIN if one did
    if(!s->dead) update_stream_events(s);
  }
}

// ---------------------------------------------------------------------
// Local ports

int open_port_socket(const MuxPort *p, std::string &error_message)
{
  int fd = socket(AF_INET, (p->udp ? SOCK_DGRAM : SOCK_STREAM) | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if(fd < 0) {
    error_message = "socket() failed, " + errno_string(errno);
    return -1;
  }
  int reuse = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons((uint16_t)p->port);
  sin.sin_addr.s_addr = htonl(INADDR_ANY);
  if(!p->listen_ip_addr.empty() && p->listen_ip_addr != "0.0.0.0" && inet_aton(p->listen_ip_addr.c_str(), &sin.sin_addr) == 0) {
    error_message = "Bad listen_ip_addr " + p->listen_ip_addr;
    close(fd);
    return -1;
  }
  if(bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    error_message = "bind() failed, " + errno_string(errno);
    close(fd);
    return -1;
  }
  if(!p->udp && listen(fd, cfg.somaxconn) < 0) {
    error_message = "listen() failed, " + errno_string(errno);
    close(fd);
    return -1;
  }
  return fd;
}

// Open a stream for an accepted TCP client. Returns false when no tunnel
// delivers the channel; the caller keeps or closes the socket.
bool port_open_stream(PortRt &p, int fd, const std::string &client)
{
  uint16_t channel = 0;
  Tunnel *t = pick_tunnel(p, channel);
  if(!t) return false;
  uint32_t id;
  if(!next_id(t, id)) {
    close(fd);
    return true;
  }
  int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  Stream *s = new_stream(t, id);
  s->initiator = true;
  s->port = &p;
  s->fd = fd;
  s->client = client;
  s->key = add_handle(H_STREAM, s);
  p.cfg->streams_total++;
  p.cfg->streams_open++;
  put_frame(t, F_OPEN, channel, id, client.data(), client.size());
  if(cfg.log_level >= 2) log_message(sname(s) + "Stream open to " + t->peer_name + ", client " + client);
  update_stream_events(s);
  return true;
}

void port_refuse(PortRt &p, int fd, const std::string &client, const char *why)
{
  p.cfg->refused++;
  if(cfg.log_level >= 1) log_message("[" + p.cfg->channel + "]: No tunnel up for this channel" + why + ", client " + client + " closed");
  close(fd);
}

// Held clients: open their streams once a tunnel is up, close them after
// mux_hold_secs. The kernel buffers what a held client sends.
void port_release_held(PortRt &p, bool expire)
{
  time_t now = time(nullptr);
  while(!p.held.empty()) {
    PortRt::Held h = p.held.front();
    if(port_open_stream(p, h.fd, h.client)) {
      p.held.pop_front();
      continue;
    }
    if(!expire) return;
    if(now - h.since < cfg.mux.hold_secs && !loop_stop) return;
    p.held.pop_front();
    port_refuse(p, h.fd, h.client, " within mux_hold_secs");
  }
}

void port_accept(PortRt &p)
{
  for(int i = 0; i < 64; i++) {
    struct sockaddr_in remote;
    socklen_t len = sizeof(remote);
    int fd = accept4(p.fd, (struct sockaddr *)&remote, &len, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if(fd < 0) return;
    cfg.connection_total++;
    std::string client = addr_string(remote);
    if(p.held.empty() && port_open_stream(p, fd, client)) continue;
    if(cfg.mux.hold_secs > 0 && p.held.size() < (size_t)cfg.mux.max_streams) {
      if(cfg.log_level >= 2) log_message("[" + p.cfg->channel + "]: No tunnel up yet, client " + client + " held");
      p.held.push_back(PortRt::Held{fd, client, time(nullptr)});
      continue;
    }
    port_refuse(p, fd, client, "");
  }
}

void port_udp_read(PortRt &p)
{
  char buf[65536];
  for(int i = 0; i < 64; i++) {
    struct sockaddr_in remote;
    socklen_t alen = sizeof(remote);
    ssize_t n = recvfrom(p.fd, buf, sizeof(buf), 0, (struct sockaddr *)&remote, &alen);
    if(n < 0) {
      if(errno == EINTR) continue;
      return;
    }
    uint64_t fkey = ((uint64_t)remote.sin_addr.s_addr << 16) | remote.sin_port;
    Stream *s = nullptr;
    auto it = p.flows.find(fkey);
    if(it != p.flows.end()) s = it->second;
    if(!s) {
      if(p.flows.size() >= (size_t)cfg.mux.udp_max_flows) {
        p.cfg->udp_dropped++;
        continue;
      }
      uint16_t channel = 0;
      Tunnel *t = pick_tunnel(p, channel);
      uint32_t id;
      if(!t || !next_id(t, id)) {
        p.cfg->refused++;
        p.cfg->udp_dropped++;
        continue;
      }
      s = new_stream(t, id);
      s->initiator = true;
      s->udp = true;
      s->port = &p;
      s->fd = p.fd;
      s->addr = remote;
      s->flow_key = fkey;
      s->client = addr_string(remote);
      p.flows[fkey] = s;
      p.cfg->streams_total++;
      p.cfg->streams_open++;
      put_frame(t, F_OPEN, channel, id, s->client.data(), s->client.size());
      if(cfg.log_level >= 2) log_message(sname(s) + "UDP flow open to " + t->peer_name + ", client " + s->client);
    }
    s->last_active = time(nullptr);
    if(s->t->out_size() > (size_t)cfg.mux.tunnel_buffer + (size_t)cfg.mux.udp_queue_bytes) {
      p.cfg->udp_dropped++;
      continue;
    }
    put_frame(s->t, F_DGRAM, 0, s->id, buf, (size_t)n);
    p.cfg->bytes_out += (unsigned long long)n;
  }
}

void tunnel_listen_accept()
{
  for(int i = 0; i < 16; i++) {
    struct sockaddr_in remote;
    socklen_t len = sizeof(remote);
    int fd = accept4(tunnel_listen_fd, (struct sockaddr *)&remote, &len, SOCK_CLOEXEC);
    if(fd < 0) return;
    std::string label = addr_string(remote);
    for(char &c : label) if(c == ' ') c = ':';
    if(tunnels.size() >= 256 || handshakes >= 64) {
      log_message("ERROR - Tunnel from " + label + " refused: " +
                  (handshakes >= 64 ? "64 handshakes already running" : "256 tunnels already open"));
      close(fd);
      continue;
    }
    handshakes++;
    if(!spawn(tunnel_accept_worker, fd, label)) {
      handshakes--;
      close(fd);
    }
  }
}

// ---------------------------------------------------------------------
// Timers, once a second

void make_report()
{
  std::ostringstream m;
  time_t now = time(nullptr);
  for(size_t i = 0; i < slots.size(); i++) {
    const Slot &sl = slots[i];
    if(sl.state == 2) continue; // Listed with the open tunnels
    m << "Tunnel " << (sl.tc->name.empty() ? sl.tc->remote_host : sl.tc->name) << " " << sl.tc->remote_host << ":"
      << sl.tc->remote_port << ": " << (sl.state == 1 ? "connecting" : "down")
      << (sl.last_error.empty() ? "" : ", " + sl.last_error) << "\n";
  }
  std::vector<Tunnel *> list;
  for(auto &kv : tunnels) list.push_back(kv.second);
  std::sort(list.begin(), list.end(), [](Tunnel *a, Tunnel *b) { return a->id < b->id; });
  for(Tunnel *t : list) {
    m << tname(t) << ": " << (t->hello_rx ? "up" : "starting");
    if(t->hello_rx) m << " " << (now - t->up_since) << " secs";
    m << ", streams " << t->streams.size() << " open " << t->streams_total << " total"
      << ", bytes sent " << t->bytes_tx << " received " << t->bytes_rx
      << ", queued " << t->out_size() << (t->congested ? " (congested)" : "");
    if(t->rtt_ms >= 0) m << ", round trip " << t->rtt_ms << " ms";
    m << "\n";
  }
  std::lock_guard<std::mutex> lock(report_lock);
  tunnel_report = m.str();
}

void timers()
{
  time_t now = time(nullptr);
  for(PortRt &p : ports) if(!p.held.empty()) port_release_held(p, true);
  // Reconnect the connector slots. While clients are held, a down tunnel
  // tries every mux_retry_secs instead of backing off.
  bool holding = false;
  for(PortRt &p : ports) if(!p.held.empty()) holding = true;
  for(size_t i = 0; i < slots.size(); i++) {
    Slot &sl = slots[i];
    if(holding && sl.state == 0) sl.next_try = std::min(sl.next_try, std::max(now, sl.last_try + cfg.mux.retry_secs));
    if(sl.state != 0 || now < sl.next_try || loop_stop) continue;
    sl.state = 1;
    sl.last_try = now;
    if(!spawn(tunnel_connect_worker, (int)i, *sl.tc)) {
      sl.state = 0;
      sl.next_try = now + cfg.mux.retry_secs;
    }
  }
  std::vector<Tunnel *> list;
  for(auto &kv : tunnels) list.push_back(kv.second);
  for(Tunnel *t : list) {
    if(t->dead) continue;
    if(!t->hello_rx) {
      if(now - t->created > cfg.ssl.ssl_handshake_timeout_secs) close_tunnel(t, "no HELLO from the peer");
      continue;
    }
    if(now - t->last_rx > 3 * cfg.mux.keepalive_secs) {
      close_tunnel(t, "no data from the peer for " + std::to_string(now - t->last_rx) + " secs");
      continue;
    }
    if(now - t->last_ping >= cfg.mux.keepalive_secs) {
      struct timespec ts;
      clock_gettime(CLOCK_MONOTONIC, &ts);
      uint64_t ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
      char b[8];
      put32(b, (uint32_t)(ms >> 32));
      put32(b + 4, (uint32_t)ms);
      put_frame(t, F_PING, 0, 0, b, 8);
      t->last_ping = now;
    }
    // Idle streams: UDP flows after mux_udp_idle_secs, TCP after timeout_secs
    std::vector<Stream *> idle;
    for(auto &kv : t->streams) {
      Stream *s = kv.second;
      if(s->connecting) continue;
      long limit = s->udp ? cfg.mux.udp_idle_secs : (cfg.use_timeout && cfg.timeout_secs > 0 ? cfg.timeout_secs : 0);
      if(limit > 0 && now - s->last_active > limit) idle.push_back(s);
    }
    for(Stream *s : idle) close_stream(s, true, s->udp ? "UDP flow idle" : "idle timeout");
  }
  make_report();
}

// ---------------------------------------------------------------------
// Event loop

void flush_dirty()
{
  std::vector<Tunnel *> list;
  list.swap(dirty);
  std::sort(list.begin(), list.end());
  list.erase(std::unique(list.begin(), list.end()), list.end());
  for(Tunnel *t : list) if(!t->dead) tunnel_flush(t);
}

void reap()
{
  for(Stream *s : dead_streams) delete s;
  dead_streams.clear();
  for(Tunnel *t : dead_tunnels) free_tunnel(t);
  dead_tunnels.clear();
}

void dispatch(uint64_t key, uint32_t ev)
{
  auto it = handles.find(key);
  if(it == handles.end()) return; // Closed earlier in this turn
  Handle h = it->second;
  switch(h.type) {
    case H_EVENT: {
      uint64_t v;
      if(read(event_fd, &v, sizeof(v)) < 0) { }
      std::vector<Completion> list;
      {
        std::lock_guard<std::mutex> lock(cq_lock);
        list.swap(cq);
      }
      for(Completion &c : list) {
        if(c.kind == 1) dest_connected(c);
        else tunnel_up(c);
      }
      break;
    }
    case H_TUNNEL_LISTEN:
      tunnel_listen_accept();
      break;
    case H_TUNNEL: {
      Tunnel *t = (Tunnel *)h.ptr;
      if(t->dead) break;
      if((ev & (EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP)) || t->read_wants_write) tunnel_read(t);
      if(!t->dead && ((ev & EPOLLOUT) || t->out_size() > 0)) tunnel_flush(t);
      break;
    }
    case H_PORT_TCP:
      port_accept(*(PortRt *)h.ptr);
      break;
    case H_PORT_UDP:
      port_udp_read(*(PortRt *)h.ptr);
      break;
    case H_STREAM: {
      Stream *s = (Stream *)h.ptr;
      if(s->dead) break;
      if(s->udp) {
        dest_udp_read(s);
        break;
      }
      if(ev & EPOLLERR) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &len);
        close_stream(s, true, "local socket error, " + errno_string(err ? err : ECONNRESET));
        break;
      }
      if(ev & EPOLLOUT) stream_write(s);
      if(!s->dead && (ev & (EPOLLIN | EPOLLHUP | EPOLLRDHUP))) stream_read(s);
      break;
    }
  }
}

void loop_main()
{
  time_t last_tick = 0;
  struct epoll_event events[256];
  while(!loop_stop) {
    int timeout = 1000;
    for(auto &kv : tunnels) if(kv.second->more) timeout = 0;
    int n = epoll_wait(epfd, events, 256, timeout);
    if(n < 0 && errno != EINTR) {
      log_message("ERROR - epoll_wait failed, " + errno_string(errno));
      break;
    }
    for(int i = 0; i < n; i++) dispatch(events[i].data.u64, events[i].events);
    std::vector<Tunnel *> more;
    for(auto &kv : tunnels) if(kv.second->more) more.push_back(kv.second);
    for(Tunnel *t : more) tunnel_read(t);
    flush_dirty();
    time_t now = time(nullptr);
    if(now != last_tick) {
      last_tick = now;
      timers();
      flush_dirty();
    }
    reap();
  }

  // Shutdown: close held clients, GOAWAY to every peer, a short wait for
  // the output, then close
  for(PortRt &p : ports) {
    for(auto &h : p.held) close(h.fd);
    p.held.clear();
  }
  std::vector<Tunnel *> list;
  for(auto &kv : tunnels) list.push_back(kv.second);
  for(Tunnel *t : list) {
    if(t->hello_rx || t->connector) put_frame(t, F_GOAWAY, 0, std::string("server stopping"));
    t->goaway_sent = true;
  }
  flush_dirty();
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while(std::chrono::steady_clock::now() < deadline) {
    bool pending = false;
    for(auto &kv : tunnels) if(kv.second->out_size() > 0) pending = true;
    if(!pending) break;
    int n = epoll_wait(epfd, events, 256, 100);
    for(int i = 0; i < n; i++) {
      auto it = handles.find(events[i].data.u64);
      if(it != handles.end() && it->second.type == H_TUNNEL) tunnel_flush((Tunnel *)it->second.ptr);
    }
    reap();
  }
  list.clear();
  for(auto &kv : tunnels) list.push_back(kv.second);
  for(Tunnel *t : list) {
    if(t->ssl) SSL_shutdown(t->ssl);
    close_tunnel(t, "server stopping");
  }
  reap();
}

} // namespace

// ---------------------------------------------------------------------

int mux_check_config()
{
  MuxConfig &mx = cfg.mux;
  int errors = 0;
  auto error = [&](const std::string &m) { nt_print(("ERROR - " + m).c_str()); errors++; };

  nt_print("Port multiplexer mode (mode = MUX)");
  if(mx.peer_name.empty()) {
    char host[256] = {0};
    if(gethostname(host, sizeof(host) - 1) == 0) mx.peer_name = host;
  }
  if(!valid_name(mx.peer_name)) error("Bad mux_peer_name " + mx.peer_name + " (letters, digits, - _ . up to 64)");
  nt_print("Peer name", mx.peer_name.c_str());

  if(!mx.listen && mx.tunnels.empty()) error("mode = MUX needs mux_listen = 1 or a [MUXTUNNEL] section");
  if(mx.ports.empty() && mx.dests.empty()) error("mode = MUX needs [MUXPORT] or [MUXDEST] sections");
  if(mx.listen) nt_print("Accepting tunnels on port", std::to_string(cfg.port).c_str());

  for(auto &t : mx.tunnels) {
    std::string n = t.name.empty() ? t.remote_host : t.name;
    if(t.remote_host.empty()) error("[MUXTUNNEL] " + n + " has no remote_host");
    if(t.remote_port <= 0) error("[MUXTUNNEL] " + n + " has no remote_port");
    nt_print("Tunnel to " + n + " " + t.remote_host + ":" + std::to_string(t.remote_port) + ", " +
             std::to_string(t.connections) + " connection(s)");
  }

  std::map<std::string, int> port_channels;
  std::map<std::string, std::string> bound;
  for(auto &p : mx.ports) {
    if(!valid_name(p->channel)) error("[MUXPORT] has a bad or missing channel name: " + p->channel);
    if(p->port <= 0) error("[MUXPORT] " + p->channel + " has no port");
    if(port_channels[p->channel]++ > 0) error("Channel " + p->channel + " is in more than one [MUXPORT]");
    std::string where = std::string(p->udp ? "udp " : "tcp ") + (p->listen_ip_addr.empty() ? "0.0.0.0" : p->listen_ip_addr) +
                        ":" + std::to_string(p->port);
    if(bound.count(where)) error("[MUXPORT] " + p->channel + " and " + bound[where] + " both use " + where);
    bound[where] = p->channel;
    if(mx.listen && !p->udp && p->port == cfg.port &&
       (p->listen_ip_addr.empty() || cfg.listen_ip_addr.empty() || p->listen_ip_addr == cfg.listen_ip_addr)) {
      error("[MUXPORT] " + p->channel + " uses the tunnel port " + std::to_string(cfg.port));
    }
    nt_print("Local port " + where + " channel " + p->channel + (p->peer.empty() ? "" : " to peer " + p->peer));
  }
  if(!mx.ports.empty() && mx.tunnels.empty() && !mx.listen) error("[MUXPORT] sections need a tunnel");

  if(mx.dests.size() > 512) error("At most 512 [MUXDEST] sections");
  bool need_rules = false;
  std::map<std::string, int> dest_channels;
  for(auto &d : mx.dests) {
    if(!valid_name(d->channel)) error("[MUXDEST] has a bad or missing channel name: " + d->channel);
    if(dest_channels[d->channel]++ > 0) error("Channel " + d->channel + " is in more than one [MUXDEST]");
    if(!d->hostname.empty() || d->port > 0) {
      if(!d->node_names.empty()) error("[MUXDEST] " + d->channel + " has both hostname/port and nodes");
      if(d->hostname.empty() || d->port <= 0) error("[MUXDEST] " + d->channel + " needs both hostname and port");
      d->own_node = std::make_unique<Node>();
      d->own_node->node_name = d->channel;
      d->own_node->hostname = d->hostname;
      d->own_node->port_number = d->port;
      d->nodes = {d->own_node.get()};
      nt_print("Channel " + d->channel + (d->udp ? " (UDP)" : " (TCP)") + " delivered to " + d->hostname + ":" + std::to_string(d->port));
      continue;
    }
    if(d->node_names.empty()) {
      error("[MUXDEST] " + d->channel + " needs hostname and port, or nodes");
      continue;
    }
    d->nodes.clear();
    for(const std::string &name : d->node_names) {
      Node *found = nullptr;
      for(auto &n : cfg.nodes) if(n->node_name == name) found = n.get();
      if(!found) error("[MUXDEST] " + d->channel + " node " + name + " has no [LBNODE] section");
      else {
        d->nodes.push_back(found);
        if((d->scheme == LB_WEIGHTED || d->scheme == LB_DISTRIB ||
            (d->scheme == LB_ASSIGNED && (d->assigned_default == LB_WEIGHTED || d->assigned_default == LB_DISTRIB))) &&
           found->weight < 1) {
          error("[MUXDEST] " + d->channel + " uses a weighted or distributed scheme and node " + name + " has no weight");
        }
      }
    }
    if(d->scheme == LB_ASSIGNED) need_rules = true;
    const char *scheme = d->scheme == LB_ASSIGNED ? "LB_ASSIGNED" : d->scheme == LB_DISTRIB ? "LB_DISTRIB" :
                         d->scheme == LB_WEIGHTED ? "LB_WEIGHTED" : "LB_RR";
    std::string list;
    for(const std::string &n : d->node_names) list += (list.empty() ? "" : ", ") + n;
    nt_print("Channel " + d->channel + (d->udp ? " (UDP)" : " (TCP)") + " load balanced " + scheme + " over " + list);
  }
  if(need_rules && cfg.scheme != LB_ASSIGNED) { // Not read yet by check_config()
    if(cfg.rules_config_file.empty()) error("LB_ASSIGNED in [MUXDEST] needs rules_config_file in [LBSERVER]");
    else if(read_rules_config() != 0) error("Cannot read the rules config file " + cfg.rules_config_file);
  }

  if(cfg.ssl.enabled) {
    mx.plain = false;
    nt_print("Tunnels use SSL/TLS");
    if(cfg.ssl.ssl_encrypt_backend) nt_print("WARNING - ssl_encrypt_backend is not used in MUX mode, destinations are plain TCP or UDP");
  }
  else if(mx.allow_plain) {
    mx.plain = true;
    nt_print("WARNING - No [SSLCONFIG] and mux_allow_plain = 1: tunnel traffic is NOT encrypted or authenticated");
  }
  else {
    error("mode = MUX needs an [SSLCONFIG] section for TLS tunnels (or mux_allow_plain = 1 for an unencrypted tunnel)");
  }
  if(!mx.allowed_peers.empty()) {
    std::string list;
    for(const std::string &p : mx.allowed_peers) list += (list.empty() ? "" : ", ") + p;
    nt_print("Allowed tunnel peers:", list.c_str());
  }
  return errors ? 1 : 0;
}

void mux_wake()
{
  loop_stop = true;
  int fd = event_fd;
  if(fd >= 0) {
    uint64_t one = 1;
    if(write(fd, &one, sizeof(one)) < 0) { }
  }
}

void mux_stats_report(std::ostream &m)
{
  {
    std::lock_guard<std::mutex> lock(report_lock);
    m << tunnel_report;
  }
  for(auto &p : cfg.mux.ports) {
    m << "Port " << p->channel << (p->udp ? " udp " : " tcp ") << p->port << ": streams " << p->streams_open
      << " open " << p->streams_total << " total, refused " << p->refused << ", bytes sent " << p->bytes_out
      << " received " << p->bytes_in;
    if(p->udp) m << ", datagrams dropped " << p->udp_dropped;
    m << "\n";
  }
  for(auto &d : cfg.mux.dests) {
    m << "Channel " << d->channel << (d->udp ? " udp" : " tcp") << ": streams " << d->streams_open << " open "
      << d->streams_total << " total, connect failures " << d->open_fail << ", bytes sent " << d->bytes_out
      << " received " << d->bytes_in;
    if(d->udp) m << ", datagrams dropped " << d->udp_dropped;
    m << "\n";
  }
}

int run_mux_server()
{
  if(start_log_thread() != 0) {
    nt_print("ERROR - Fatal error starting log thread");
    return 1;
  }
  if(cfg.mux.plain) log_message("WARNING - Tunnel traffic is NOT encrypted or authenticated (mux_allow_plain = 1, no [SSLCONFIG])");

  epfd = epoll_create1(EPOLL_CLOEXEC);
  int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if(epfd < 0 || efd < 0) {
    nt_print("ERROR - Cannot create the event loop");
    stop_log_thread();
    return 1;
  }
  event_fd = efd;
  {
    uint64_t k = add_handle(H_EVENT, nullptr);
    uint32_t cur = 0;
    bool in = false;
    set_events(efd, k, EPOLLIN, cur, in);
  }

  int errors = 0;
  if(cfg.mux.listen) {
    std::string err;
    tunnel_listen_fd = open_listen_socket(err);
    if(tunnel_listen_fd < 0) {
      nt_print("ERROR - Cannot open the tunnel port", err.c_str());
      errors++;
    }
    else {
      set_nonblock(tunnel_listen_fd);
      tunnel_listen_key = add_handle(H_TUNNEL_LISTEN, nullptr);
      uint32_t cur = 0;
      bool in = false;
      set_events(tunnel_listen_fd, tunnel_listen_key, EPOLLIN, cur, in);
    }
  }
  ports.resize(cfg.mux.ports.size());
  for(size_t i = 0; i < cfg.mux.ports.size() && !errors; i++) {
    PortRt &p = ports[i];
    p.cfg = cfg.mux.ports[i].get();
    std::string err;
    p.fd = open_port_socket(p.cfg, err);
    if(p.fd < 0) {
      nt_print(("ERROR - Cannot open port " + std::to_string(p.cfg->port) + " for channel " + p.cfg->channel).c_str(), err.c_str());
      errors++;
      break;
    }
    p.key = add_handle(p.cfg->udp ? H_PORT_UDP : H_PORT_TCP, &p);
    uint32_t cur = 0;
    bool in = false;
    set_events(p.fd, p.key, EPOLLIN, cur, in);
  }
  if(errors) {
    stop_log_thread();
    return 1;
  }
  for(auto &tc : cfg.mux.tunnels) {
    for(int c = 0; c < tc.connections; c++) {
      Slot sl;
      sl.tc = &tc;
      slots.push_back(sl);
    }
  }
  if(start_stats_thread() != 0) {
    nt_print("ERROR - Fatal error starting the stats thread");
    stop_log_thread();
    return 1;
  }
  try {
    loop_thread = std::thread(loop_main);
  }
  catch(const std::system_error &) {
    nt_print("ERROR - Fatal error starting the event loop thread");
    stop_stats_thread();
    stop_log_thread();
    return 1;
  }
  nt_print("DRLB port multiplexer started");

  {
    std::unique_lock<std::mutex> lock(cfg.stop_lock);
    cfg.stop_cond.wait(lock, [] { return cfg.kill_server.load(); });
  }
  log_proc_message("Stopping the port multiplexer");
  mux_wake();
  loop_thread.join();
  int error_level = 0;
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(cfg.connect_timeout_secs + 2);
  while(workers > 0 && std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  if(workers > 0) {
    log_proc_message(std::to_string((int)workers) + " connect threads are still running and will end with the process");
    error_level = 2;
  }
  else {
    log_proc_message("Port multiplexer stopped");
  }
  stop_stats_thread();
  stop_log_thread();
  return error_level;
}

} // namespace drlb
