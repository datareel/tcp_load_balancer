// DRLB TCP load balancer
// Copyright (c) 2016-2026 DataReel Software Development
// GNU General Public License version 3 or later, see the COPYING file.
//
// Sockets: the listening socket, backend connections and the reverse
// DNS lookup used by assigned rules. IPv4, as in 1.60.

#include "drlb.h"

#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace drlb {

void set_socket_timeouts(int fd, int send_secs, int recv_secs)
{
  struct timeval tv;
  if(send_secs >= 0) {
    tv.tv_sec = send_secs; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  }
  if(recv_secs >= 0) {
    tv.tv_sec = recv_secs; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  }
}

int open_listen_socket(std::string &error_message)
{
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if(fd < 0) {
    error_message = "socket() failed, " + errno_string(errno);
    return -1;
  }
  int reuse = 1;
  if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0 && cfg.debug) {
    log_message("ERROR - Socket error setting SO_REUSEADDR option");
  }
  // SO_REUSEPORT is not set. It lets a second server bind the same port
  // and silently take a share of the connections.

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons((uint16_t)cfg.port);
  sin.sin_addr.s_addr = htonl(INADDR_ANY);
  const std::string &ip = cfg.listen_ip_addr;
  if(!ip.empty() && ip != "0.0.0.0" && ip != "::0") {
    if(inet_aton(ip.c_str(), &sin.sin_addr) == 0) {
      error_message = "Bad listen_ip_addr " + ip;
      close(fd);
      return -1;
    }
  }
  if(bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    error_message = "Fatal bind() error initializing server, " + errno_string(errno);
    close(fd);
    return -1;
  }
  if(listen(fd, cfg.somaxconn) < 0) {
    error_message = "Fatal listen() error initializing server, " + errno_string(errno);
    close(fd);
    return -1;
  }
  return fd;
}

// Connect to a node, waiting up to timeout_secs. Returns the connected
// blocking socket, or -1 with error_message set.
int connect_to_node(const Node *n, int timeout_secs, std::string &error_message)
{
  struct addrinfo hints, *res = nullptr;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
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

  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if(fd < 0) {
    error_message = "socket() failed, " + errno_string(errno);
    return -1;
  }
  rv = connect(fd, (struct sockaddr *)&sin, sizeof(sin));
  if(rv < 0 && errno == EINPROGRESS) {
    struct pollfd p;
    p.fd = fd; p.events = POLLOUT; p.revents = 0;
    do {
      rv = poll(&p, 1, timeout_secs > 0 ? timeout_secs * 1000 : -1);
    } while(rv < 0 && errno == EINTR);
    if(rv == 0) {
      error_message = "Connection timed out after " + std::to_string(timeout_secs) + " secs";
      close(fd);
      return -1;
    }
    int err = 0;
    socklen_t len = sizeof(err);
    if(rv < 0) err = errno;
    else if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) err = errno;
    if(err != 0) {
      error_message = errno_string(err);
      close(fd);
      return -1;
    }
  }
  else if(rv < 0) {
    error_message = errno_string(errno);
    close(fd);
    return -1;
  }
  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
  return fd;
}

// Returns 0 for pass, with hostname set in hostname_str.
// Returns a non-zero value for fail, with error_message set.
int ip_to_hostname(const std::string &ip_str, std::string &hostname_str, std::string &error_message)
{
  hostname_str.clear();
  error_message.clear();

  struct addrinfo *result;
  int gai_result = getaddrinfo(ip_str.c_str(), nullptr, nullptr, &result);
  if(gai_result != 0) {
    error_message = gai_strerror(gai_result);
    return gai_result;
  }
  char hostname[NI_MAXHOST];
  memset(hostname, 0, sizeof(hostname));
  gai_result = getnameinfo(result->ai_addr, result->ai_addrlen, hostname, NI_MAXHOST, nullptr, 0, NI_NAMEREQD);
  freeaddrinfo(result);
  if(gai_result != 0) {
    error_message = gai_strerror(gai_result);
    return gai_result;
  }
  if(*hostname == '\0') return 0;

  // Forward-confirm the reverse DNS name. Anyone who controls the reverse
  // zone for their address can return any name, so a name is only used
  // when one of its addresses is the client address.
  struct addrinfo hints, *fwd;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  gai_result = getaddrinfo(hostname, nullptr, &hints, &fwd);
  if(gai_result != 0) {
    error_message = std::string("forward lookup of ") + hostname + " failed: " + gai_strerror(gai_result);
    return gai_result;
  }
  bool confirmed = false;
  for(struct addrinfo *rp = fwd; rp && !confirmed; rp = rp->ai_next) {
    char addr[NI_MAXHOST];
    if(getnameinfo(rp->ai_addr, rp->ai_addrlen, addr, sizeof(addr), nullptr, 0, NI_NUMERICHOST) == 0) {
      if(ip_str == addr) confirmed = true;
    }
  }
  freeaddrinfo(fwd);
  if(!confirmed) {
    error_message = std::string(hostname) + " does not resolve back to " + ip_str;
    return EAI_NONAME;
  }
  hostname_str = hostname;
  return 0;
}

} // namespace drlb
