// DRLB TCP load balancer
// Copyright (c) 2016-2026 DataReel Software Development
// GNU General Public License version 3 or later, see the COPYING file.
//
// Frontend to backend data relay, ported from the 1.60 m_relay.cpp.
//
// The relay waits on both sockets with poll(), so idle connections use
// no CPU. Data read from one side is passed through an optional filter
// and written in full to the other side. Writes and idle periods are
// bounded by timeouts, and the amount of data read in one burst is
// capped by max_cache_size.

#include "drlb.h"

#include <cerrno>
#include <cstring>
#include <memory>

#include <fcntl.h>
#include <poll.h>
#include <strings.h>
#include <sys/socket.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace drlb {

static int set_nonblocking(int fd)
{
  int flags = fcntl(fd, F_GETFL, 0);
  if(flags < 0) return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Returns > 0 if ready, 0 on timeout, < 0 on error
static int wait_for(int fd, short events, int timeout_ms)
{
  struct pollfd p;
  p.fd = fd; p.events = events; p.revents = 0;
  int rv;
  do {
    rv = poll(&p, 1, timeout_ms);
  } while(rv < 0 && errno == EINTR);
  return rv;
}

// Read up to bytes from one side.
// Returns > 0 bytes read, 0 if the peer closed, -1 on error, -2 if no data is ready.
static int side_read(RelaySide &side, char *buf, int bytes)
{
  if(side.ssl) {
    ERR_clear_error();
    errno = 0;
    int rv = SSL_read(side.ssl, buf, bytes);
    if(rv > 0) return rv;
    switch(SSL_get_error(side.ssl, rv)) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE: // TLS 1.3 tickets and key updates
        return -2;
      case SSL_ERROR_ZERO_RETURN:
        return 0;
      case SSL_ERROR_SYSCALL:
        if(ERR_peek_error() == 0 && errno == 0) return 0; // EOF without close_notify
        return -1;
      default:
        return -1;
    }
  }
  int rv;
  do {
    rv = recv(side.fd, buf, bytes, MSG_DONTWAIT);
  } while(rv < 0 && errno == EINTR);
  if(rv >= 0) return rv;
  if(errno == EAGAIN || errno == EWOULDBLOCK) return -2;
  return -1;
}

// True if a read on this side will return data without waiting
static bool side_has_data(RelaySide &side)
{
  if(side.ssl && SSL_pending(side.ssl) > 0) return true;
  return wait_for(side.fd, POLLIN, 0) > 0;
}

// Write all bytes to one side, waiting up to timeout_secs for the peer.
// Returns 0 if all bytes were written.
static int write_all(RelaySide &side, const char *buf, size_t bytes, int timeout_secs)
{
  int timeout_ms = timeout_secs > 0 ? timeout_secs * 1000 : -1;
  size_t done = 0;
  while(done < bytes) {
    if(side.ssl) {
      ERR_clear_error();
      int rv = SSL_write(side.ssl, buf + done, (int)(bytes - done));
      if(rv > 0) { done += rv; continue; }
      int err = SSL_get_error(side.ssl, rv);
      short ev;
      if(err == SSL_ERROR_WANT_WRITE) ev = POLLOUT;
      else if(err == SSL_ERROR_WANT_READ) ev = POLLIN;
      else return -1;
      if(wait_for(side.fd, ev, timeout_ms) <= 0) return -1; // Timeout or error
      continue;
    }
    ssize_t rv = send(side.fd, buf + done, bytes - done, MSG_DONTWAIT | MSG_NOSIGNAL);
    if(rv > 0) { done += rv; continue; }
    if(rv < 0 && errno == EINTR) continue;
    if(rv < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      if(wait_for(side.fd, POLLOUT, timeout_ms) <= 0) return -1; // Timeout or error
      continue;
    }
    return -1;
  }
  return 0;
}

static std::string seq(ClientSocket *s)
{
  return "[" + std::to_string(s->seq_num) + "]: ";
}

// Move one burst of data from src to dst.
// Returns 0 to keep relaying, 1 if src closed, -1 on errors.
static int relay_burst(ClientSocket *s, RelaySide &src, RelaySide &dst, char *buffer,
                       int buffer_size, RelayFilter *filter, std::string &out)
{
  unsigned long burst = 0;
  unsigned long max_burst = (unsigned long)cfg.max_cache_size;
  bool closed = false;
  int rv = 0;

  out.clear();
  while(true) {
    int br = side_read(src, buffer, buffer_size);
    if(br == -2) break; // Nothing more ready
    if(br == 0) { closed = true; break; }
    if(br < 0) {
      if(cfg.log_level >= 3) log_message(seq(s) + "Error reading from " + src.name + " socket");
      rv = -1;
      break;
    }
    burst += br;
    if(filter) {
      if(filter->filter(s, src.is_frontend, buffer, br, out) != 0) {
        rv = -1;
        break;
      }
    }
    else {
      out.append(buffer, br);
    }
    if(src.is_frontend && cfg.enable_buffer_overflow_detection &&
       burst >= (unsigned long)cfg.buffer_overflow_size) {
      if(cfg.log_level >= 3) {
        log_message(seq(s) + "Frontend read " + std::to_string(burst) + " bytes from client");
        log_message(seq(s) + "Closing Frontend connection due to buffer overflow");
      }
      return -1;
    }
    // Without the buffer cache each read is written before the next one
    if(!cfg.use_buffer_cache) break;
    if(burst >= max_burst) break;
    if(!side_has_data(src)) break;
  }

  if(!out.empty() && rv == 0) {
    if(write_all(dst, out.data(), out.size(), cfg.write_timeout_secs) != 0) {
      if(cfg.log_level >= 3) {
        log_message(seq(s) + "Error writing " + std::to_string(out.size()) + " bytes to " + dst.name + " socket");
      }
      return -1;
    }
    if(cfg.debug_at(5)) {
      log_debug_message(seq(s) + "Moved " + std::to_string(out.size()) + " bytes from " + src.name + " to " + dst.name);
    }
  }
  out.clear();

  if(rv != 0) return rv;
  if(closed) {
    if(cfg.debug_at(5)) log_debug_message(seq(s) + src.name + " socket disconnected");
    return 1;
  }
  return 0;
}

int relay(ClientSocket *s, RelaySide &frontend, RelaySide &backend, int buffer_size, RelayFilter *filter)
{
  if(buffer_size <= 0) buffer_size = 1500;
  std::unique_ptr<char[]> buffer(new char[buffer_size]);
  std::string out;
  int error_level = 0;

  set_nonblocking(frontend.fd);
  set_nonblocking(backend.fd);

  // Idle timeout in milliseconds, 0 for no timeout
  long idle_limit_ms = 0;
  if(cfg.use_timeout) idle_limit_ms = (long)cfg.timeout_secs * 1000 + cfg.timeout_usecs / 1000;
  const int slice_ms = 1000; // Wake up to check for server shutdown
  long idle_ms = 0;

  while(cfg.accept_clients) {
    bool f_ready = side_has_data(frontend);
    bool b_ready = side_has_data(backend);
    if(!f_ready && !b_ready) {
      struct pollfd p[2];
      p[0].fd = frontend.fd; p[0].events = POLLIN; p[0].revents = 0;
      p[1].fd = backend.fd; p[1].events = POLLIN; p[1].revents = 0;
      int wait_ms = slice_ms;
      if(idle_limit_ms > 0 && (idle_limit_ms - idle_ms) < wait_ms) wait_ms = (int)(idle_limit_ms - idle_ms);
      if(wait_ms < 0) wait_ms = 0;
      int rv = poll(p, 2, wait_ms);
      if(rv < 0) {
        if(errno == EINTR) continue;
        error_level = 1;
        break;
      }
      if(rv == 0) {
        idle_ms += wait_ms;
        if(idle_limit_ms > 0 && idle_ms >= idle_limit_ms) {
          if(cfg.debug || cfg.log_level >= 4) {
            log_message(seq(s) + "Connection idle timeout after " + std::to_string(cfg.timeout_secs) +
                        " secs " + std::to_string(cfg.timeout_usecs) + " usecs");
          }
          error_level = 1;
          break;
        }
        continue;
      }
      f_ready = (p[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0;
      b_ready = (p[1].revents & (POLLIN | POLLHUP | POLLERR)) != 0;
    }
    idle_ms = 0;

    int rv = 0;
    if(f_ready) rv = relay_burst(s, frontend, backend, buffer.get(), buffer_size, filter, out);
    if(rv == 0 && b_ready) rv = relay_burst(s, backend, frontend, buffer.get(), buffer_size, filter, out);
    if(rv != 0) {
      if(rv < 0) error_level = 1;
      break;
    }
  }
  return error_level;
}

int HttpForwardFilter::filter(ClientSocket *s, int from_frontend, const char *buf, int bytes, std::string &out)
{
  if(!from_frontend || state == HTTP_PASSTHRU) {
    out.append(buf, bytes);
    return 0;
  }

  int pos = 0;
  while(pos < bytes) {
    if(state == HTTP_PASSTHRU) {
      out.append(buf + pos, bytes - pos);
      return 0;
    }
    if(state == HTTP_HEADER) {
      // Collect the header up to and including the blank line
      const size_t max_header = 65536;
      bool complete = false;
      while(pos < bytes) {
        header += buf[pos++];
        size_t hl = header.size();
        if(hl >= 4 && header.compare(hl - 4, 4, "\r\n\r\n") == 0) { complete = true; break; }
        if(hl >= max_header) { // Not a request we can parse, stop inspecting
          out += header;
          header.clear();
          state = HTTP_PASSTHRU;
          break;
        }
      }
      if(complete && process_header(s, out) != 0) return 1;
      continue;
    }
    int used = 0;
    if(process_body(buf + pos, bytes - pos, used, out) != 0) return 1;
    pos += used;
  }
  return 0;
}

static bool header_name_is(const char *line, int len, const std::string &name)
{
  int nlen = (int)name.size();
  if(len <= nlen || line[nlen] != ':') return false;
  return strncasecmp(line, name.c_str(), nlen) == 0;
}

// Rewrite one complete request header and set up the body state
int HttpForwardFilter::process_header(ClientSocket *s, std::string &out)
{
  const char *h = header.data();
  int hl = (int)header.size();

  // Only requests that start with a configured method are rewritten
  bool is_request = false;
  for(const std::string &m : cfg.http_requests) {
    int ml = (int)m.size();
    if(ml > 0 && hl > ml && memcmp(h, m.data(), ml) == 0 && h[ml] == ' ') {
      is_request = true;
      break;
    }
  }
  if(!is_request) {
    // Not HTTP/1.x, or a method we do not handle. Pass the rest of the
    // connection through unchanged.
    out += header;
    header.clear();
    state = HTTP_PASSTHRU;
    return 0;
  }

  unsigned long long content_length = 0;
  bool chunked = false, upgrade = false, first = true;
  int line_start = 0;
  while(line_start < hl - 2) { // Stop at the blank line
    int e = line_start;
    while(e < hl - 1 && !(h[e] == '\r' && h[e + 1] == '\n')) e++;
    int len = e - line_start;
    const char *l = h + line_start;
    bool keep = true;
    if(!first) {
      if(header_name_is(l, len, cfg.http_forward_for_str)) {
        keep = false; // Remove forwarding headers sent by the client
      }
      else if(header_name_is(l, len, "Content-Length")) {
        content_length = strtoull(trim(std::string(l + 15, len - 15)).c_str(), nullptr, 10);
      }
      else if(header_name_is(l, len, "Transfer-Encoding")) {
        if(icontains(std::string(l + 18, len - 18), "chunked")) chunked = true;
      }
      else if(header_name_is(l, len, "Upgrade")) {
        upgrade = true;
      }
    }
    if(keep) out.append(l, len + 2);
    first = false;
    line_start = e + 2;
  }
  out += cfg.http_forward_for_str + ": " + s->client_name + "\r\n\r\n";
  bool is_connect = header.compare(0, 8, "CONNECT ") == 0;
  header.clear();

  if(upgrade || is_connect) {
    state = HTTP_PASSTHRU; // WebSocket or tunnel, no more HTTP requests follow
  }
  else if(chunked) {
    state = HTTP_CHUNK_SIZE;
    line.clear();
  }
  else if(content_length > 0) {
    state = HTTP_BODY_LENGTH;
    remaining = content_length;
  }
  else {
    state = HTTP_HEADER;
  }
  return 0;
}

// Pass request body bytes and find where the next request starts
int HttpForwardFilter::process_body(const char *buf, int bytes, int &used, std::string &out)
{
  used = 0;
  switch(state) {
    case HTTP_BODY_LENGTH:
    case HTTP_CHUNK_DATA: {
      unsigned long long n = remaining;
      if(n > (unsigned long long)bytes) n = bytes;
      out.append(buf, (size_t)n);
      used = (int)n;
      remaining -= n;
      if(remaining == 0) state = (state == HTTP_BODY_LENGTH) ? HTTP_HEADER : HTTP_CHUNK_DATA_END;
      return 0;
    }
    case HTTP_CHUNK_SIZE:
    case HTTP_CHUNK_DATA_END:
    case HTTP_TRAILER:
      while(used < bytes) {
        char c = buf[used++];
        out += c;
        if(c != '\n') {
          if(line.size() > 4096) { state = HTTP_PASSTHRU; return 0; }
          if(c != '\r') line += c;
          continue;
        }
        // One line complete
        if(state == HTTP_CHUNK_DATA_END) { // CRLF after chunk data
          line.clear();
          state = HTTP_CHUNK_SIZE;
          return 0;
        }
        if(state == HTTP_CHUNK_SIZE) {
          remaining = strtoull(line.c_str(), nullptr, 16);
          line.clear();
          state = (remaining == 0) ? HTTP_TRAILER : HTTP_CHUNK_DATA;
          return 0;
        }
        // The trailer section ends with an empty line
        bool empty = line.empty();
        line.clear();
        if(empty) state = HTTP_HEADER;
        return 0;
      }
      return 0;
    default:
      out.append(buf, bytes);
      used = bytes;
      return 0;
  }
}

} // namespace drlb
