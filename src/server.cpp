// DRLB TCP load balancer
// Copyright (c) 2016-2026 DataReel Software Development
// GNU General Public License version 3 or later, see the COPYING file.
//
// The accept thread, one client thread per connection, the signal
// thread and the server start and stop sequence.

#include "drlb.h"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <thread>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

namespace drlb {

namespace {

int listen_fd = -1;
int wake_pipe[2] = {-1, -1};  // Written by request_stop() to end the accept loop
std::atomic<int> wake_fd{-1}; // wake_pipe[1] once the pipe is ready
std::thread accept_thread;

std::string seq(const ClientSocket *s)
{
  return "[" + std::to_string(s->seq_num) + "]: ";
}

void throttle(ClientSocket *s)
{
  int count;
  {
    std::lock_guard<std::mutex> lock(cfg.throttle_lock);
    cfg.throttle_count++;
    if(cfg.throttle_count >= cfg.throttle_every_connections) cfg.throttle_count = 0;
    count = cfg.throttle_count;
  }
  if(count != 0) return;
  if(cfg.throttle_apply_by_load && cfg.connections_per_second < cfg.throttle_connections_per_sec) return;
  if(cfg.debug_at(5)) log_debug_message(seq(s) + "Throttling connection");
  if(cfg.throttle_wait_secs >= 1) sleep_secs(cfg.throttle_wait_secs);
  if(cfg.throttle_wait_usecs >= 1) sleep_usecs(cfg.throttle_wait_usecs);
}

void handle_client_request(ClientSocket *s)
{
  if(cfg.ssl.server_ctx && tls_accept(s) != 0) return;

  Node *n = select_node(s);
  if(!n) return; // No backend nodes ready

  s->node = n;
  n->add_connection();
  if(cfg.debug_at(5)) {
    log_debug_message(seq(s) + n->node_name + " has " + std::to_string((int)n->num_connections) + " client connections");
  }

  RelaySide frontend, backend;
  frontend.fd = s->client_socket; frontend.name = "Frontend"; frontend.is_frontend = 1;
  frontend.ssl = s->frontend_ssl;
  backend.fd = s->backend_socket; backend.name = "Backend";
  backend.ssl = s->backend_ssl;
  HttpForwardFilter http_filter;
  relay(s, frontend, backend, n->buffer_size, cfg.enable_http_forwarding ? &http_filter : nullptr);

  tls_shutdown(s);
  shutdown(s->client_socket, SHUT_RDWR);
  shutdown(s->backend_socket, SHUT_RDWR);
  if(cfg.debug_at(5)) log_debug_message(seq(s) + "Client has disconnected, exiting client request thread");
}

void client_thread_main(ClientSocket *s)
{
  if(cfg.enable_throttling) throttle(s);
  handle_client_request(s);
  if(cfg.debug_at(5)) log_debug_message(seq(s) + "Client request thread exit routine closing connections");
  if(s->node) s->node->remove_connection();
  delete s;
  cfg.num_client_threads--;
}

void accept_thread_main()
{
  unsigned long accept_errors = 0;
  int num_start_threads = 4; // main + accept + log + signal
  if(cfg.enable_stats) num_start_threads++;

  while(cfg.accept_clients) {
    if(cfg.debug_at(5)) log_debug_message("LB server thread accept() call");
    struct pollfd p[2];
    p[0].fd = listen_fd; p[0].events = POLLIN; p[0].revents = 0;
    p[1].fd = wake_pipe[0]; p[1].events = POLLIN; p[1].revents = 0;
    int rv = poll(p, 2, -1);
    if(rv < 0 && errno == EINTR) continue;
    if(p[1].revents || !cfg.accept_clients) break;
    if(rv <= 0) continue;

    struct sockaddr_in remote;
    socklen_t addr_size = sizeof(remote);
    memset(&remote, 0, sizeof(remote));
    int fd = accept4(listen_fd, (struct sockaddr *)&remote, &addr_size, SOCK_CLOEXEC);
    if(fd < 0) {
      // Only a broken listening socket ends the server. Running out of
      // file descriptors or memory, or a client resetting before accept()
      // returns, is transient.
      int error_number = errno;
      if(error_number == EBADF || error_number == EINVAL || error_number == ENOTSOCK ||
         error_number == EOPNOTSUPP || error_number == EFAULT) {
        log_message("ERROR - accept() call failed, ENUM: " + std::to_string(error_number) +
                    " Message: " + errno_string(error_number));
        break;
      }
      if(error_number == EINTR || error_number == ECONNABORTED || error_number == EAGAIN) continue;
      if(accept_errors++ == 0 || cfg.debug) {
        log_message("ERROR - accept() call failed, will keep retrying, ENUM: " + std::to_string(error_number) +
                    " Message: " + errno_string(error_number));
      }
      // Back off while resources are exhausted
      std::this_thread::sleep_for(std::chrono::milliseconds(accept_errors < 10 ? 10 * accept_errors : 100));
      continue;
    }
    if(accept_errors > 0) {
      log_message("INFO - accept() recovered after " + std::to_string(accept_errors) + " failed calls");
      accept_errors = 0;
    }

    cfg.connection_total++;
    char client_name[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &remote.sin_addr, client_name, sizeof(client_name));
    int seq_num = ntohs(remote.sin_port);
    if(cfg.debug || cfg.log_level >= 1) {
      log_message("[" + std::to_string(seq_num) + "]: Frontend client connect: " + client_name);
    }

    int thread_count = cfg.num_client_threads;
    int num_connections = thread_count + 1; // Count this connection
    int num_threads = num_start_threads + thread_count;
    if(cfg.debug_at(5)) {
      log_debug_message(std::to_string(num_threads) + " threads working");
      log_debug_message(std::to_string(num_connections) + " server connections");
    }
    if(cfg.max_threads > 1) {
      if(cfg.debug_at(5)) log_debug_message("Max thread limit is set to " + std::to_string(cfg.max_threads));
      if(num_threads >= cfg.max_threads) {
        log_message("[" + std::to_string(seq_num) + "]: Reached " + std::to_string(num_threads) +
                    " max thread limit. " + client_name + " connection denied");
        close(fd);
        continue;
      }
    }
    if(cfg.max_connections > 1) {
      if(cfg.debug_at(5)) log_debug_message("Max frontend connection limit is set to " + std::to_string(cfg.max_connections));
      if(num_connections >= cfg.max_connections) {
        log_message("[" + std::to_string(seq_num) + "]: Reached " + std::to_string(num_connections) +
                    " max frontend connection limit. " + client_name + " connection denied");
        close(fd);
        continue;
      }
    }

    ClientSocket *s = new ClientSocket;
    s->client_socket = fd;
    s->seq_num = seq_num;
    s->client_name = client_name;
    cfg.num_client_threads++;
    try {
      std::thread(client_thread_main, s).detach();
    }
    catch(const std::system_error &e) {
      // Out of threads or memory: drop this connection and keep serving
      cfg.num_client_threads--;
      log_message("[" + std::to_string(seq_num) + "]: ERROR - Cannot start client thread, connection closed: " + e.what());
      delete s;
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }

  cfg.accept_clients = false;
  log_proc_message("NOTICE - Main server thread has exited");
  if(listen_fd >= 0) {
    close(listen_fd);
    listen_fd = -1;
  }
  // Tell the main thread to stop the server
  {
    std::lock_guard<std::mutex> lock(cfg.stop_lock);
    cfg.kill_server = true;
  }
  cfg.stop_cond.notify_all();
}

sigset_t drlb_signal_set()
{
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGQUIT);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGHUP);
  sigaddset(&set, SIGTSTP);
  sigaddset(&set, SIGUSR1);
  sigaddset(&set, SIGUSR2);
  return set;
}

// Handles termination and debug level signals. Runs in the signal
// thread, not in a signal handler.
void termination_handler(int signum)
{
  switch(signum) {
    case SIGINT:
      log_proc_message("Process interrupted with Ctrl-C");
      request_stop();
      break;
    case SIGTERM:
      log_proc_message("Process terminated by kill command");
      request_stop();
      break;
    case SIGQUIT:
      log_proc_message("Process interrupted Ctrl-backslash");
      break;
    case SIGHUP:
      log_proc_message("Process received hangup");
      break;
    case SIGTSTP:
      log_proc_message("Process received suspend from Ctrl-Z");
      break;
    case SIGUSR1:
      log_proc_message("Process received SIGUSR1, lowering debug level");
      if(!cfg.debug) {
        log_proc_message("Debug mode is disabled");
      }
      else if(cfg.debug_level > 0) {
        if(--cfg.debug_level <= 0) {
          log_proc_message("Debug mode has been disabled");
          cfg.debug = 0;
          cfg.debug_level = 0;
        }
        else {
          log_proc_message("Debug level decreased to " + std::to_string(cfg.debug_level));
        }
      }
      break;
    case SIGUSR2:
      log_proc_message("Process received SIGUSR2, raising debug level");
      if(cfg.debug) {
        log_proc_message("Debug mode is enabled");
      }
      else {
        log_proc_message("Debug mode has been enabled");
        cfg.debug = 1;
        cfg.debug_level = 1;
      }
      if(++cfg.debug_level >= 5) {
        log_proc_message("Debug mode set to level 5");
        cfg.debug_level = 5;
      }
      else {
        log_proc_message("Debug level increased to " + std::to_string(cfg.debug_level));
      }
      break;
  }
}

} // namespace

// Call before any other thread is created so every thread inherits the
// blocked signal mask. Returns 0 if successful.
int start_signal_thread()
{
  sigset_t set = drlb_signal_set();
  if(pthread_sigmask(SIG_BLOCK, &set, nullptr) != 0) return 1;
  try {
    std::thread([] {
      sigset_t set = drlb_signal_set();
      while(true) {
        int signum = 0;
        if(sigwait(&set, &signum) == 0) termination_handler(signum);
      }
    }).detach();
  }
  catch(const std::system_error &) {
    return 1;
  }
  return 0;
}

void request_stop()
{
  {
    std::lock_guard<std::mutex> lock(cfg.stop_lock);
    cfg.accept_clients = false;
    cfg.kill_server = true;
  }
  cfg.stop_cond.notify_all();
  int fd = wake_fd;
  if(fd >= 0) {
    char c = 1;
    if(write(fd, &c, 1) < 0) { } // The pipe is non-blocking; one byte is enough
  }
}

// Start the threads and serve until a stop is requested. Returns 0 for
// a normal stop, 1 if the server could not start, 2 if client threads
// were still running when the process had to exit.
int run_server()
{
  if(start_log_thread() != 0) {
    nt_print("ERROR - Fatal error starting log thread");
    return 1;
  }
  nt_print("Starting LB log thread");

  std::string error_message;
  for(int tries = 1; tries <= 2; tries++) {
    nt_print("Initializing DRLB server...");
    listen_fd = open_listen_socket(error_message);
    if(listen_fd >= 0) break;
    nt_print("ERROR - Cannot initialize DRLB server", error_message.c_str());
    if(tries < 2) {
      nt_print("Retrying in 60 seconds");
      std::unique_lock<std::mutex> lock(cfg.stop_lock);
      cfg.stop_cond.wait_for(lock, std::chrono::seconds(60), [] { return cfg.kill_server.load(); });
      if(cfg.kill_server) break;
    }
  }
  if(listen_fd < 0) {
    stop_log_thread();
    return 1;
  }

  if(pipe2(wake_pipe, O_CLOEXEC | O_NONBLOCK) != 0 || start_stats_thread() != 0) {
    nt_print("ERROR - Fatal error starting server threads");
    stop_log_thread();
    return 1;
  }
  wake_fd = wake_pipe[1];
  try {
    accept_thread = std::thread(accept_thread_main);
  }
  catch(const std::system_error &) {
    nt_print("ERROR - Fatal error starting main server thread");
    stop_stats_thread();
    stop_log_thread();
    return 1;
  }
  nt_print("DRLB thread started, waiting for client connections...");

  {
    std::unique_lock<std::mutex> lock(cfg.stop_lock);
    cfg.stop_cond.wait(lock, [] { return cfg.kill_server.load(); });
  }

  // Stop accepting, then give open connections time to finish. With
  // accept_clients cleared every relay loop exits within about a second.
  log_proc_message("Stopping LB server thread");
  request_stop();
  accept_thread.join();
  log_proc_message("LB server thread was stopped");

  int error_level = 0;
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(cfg.write_timeout_secs + 5);
  while(cfg.num_client_threads > 0 && std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if(cfg.num_client_threads > 0) {
    log_proc_message(std::to_string((int)cfg.num_client_threads) + " client threads are still running and will end with the process");
    error_level = 2;
  }
  else {
    log_proc_message("All client threads have finished");
  }

  log_proc_message("Stopping stats thread");
  stop_stats_thread();
  log_proc_message("Log server thread has stopped");
  stop_log_thread();
  return error_level;
}

} // namespace drlb
