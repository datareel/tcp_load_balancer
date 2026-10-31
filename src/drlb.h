// DRLB TCP load balancer
// Copyright (c) 2016-2026 DataReel Software Development
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at
// your option) any later version. See the COPYING file.
//
// Shared types, settings and function declarations.

#ifndef DRLB_H
#define DRLB_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

#include <regex.h>

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace drlb {

extern const char *VersionString;
extern const char *ProgramDescription;
extern const char *ProducedBy;

enum Scheme {
  LB_NONE = 0, // Only used for assigned_default
  LB_ASSIGNED,
  LB_DISTRIB,
  LB_RR,
  LB_WEIGHTED
};

// One backend node, from a [LBNODE] section
struct Node {
  std::string node_name = "LBnode";
  int port_number = 8080;
  std::string hostname = "localhost";
  int weight = -1;          // Not set
  int max_connections = -1; // Not set
  int buffer_size = 65536;

  std::atomic<int> num_connections{0};
  std::atomic<unsigned long> connection_total{0};
  std::atomic<time_t> down_until{0}; // Round robin skips the node until this time

  void add_connection() { num_connections++; connection_total++; }
  void remove_connection() { if(num_connections.fetch_sub(1) <= 0) num_connections = 0; }
};

// One "route IP node" line from the rules file, used by LB_ASSIGNED
struct Rule {
  Rule() = default;
  Rule(const Rule &) = delete;
  Rule &operator=(const Rule &) = delete;
  ~Rule() { if(compiled) { regfree(&regex); regfree(&regex_icase); } }

  std::string front_end_client_ip; // Extended regular expression
  std::string node_name;
  regex_t regex;
  regex_t regex_icase; // Used for host names
  bool compiled = false;
};

// Settings from [SSLCONFIG]
struct SSLConfig {
  bool enabled = false; // The config has an [SSLCONFIG] section
  std::string ssl_key_file = "/etc/drlb/ssl/private/ca.key";
  std::string ssl_cert_file = "/etc/drlb/ssl/certs/ca.crt";
  std::string ssl_dhparms_file = "/etc/drlb/ssl/certs/dhparams.pem";
  std::string ssh_ca_list_file; // Certificate chain (1.60 setting name kept)
  bool ssl_encrypt_backend = false;
  std::string ssl_backend_hostname;
  bool ssl_verify_backend_cert = true;
  std::string ssl_backend_ca_list_file = "/etc/pki/tls/certs/ca-bundle.crt";
  bool ssl_use_dhparms = false;
  int ssl_handshake_timeout_secs = 30;
  std::string ssl_protocol = "TLS";
  std::string ssl_cipher_list;  // TLS 1.2 ciphers, system crypto policy if empty
  std::string ssl_ciphersuites; // TLS 1.3 cipher suites, system crypto policy if empty

  SSL_CTX *server_ctx = nullptr; // Frontend
  SSL_CTX *client_ctx = nullptr; // Shared by all backend connections
};

// Settings from [LBSERVER] and the command line, plus the server state
struct Config {
  // [LBSERVER]
  Scheme scheme = LB_RR;
  int use_buffer_cache = 1;
  int buffer_size = 65536;
  int max_threads = -1;
  int max_connections = -1;
  std::string service_name = "drlb_server";
  int port = 8080;
  std::string listen_ip_addr;
  int resolve_assigned_hostnames = 1;
  Scheme assigned_default = LB_RR;
  std::string rules_config_file;
  int buffer_overflow_size = 6400000;
  int enable_buffer_overflow_detection = 0;
  unsigned retries = 3;
  unsigned retry_wait = 1;
  int dead_node_secs = 1;
  int timeout_secs = 300;
  int timeout_usecs = 0;
  int use_timeout = 1;
  int somaxconn = 128;
  int write_timeout_secs = 60;
  int connect_timeout_secs = 5;
  int max_cache_size = 1048576;

  // Logging
  int clear_log = 0;
  int enable_logging = 0;
  int num_logs_to_keep = 3;
  long max_log_size = 5000000;
  std::string logfile_name;
  int log_level = 0;
  int log_queue_size = 2048;
  int log_queue_debug_size = 4096;
  int log_queue_proc_size = 255;

  // Stats
  int enable_stats = 0;
  std::string stats_file_name = "drlb_stats.log";
  long max_stats_size = 5000000;
  int num_stats_to_keep = 3;
  int stats_min = 5;
  int stats_secs = 0;

  // Throttling
  int enable_throttling = 0;
  int throttle_apply_by_load = 0;
  int throttle_every_connections = 10;
  int throttle_connections_per_sec = 10;
  int throttle_wait_secs = 1;
  int throttle_wait_usecs = 0;

  // HTTP X-Forwarded-For
  int enable_http_forwarding = 0;
  std::string http_request_strings = "DELETE,GET,HEAD,PATCH,POST,PUT";
  std::vector<std::string> http_requests;
  std::string http_hdr_str = "HTTP/";
  std::string http_forward_for_str = "X-Forwarded-For";

  // Debug and console output, changed at run time by SIGUSR1 and SIGUSR2
  std::atomic<int> debug{0};
  std::atomic<int> debug_level{1};
  int verbose = 0;
  int verbose_level = 1;

  // Command line
  std::string program_name = "drlb_server";
  std::string config_file = "drlb_server.cfg";
  int user_config_file = 0;
  int check_config = 0;
  int ssl_name = 0; // Started as drlb_ssl_server

  int has_debug_override = 0;
  int has_debug_level_override = 0;
  int has_verbose_override = 0;
  int has_verbose_level_override = 0;
  int has_log_file_name_override = 0;
  int has_log_level_override = 0;
  int has_log_file_clear_override = 0;
  int has_enable_logging_override = 0;
  int has_disable_logging_override = 0;
  int has_stats_file_name_override = 0;
  int has_enable_stats_override = 0;
  int has_disable_stats_override = 0;

  // Nodes and rules
  std::vector<std::unique_ptr<Node>> nodes;
  std::vector<std::unique_ptr<Rule>> rules;
  std::vector<Node *> distributed_rr_node_list; // Highest load percent first
  std::vector<Node *> weighted_rr_node_list;    // Highest weight first
  int refactor_scale = 1;

  SSLConfig ssl;

  // Server state
  std::atomic<bool> accept_clients{true};
  std::atomic<bool> kill_server{false};
  std::mutex stop_lock;
  std::condition_variable stop_cond;
  time_t etime_server_start = time(nullptr);
  std::atomic<unsigned long> connection_total{0};
  std::atomic<int> connections_per_second{0};
  std::atomic<int> num_client_threads{0}; // Running client threads
  std::atomic<unsigned long> rr_counter[3] = {{0}, {0}, {0}}; // All, distributed, weighted

  // Shared by the distributed and weighted schemes
  std::mutex refactor_lock;
  int refactored_connections = 1;
  int prev_refactored_connections = 1;
  int weight_scale = 1;

  std::mutex throttle_lock;
  int throttle_count = 0;

  bool debug_at(int level) const { return debug && debug_level >= level; }
};

extern Config cfg;

// A limit for one node, used by the distributed and weighted schemes
struct LimitNode {
  unsigned limit = 1;
  Node *node = nullptr;
};

// One client connection
struct ClientSocket {
  ClientSocket() = default;
  ClientSocket(const ClientSocket &) = delete;
  ClientSocket &operator=(const ClientSocket &) = delete;
  ~ClientSocket();

  int client_socket = -1;  // Frontend
  int backend_socket = -1; // Backend
  SSL *frontend_ssl = nullptr;
  SSL *backend_ssl = nullptr;
  int seq_num = 0;         // Client port, used in log messages
  std::string client_name; // Client IP address
  Node *node = nullptr;
};

// util.cpp
std::string trim(const std::string &s);
std::string to_lower(std::string s);
std::string to_upper(std::string s);
bool icontains(const std::string &haystack, const std::string &needle);
std::vector<std::string> split(const std::string &s, char delim);
long to_long(const std::string &s); // atol() rules: leading number, 0 if none
std::string errno_string(int error_number);
std::string syslog_time();          // "Oct 31 14:30:00", local time
std::string gmt_date_time(time_t t); // "Sat, 31 Oct 2026 14:30:00 GMT"
void sleep_secs(unsigned long secs);
void sleep_usecs(unsigned long usecs);

// config.cpp
int process_args(int argc, char **argv);
int load_config_file();
int read_rules_config();
int check_config();
void help_message();
void version_message();
int build_distributed_rr_node_list();
int build_weighted_rr_node_list();
int refactor_distribution_limits(std::vector<LimitNode> &limits, int num_connections);
int refactor_weighted_limits(std::vector<LimitNode> &limits, int scale);
int get_num_node_connections();
int check_node_max_clients(Node *n, int seq_num);

// log.cpp
void log_message(const std::string &mesg); // Queued, thread safe
void log_debug_message(const std::string &mesg);
void log_proc_message(const std::string &mesg);
int nt_print(const char *mesg1, const char *mesg2 = nullptr, const char *mesg3 = nullptr);
inline int nt_print(const std::string &mesg) { return nt_print(mesg.c_str()); }
int nt_log_rotate();
int clear_log_file();
int start_log_thread();
void stop_log_thread();
void close_log_file();

// stats.cpp
int start_stats_thread();
void stop_stats_thread();

// net.cpp
int open_listen_socket(std::string &error_message);
int connect_to_node(const Node *n, int timeout_secs, std::string &error_message);
int ip_to_hostname(const std::string &ip_str, std::string &hostname_str, std::string &error_message);
void set_socket_timeouts(int fd, int send_secs, int recv_secs);

// tls.cpp
int tls_init();
void tls_cleanup();
int tls_accept(ClientSocket *s);
int tls_connect(ClientSocket *s, const Node *n);
void tls_shutdown(ClientSocket *s);
void close_backend(ClientSocket *s); // Free the backend TLS session and close the socket

// relay.cpp
struct RelaySide {
  int fd = -1;
  const char *name = "";
  int is_frontend = 0;
  SSL *ssl = nullptr; // Null for plain TCP
};

// Filters see every block of data read from either side, in order, and
// append the bytes to forward to out. Returns 0 to continue or non-zero
// to close the connection.
class RelayFilter {
public:
  virtual ~RelayFilter() = default;
  virtual int filter(ClientSocket *s, int from_frontend, const char *buf, int bytes, std::string &out) = 0;
};

// Adds one X-Forwarded-For header with the client address to each HTTP
// request, after removing any sent by the client. Request bodies with a
// Content-Length or chunked encoding are followed, so every request on
// a keep alive connection is handled.
class HttpForwardFilter : public RelayFilter {
public:
  int filter(ClientSocket *s, int from_frontend, const char *buf, int bytes, std::string &out) override;

private:
  int process_header(ClientSocket *s, std::string &out);
  int process_body(const char *buf, int bytes, int &used, std::string &out);

  enum { HTTP_HEADER, HTTP_BODY_LENGTH, HTTP_CHUNK_SIZE, HTTP_CHUNK_DATA,
         HTTP_CHUNK_DATA_END, HTTP_TRAILER, HTTP_PASSTHRU };
  int state = HTTP_HEADER;
  std::string header;               // Request header being collected
  unsigned long long remaining = 0; // Body or chunk bytes left to pass
  std::string line;                 // Chunk size or trailer line being collected
};

int relay(ClientSocket *s, RelaySide &frontend, RelaySide &backend, int buffer_size, RelayFilter *filter);

// balance.cpp
Node *select_node(ClientSocket *s);

// server.cpp
int start_signal_thread();
int run_server();
void request_stop();

} // namespace drlb

#endif // DRLB_H
