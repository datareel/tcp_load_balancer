// DRLB TCP load balancer
// Copyright (c) 2016-2026 DataReel Software Development
// GNU General Public License version 3 or later, see the COPYING file.
//
// Command line, config file, rules file and startup checks. The config
// file format is the same as the 1.60 drlb_server and drlb_ssl_server
// configs.

#include "drlb.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>

namespace drlb {

const char *VersionString = "2.0-beta";
const char *ProgramDescription = "DRLB TCP Load Balancer";
const char *ProducedBy = "http://datareel.com";

Config cfg;

void version_message()
{
  std::cout << "\n" << ProgramDescription << " version " << VersionString << "\n"
            << "Produced by: " << ProducedBy << "\n\n" << std::flush;
}

void help_message()
{
  version_message();
  std::cout << "Usage: " << cfg.program_name << " [args]\n"
            << "args: \n"
            << "     --help                      Print help message and exit\n"
            << "     --version                   Print version number and exit\n"
            << "     --check-config              Check the LB config file and exit\n"
            << "     --debug                     Enable debug mode default level --debug=1\n"
            << "     --debug-level=1             Set debugging level, 1-5\n"
            << "     --verbose                   Turn on verbose messaging to console\n"
            << "     --verbose-level=1           Set verbose level, 0-5\n"
            << "     --config-file=\"config.cfg\"  Specify configuration CFG file location\n"
            << "     --log-file=\"logfile.log\"    Use log file to log program output\n"
            << "     --log-level=1               Set logging level, 0-5\n"
            << "     --log-file-clear            Clear the log file when program starts\n"
            << "     --log-disable               Disable logging, override cfg setting\n"
            << "     --stats-file=\"stats.log\"    Write server stats to specified file \n"
            << "     --stats-disable             Disable server stats, override cfg setting\n"
            << "\n"
            << "A config file with an [SSLCONFIG] section runs as an SSL/TLS load balancer.\n"
            << "\n" << std::flush;
}

static int process_dash_dash_arg(std::string arg)
{
  std::string equal_arg;
  int has_arg_errors = 0;
  int has_arg = 0;

  size_t eq = arg.find('=');
  if(eq != std::string::npos) {
    // --config-file="/etc/program.cfg"
    equal_arg = trim(arg.substr(eq + 1));
    arg.erase(eq);
    auto strip = [&](char c) {
      while(!equal_arg.empty() && equal_arg.front() == c) equal_arg.erase(0, 1);
      while(!equal_arg.empty() && equal_arg.back() == c) equal_arg.pop_back();
    };
    strip('"');
    strip('\'');
  }
  arg = to_lower(arg);

  if(arg == "help" || arg == "?") {
    help_message();
    exit(1);
  }
  if(arg == "version" || arg == "ver") {
    version_message();
    exit(1);
  }
  if(arg == "verbose") {
    cfg.has_verbose_override = 1;
    cfg.verbose = 1;
    has_arg = 1;
  }
  if(arg == "verbose-level") {
    if(equal_arg.empty()) {
      cfg.verbose = 1;
      nt_print("Error no verbose level supplied with the --verbose-level switch");
      has_arg_errors++;
    }
    else {
      cfg.has_verbose_level_override = 1;
      cfg.verbose_level = (int)to_long(equal_arg);
      if(cfg.verbose_level <= 0) cfg.verbose_level = 1;
      has_arg = 1;
    }
  }
  if(arg == "debug") {
    cfg.has_debug_override = 1;
    cfg.debug = 1;
    has_arg = 1;
  }
  if(arg == "debug-level") {
    if(equal_arg.empty()) {
      cfg.verbose = 1;
      nt_print("Error no debug level supplied with the --debug-level switch");
      has_arg_errors++;
    }
    else {
      cfg.has_debug_level_override = 1;
      cfg.debug = 1;
      cfg.debug_level = (int)to_long(equal_arg);
      if(cfg.debug_level <= 0) cfg.debug_level = 1;
      has_arg = 1;
    }
  }
  if(arg == "check-config") {
    cfg.check_config = 1;
    has_arg = 1;
  }
  if(arg == "config-file") {
    if(equal_arg.empty()) {
      cfg.verbose = 1;
      nt_print("Error no config file name supplied with the --config-file switch");
      has_arg_errors++;
    }
    else {
      cfg.config_file = equal_arg;
      cfg.user_config_file = 1;
      has_arg = 1;
    }
  }
  if(arg == "log-file") {
    if(equal_arg.empty()) {
      cfg.verbose = 1;
      nt_print("Error no LOG file name supplied with the --log-file switch");
      has_arg_errors++;
    }
    else {
      cfg.has_log_file_name_override = 1;
      cfg.logfile_name = equal_arg;
      cfg.enable_logging = 1;
      has_arg = 1;
    }
  }
  if(arg == "log-file-clear") {
    cfg.has_log_file_clear_override = 1;
    cfg.clear_log = 1;
    has_arg = 1;
  }
  if(arg == "log-disable") {
    cfg.has_disable_logging_override = 1;
    cfg.enable_logging = 0;
    has_arg = 1;
  }
  if(arg == "log-level") {
    if(equal_arg.empty()) {
      cfg.verbose = 1;
      nt_print("Error no log level supplied with the --log-level switch");
      has_arg_errors++;
    }
    else {
      cfg.has_log_level_override = 1;
      cfg.log_level = (int)to_long(equal_arg);
      if(cfg.log_level < 0) cfg.log_level = 0;
      has_arg = 1;
    }
  }
  if(arg == "stats-file") {
    if(equal_arg.empty()) {
      cfg.verbose = 1;
      nt_print("Error no STATS file name supplied with the --stats-file switch");
      has_arg_errors++;
    }
    else {
      cfg.has_stats_file_name_override = 1;
      cfg.stats_file_name = equal_arg;
      cfg.enable_stats = 1;
      has_arg = 1;
    }
  }
  if(arg == "stats-disable") {
    cfg.has_disable_stats_override = 1;
    cfg.enable_stats = 0;
    has_arg = 1;
  }

  if(has_arg == 0) has_arg_errors++;
  return has_arg_errors;
}

int process_args(int argc, char **argv)
{
  int has_arg_errors = 0;
  for(int i = 1; i < argc; i++) {
    if(argv[i][0] != '-') continue;
    switch(argv[i][1]) {
      case '-': {
        std::string arg = &argv[i][2];
        while(!arg.empty() && arg[0] == '-') arg.erase(0, 1);
        if(process_dash_dash_arg(arg) != 0) has_arg_errors++;
        break;
      }
      case '?':
        help_message();
        exit(1);
      case 'v': case 'V':
        cfg.verbose = 1;
        cfg.has_verbose_override = 1;
        break;
      case 'd': case 'D':
        cfg.has_debug_override = 1;
        cfg.debug = 1;
        break;
      default:
        cfg.verbose = 1;
        nt_print((std::string("Unknown command line arg ") + argv[i]).c_str());
        nt_print("Exiting with errors");
        exit(1);
    }
  }
  return has_arg_errors;
}

static int true_false(const std::string &value)
{
  std::string v = to_upper(value);
  if(v == "TRUE" || v == "T" || v == "YES" || v == "Y") return 1;
  if(v == "FALSE" || v == "F" || v == "NO" || v == "N") return 0;
  return to_long(v) >= 1 ? 1 : 0;
}

static Scheme parse_scheme(const std::string &value, bool &ok)
{
  ok = true;
  if(icontains(value, "LB_ASSIGNED")) return LB_ASSIGNED;
  if(icontains(value, "LB_DISTRIB")) return LB_DISTRIB;
  if(icontains(value, "LB_RR")) return LB_RR;
  if(icontains(value, "LB_WEIGHTED")) return LB_WEIGHTED;
  if(icontains(value, "LB_NONE")) return LB_NONE;
  ok = false;
  return LB_NONE;
}

static const char *default_config =
  "# Default LB config file\n"
  "\n"
  "# Global config\n"
  "[LBSERVER]\n"
  "port = 8080 # All incoming traffic connections here\n"
  "#\n"
  "# Set to accept clients on single interface\n"
  "##listen_ip_addr = 0.0.0.0\n"
  "#\n"
  "# LB_ASSIGNED scheme requires a rules config file\n"
  "# A default rules config file will be build if specified file does not exist\n"
  "##scheme = LB_ASSIGNED\n"
  "##rules_config_file = drlb_server_rules.cfg\n"
  "##resolve_assigned_hostnames = 1\n"
  "##assigned_default = LB_RR # Use round robin for node fail over\n"
  "##assigned_default = LB_DISTRIB  # Use distib for node fail over\n"
  "##assigned_default = LB_WEIGHTED # Use weighted for node fail over\n"
  "# Set assigned_default to LB_NONE to disable node fail over, meaning:\n"
  "# If the assigned node is not available the client connection will fail\n"
  "##assigned_default = LB_NONE\n"
  "#\n"
  "##scheme = LB_DISTRIB\n"
  "##scheme = LB_WEIGHTED\n"
  "# Use Round Robin as default LB scheme\n"
  "scheme = LB_RR\n"
  "use_buffer_cache = 1\n"
  "buffer_size = 65536\n"
  "max_connections = -1 # Not set, if set will limit number of connections this server\n"
  "max_threads = -1 # Not set, if set will limit number of threads for this process\n"
  "#\n"
  "# Log settings\n"
  "# Keep log file plus last 3. Disk space will be: (max_log_size * (num_logs_to_keep +1))\n"
  "num_logs_to_keep = 3\n"
  "# Set max size per log file, max is 2000000000\n"
  "max_log_size = 5000000 # Default is 5M, max is 2G\n"
  "log_queue_size = 2048 # Max number of log or console messages to queue\n"
  "log_queue_debug_size = 4096 # Max number of debug messages to queue\n"
  "log_queue_proc_size = 255 # Max number of process messages to queue\n"
  "# Values below can be set here or args when program is launched\n"
  "##clear_log = 0\n"
  "##enable_logging = 0\n"
  "# Log levels 0-5, 0 lowest log level, 5 highest log level \n"
  "##log_level = 0\n"
  "##logfile_name = /var/log/drlb/drlb_server.log\n"
  "#\n"
  "# Stats settings\n"
  "# Keep stats file plus last 3. Disk space will be: (max_stats_size * (num_stats_to_keep +1))\n"
  "num_stats_to_keep = 3\n"
  "# Set max size per stats file, max is 2000000000\n"
  "max_stats_size = 5000000 # Default is 5M, max is 2G\n"
  "stats_min = 5 # Generate a stats report every 5 minutes\n"
  "stats_secs = 0 # If min=0 gen a stats report less than every min\n"
  "##enable_stats = 0\n"
  "##stats_file_name = /var/log/drlb/drlb_stats.log\n"
  "#\n"
  "# Set max number of back logged connections\n"
  "# Should match: cat /proc/sys/net/core/somaxconn\n"
  "somaxconn = 128\n"
  "#\n"
  "# Buffer overflow detection with using cached reads, disabled by default\n"
  "enable_buffer_overflow_detection = 0\n"
  "buffer_overflow_size = 6400000\n"
  "#\n"
  "# Retries for backend node connection errors\n"
  "retries = 3\n"
  "retry_wait = 1\n"
  "# Seconds a node that refused a connection is skipped\n"
  "dead_node_secs = 1\n"
  "#\n"
  "# Close connections with no data in either direction for timeout_secs\n"
  "use_timeout = 1\n"
  "timeout_secs = 300\n"
  "timeout_usecs = 0\n"
  "#\n"
  "# Seconds to wait for a slow peer to accept data, and to connect to a node\n"
  "write_timeout_secs = 60\n"
  "connect_timeout_secs = 5\n"
  "#\n"
  "# Max bytes read from one side before they are written to the other side\n"
  "max_cache_size = 1048576\n"
  "#\n"
  "# Service name that appears in log file\n"
  "##service_name = drlb_server\n"
  "#\n"
  "# \n"
  "# Settings for throttling connections\n"
  "# Throttling is used to prevent backend server saturation during peak load events\n"
  "#\n"
  "# Enable throttling\n"
  "##enable_throttling = 0\n"
  "# Apply throttle control only when load reached a certain number of connection per second\n"
  "# If apply by load is set to 0, we will throttle based on the connection count\n"
  "##throttle_apply_by_load = 0\n"
  "# Set the number of connection per second to start throttling connections\n"
  "##throttle_connections_per_sec = 10\n"
  "# Set the number of connections to start throttling\n"
  "# A setting of 1 will throttle every connection\n"
  "##throttle_every_connections = 10\n"
  "# Set the time in seconds or microseconds to hold a connection in the throttle queue\n"
  "##throttle_wait_secs = 1\n"
  "##throttle_wait_usecs = 0\n"
  "#\n"
  "# HTTP IP address forwarding\n"
  "##enable_http_forwarding = 0\n"
  "##http_request_strings = DELETE,GET,HEAD,PATCH,POST,PUT\n"
  "##http_hdr_str = HTTP/\n"
  "##http_forward_for_str = X-Forwarded-For\n"
  "#\n"
  "# Values below can be set here or args when program is launched\n"
  "# Debug and verbose modes used mainly for development and testing\n"
  "# NOTE: Debug level 5 will greatly increase log file size\n"
  "# NOTE: Verbose mode will echo messages to the console, used mainly to test config files\n"
  "##debug = 0\n"
  "##debug_level = 1\n"
  "##verbose = 0\n"
  "##verbose_level = 1\n"
  "\n"
  "# SSL/TLS settings. Remove the ## from the [SSLCONFIG] line below to\n"
  "# terminate TLS on the frontend. Without an [SSLCONFIG] section the\n"
  "# server is a plain TCP load balancer.\n"
  "##[SSLCONFIG]\n"
  "# TLS protocol versions\n"
  "# TLS - TLS 1.2 and TLS 1.3 (default)\n"
  "# TLSv1_2 - TLS 1.2 only\n"
  "# TLSv1_3 - TLS 1.3 only\n"
  "##ssl_protocol = TLS\n"
  "# Ciphers follow the system crypto policy (update-crypto-policies).\n"
  "# Set these only to restrict them further for this server.\n"
  "##ssl_cipher_list = ECDHE+AESGCM:ECDHE+CHACHA20\n"
  "##ssl_ciphersuites = TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256\n"
  "# Seconds allowed for a TLS handshake\n"
  "##ssl_handshake_timeout_secs = 30\n"
  "# Private key and certificate files\n"
  "##ssl_key_file = /etc/drlb/ssl/private/ca.key\n"
  "##ssl_cert_file = /etc/drlb/ssl/certs/ca.crt\n"
  "# Certificate chain\n"
  "##ssh_ca_list_file = /etc/drlb/ssl/certs/ca_list.crt\n"
  "# Optional Diffie-Hellman parameters\n"
  "##ssl_use_dhparms = 0\n"
  "##ssl_dhparms_file = /etc/drlb/ssl/certs/dhparams.pem\n"
  "# Use TLS to connect to the LB nodes. Backend certificates are verified\n"
  "# against the CA list and the node hostname, or ssl_backend_hostname if\n"
  "# set, using subjectAltName. Set ssl_verify_backend_cert = 0 only for\n"
  "# test backends.\n"
  "##ssl_encrypt_backend = 0\n"
  "##ssl_backend_hostname = www.example.com\n"
  "##ssl_verify_backend_cert = 1\n"
  "##ssl_backend_ca_list_file = /etc/pki/tls/certs/ca-bundle.crt\n"
  "\n"
  "# Node Configs, define a [LBNODE] section for each node\n"
  "# The default config uses 4 nodes as an example\n"
  "# Replace 192.168.122 address with the IP address or hostname of the backend node\n"
  "# running the service you want to load balance.\n";

static int build_default_config()
{
  std::ofstream f(cfg.config_file);
  if(!f) {
    nt_print("ERROR - Cannot write to config file", cfg.config_file.c_str());
    return 3;
  }
  f << "# " << ProgramDescription << " " << VersionString << " configuration file\n#\n\n";
  f << default_config;
  for(int i = 1; i <= 4; i++) {
    f << "[LBNODE]\n"
      << "node_name = lbnode" << i << "\n"
      << "port_number = 80   # Port backend host is listening on \n"
      << "hostname = 192.168.122.11" << i << " # Backend host\n"
      << "weight = -1 # Must be set if using LB_WEIGHTED or LB_DISTRIB scheme\n"
      << "max_connections = -1 # Not set, if set will limit number of connection to this node\n"
      << "buffer_size = -1 # Use global size\n\n";
  }
  f << "# End of configuration file\n\n";
  f.close();
  if(!f) {
    nt_print("ERROR - Cannot write to config file", cfg.config_file.c_str());
    return 3;
  }
  return 2;
}

// Clean one config line: comments removed, spaces trimmed. Returns an
// empty string for blank and comment lines.
static std::string clean_line(const std::string &raw)
{
  std::string line = trim(raw);
  if(line.empty() || line[0] == '#' || line[0] == ';') return "";
  size_t hash = line.find('#');
  if(hash != std::string::npos) line = trim(line.substr(0, hash));
  return line;
}

enum Section { SEC_NONE, SEC_LBSERVER, SEC_LBNODE, SEC_SSLCONFIG, SEC_OTHER };

static Section section_of(const std::string &line)
{
  std::string s;
  for(char c : line) if(c != ' ' && c != '\t') s += c;
  s = to_upper(s);
  if(s.find("[LBSERVER]") != std::string::npos) return SEC_LBSERVER;
  if(s.find("[LBNODE]") != std::string::npos) return SEC_LBNODE;
  if(s.find("[SSLCONFIG]") != std::string::npos) return SEC_SSLCONFIG;
  return SEC_OTHER;
}

static int bad_value(const char *name)
{
  nt_print("Config file has bad value for", name);
  return 1;
}

static int set_lbserver(const std::string &name, const std::string &value)
{
  int error_level = 0;
  int ival = (int)to_long(value);
  bool known = true;

  if(name == "verbose") { if(!cfg.has_verbose_override) cfg.verbose = true_false(value); }
  else if(name == "verbose_level") { if(!cfg.has_verbose_level_override) cfg.verbose_level = ival; }
  else if(name == "debug") { if(!cfg.has_debug_override) cfg.debug = true_false(value); }
  else if(name == "debug_level") { if(!cfg.has_debug_level_override) cfg.debug_level = ival; }
  else if(name == "log_level") { if(!cfg.has_log_level_override) cfg.log_level = ival; }
  else if(name == "clear_log") {
    if(!cfg.has_disable_logging_override && !cfg.has_log_file_clear_override) cfg.clear_log = true_false(value);
  }
  else if(name == "logfile_name") {
    if(!cfg.has_disable_logging_override && !cfg.has_log_file_name_override) cfg.logfile_name = value;
  }
  else if(name == "enable_logging") {
    if(!cfg.has_disable_logging_override && !cfg.has_enable_logging_override) cfg.enable_logging = true_false(value);
  }
  else if(name == "scheme") {
    bool ok;
    Scheme s = parse_scheme(value, ok);
    if(!ok || s == LB_NONE) {
      nt_print("Config file has bad scheme value", value.c_str());
      error_level = 1;
    }
    else {
      cfg.scheme = s;
    }
  }
  else if(name == "use_buffer_cache") cfg.use_buffer_cache = true_false(value);
  else if(name == "buffer_size") {
    cfg.buffer_size = ival;
    if(cfg.buffer_size <= 0) error_level = bad_value("buffer_size");
  }
  else if(name == "max_threads") cfg.max_threads = ival;
  else if(name == "max_connections") cfg.max_connections = ival;
  else if(name == "stats_file_name") {
    if(!cfg.has_disable_stats_override && !cfg.has_stats_file_name_override) cfg.stats_file_name = value;
  }
  else if(name == "enable_stats") {
    if(!cfg.has_disable_stats_override && !cfg.has_enable_stats_override) cfg.enable_stats = true_false(value);
  }
  else if(name == "num_stats_to_keep") {
    cfg.num_stats_to_keep = ival;
    if(cfg.num_stats_to_keep <= 0) error_level = bad_value("num_stats_to_keep");
  }
  else if(name == "max_stats_size") {
    cfg.max_stats_size = to_long(value);
    if(cfg.max_stats_size > 2000000000) { nt_print("Config max_stats_size is over 2GB"); error_level = 1; }
    if(cfg.max_stats_size <= 0) error_level = bad_value("max_stats_size");
  }
  else if(name == "stats_min") {
    cfg.stats_min = ival;
    if(cfg.stats_min < 0) error_level = bad_value("stats_min");
  }
  else if(name == "stats_secs") {
    cfg.stats_secs = ival;
    if(cfg.stats_secs < 0) error_level = bad_value("stats_secs");
  }
  else if(name == "service_name") cfg.service_name = value;
  else if(name == "num_logs_to_keep") {
    cfg.num_logs_to_keep = ival;
    if(cfg.num_logs_to_keep <= 0) error_level = bad_value("num_logs_to_keep");
  }
  else if(name == "max_log_size") {
    cfg.max_log_size = to_long(value);
    if(cfg.max_log_size > 2000000000) { nt_print("Config max_log_size is over 2GB"); error_level = 1; }
    if(cfg.max_log_size <= 0) error_level = bad_value("max_log_size");
  }
  else if(name == "enable_buffer_overflow_detection") cfg.enable_buffer_overflow_detection = true_false(value);
  else if(name == "buffer_overflow_size") {
    cfg.buffer_overflow_size = ival;
    if(cfg.buffer_overflow_size <= 0) error_level = bad_value("buffer_overflow_size");
  }
  else if(name == "log_queue_size") {
    cfg.log_queue_size = ival;
    if(cfg.log_queue_size <= 0) error_level = bad_value("log_queue_size");
  }
  else if(name == "log_queue_debug_size") {
    cfg.log_queue_debug_size = ival;
    if(cfg.log_queue_debug_size <= 0) error_level = bad_value("log_queue_debug_size");
  }
  else if(name == "log_queue_proc_size") {
    cfg.log_queue_proc_size = ival;
    if(cfg.log_queue_proc_size <= 0) error_level = bad_value("log_queue_proc_size");
  }
  else if(name == "retries") {
    if(ival < 0) error_level = bad_value("retries");
    else cfg.retries = (unsigned)ival;
  }
  else if(name == "retry_wait") {
    if(ival < 0) error_level = bad_value("retry_wait");
    else cfg.retry_wait = (unsigned)ival;
  }
  else if(name == "dead_node_secs") {
    cfg.dead_node_secs = ival;
    if(cfg.dead_node_secs < 0) error_level = bad_value("dead_node_secs");
  }
  else if(name == "timeout_secs") {
    cfg.timeout_secs = ival;
    if(cfg.timeout_secs < 0) error_level = bad_value("timeout_secs");
  }
  else if(name == "timeout_usecs") {
    cfg.timeout_usecs = ival;
    if(cfg.timeout_usecs < 0) error_level = bad_value("timeout_usecs");
  }
  else if(name == "write_timeout_secs") {
    cfg.write_timeout_secs = ival;
    if(cfg.write_timeout_secs <= 0) error_level = bad_value("write_timeout_secs");
  }
  else if(name == "connect_timeout_secs") {
    cfg.connect_timeout_secs = ival;
    if(cfg.connect_timeout_secs <= 0) error_level = bad_value("connect_timeout_secs");
  }
  else if(name == "max_cache_size") {
    cfg.max_cache_size = ival;
    if(cfg.max_cache_size <= 0) error_level = bad_value("max_cache_size");
  }
  else if(name == "use_timeout") cfg.use_timeout = true_false(value);
  else if(name == "port") {
    cfg.port = ival;
    if(cfg.port <= 0 || cfg.port > 65535) { nt_print("Config file has bad server port value"); error_level = 1; }
  }
  else if(name == "listen_ip_addr") cfg.listen_ip_addr = value;
  else if(name == "somaxconn") {
    cfg.somaxconn = ival;
    if(cfg.somaxconn <= 0) error_level = bad_value("somaxconn");
  }
  else if(name == "resolve_assigned_hostnames") cfg.resolve_assigned_hostnames = true_false(value);
  else if(name == "assigned_default") {
    bool ok;
    Scheme s = parse_scheme(value, ok);
    if(ok && s == LB_ASSIGNED) {
      nt_print("Config file error, assigned_default cannot equal LB_ASSIGNED", value.c_str());
      error_level = 1;
    }
    else if(!ok) {
      nt_print("Config file has bad assigned_default scheme default value", value.c_str());
      error_level = 1;
    }
    else {
      cfg.assigned_default = s;
    }
  }
  else if(name == "rules_config_file") cfg.rules_config_file = value;
  else if(name == "enable_throttling") cfg.enable_throttling = true_false(value);
  else if(name == "throttle_apply_by_load") cfg.throttle_apply_by_load = true_false(value);
  else if(name == "throttle_connections_per_sec") {
    cfg.throttle_connections_per_sec = ival;
    if(cfg.throttle_connections_per_sec <= 0) error_level = bad_value("throttle_connections_per_sec");
  }
  else if(name == "throttle_every_connections") {
    cfg.throttle_every_connections = ival;
    if(cfg.throttle_every_connections <= 0) error_level = bad_value("throttle_every_connections");
  }
  else if(name == "throttle_wait_secs") {
    cfg.throttle_wait_secs = ival;
    if(cfg.throttle_wait_secs < 0) error_level = bad_value("throttle_wait_secs");
  }
  else if(name == "throttle_wait_usecs") {
    cfg.throttle_wait_usecs = ival;
    if(cfg.throttle_wait_usecs < 0) error_level = bad_value("throttle_wait_usecs");
  }
  else if(name == "enable_http_forwarding") cfg.enable_http_forwarding = true_false(value);
  else if(name == "http_request_strings") cfg.http_request_strings = value;
  else if(name == "http_hdr_str") cfg.http_hdr_str = value;
  else if(name == "http_forward_for_str") cfg.http_forward_for_str = value;
  else known = false;

  if(!known) nt_print("WARNING - Unknown [LBSERVER] setting ignored:", name.c_str());
  return error_level;
}

static int set_lbnode(Node *n, const std::string &name, const std::string &value)
{
  int error_level = 0;
  int ival = (int)to_long(value);
  if(name == "node_name") n->node_name = value;
  else if(name == "port_number") {
    n->port_number = ival;
    if(n->port_number <= 0 || n->port_number > 65535) {
      nt_print("Config file has bad node port value", value.c_str());
      error_level = 1;
    }
  }
  else if(name == "hostname") n->hostname = value;
  else if(name == "weight") {
    std::string w;
    for(char c : value) if(c != '%') w += c;
    n->weight = (int)to_long(trim(w));
  }
  else if(name == "max_connections") n->max_connections = ival;
  else if(name == "buffer_size") {
    n->buffer_size = ival;
    if(n->buffer_size <= 0) n->buffer_size = cfg.buffer_size;
  }
  else nt_print("WARNING - Unknown [LBNODE] setting ignored:", name.c_str());
  return error_level;
}

static int set_sslconfig(const std::string &name, const std::string &value)
{
  SSLConfig &ssl = cfg.ssl;
  if(name == "ssl_key_file") ssl.ssl_key_file = value;
  else if(name == "ssl_cert_file") ssl.ssl_cert_file = value;
  else if(name == "ssh_ca_list_file") ssl.ssh_ca_list_file = value;
  else if(name == "ssl_encrypt_backend") ssl.ssl_encrypt_backend = true_false(value);
  else if(name == "ssl_verify_backend_cert") ssl.ssl_verify_backend_cert = true_false(value);
  else if(name == "ssl_backend_hostname") ssl.ssl_backend_hostname = value;
  else if(name == "ssl_backend_ca_list_file") ssl.ssl_backend_ca_list_file = value;
  else if(name == "ssl_use_dhparms") ssl.ssl_use_dhparms = true_false(value);
  else if(name == "ssl_dhparms_file") ssl.ssl_dhparms_file = value;
  else if(name == "ssl_handshake_timeout_secs") {
    ssl.ssl_handshake_timeout_secs = (int)to_long(value);
    if(ssl.ssl_handshake_timeout_secs <= 0) {
      nt_print("ERROR - Bad ssl_handshake_timeout_secs value in [SSLCONFIG]");
      return 1;
    }
  }
  else if(name == "ssl_cipher_list") ssl.ssl_cipher_list = value;
  else if(name == "ssl_ciphersuites") ssl.ssl_ciphersuites = value;
  else if(name == "ssl_protocol") ssl.ssl_protocol = value;
  else nt_print("WARNING - Unknown [SSLCONFIG] setting ignored:", name.c_str());
  return 0;
}

// Returns 0 if the config loaded, 1 for config errors, 2 if the file was
// missing and a default file was built, 3 if the default file could not
// be written.
int load_config_file()
{
  nt_print("Loading or building config file", cfg.config_file.c_str());

  if(!std::filesystem::exists(cfg.config_file)) {
    nt_print("DRLB configuration file not found. Building default file and exiting");
    return build_default_config();
  }

  std::ifstream f(cfg.config_file);
  if(!f) {
    nt_print("ERROR - Cannot open config file for reading", cfg.config_file.c_str());
    return 1;
  }

  int error_level = 0;
  int has_lbserver = 0, has_scheme = 0, num_ssl_sections = 0;
  Section section = SEC_NONE;
  Node *node = nullptr;
  std::string raw;
  int line_number = 0;

  while(std::getline(f, raw)) {
    line_number++;
    std::string line = clean_line(raw);
    if(line.empty()) continue;

    if(line[0] == '[') {
      section = section_of(line);
      node = nullptr;
      if(section == SEC_LBSERVER) has_lbserver = 1;
      if(section == SEC_SSLCONFIG) num_ssl_sections++;
      if(section == SEC_LBNODE) {
        cfg.nodes.push_back(std::make_unique<Node>());
        node = cfg.nodes.back().get();
        node->buffer_size = cfg.buffer_size; // Global size set in [LBSERVER]
      }
      continue;
    }
    if(section == SEC_NONE || section == SEC_OTHER) continue;

    size_t eq = line.find('=');
    if(eq == std::string::npos) {
      std::ostringstream m;
      m << "WARNING - Line " << line_number << " has no = sign, ignored: " << line;
      nt_print(m.str());
      continue;
    }
    std::string name = to_lower(trim(line.substr(0, eq)));
    std::string value = trim(line.substr(eq + 1));

    if(section == SEC_LBSERVER) {
      if(name == "scheme" && ++has_scheme > 1) {
        nt_print("Config file has more than one scheme defined");
        error_level = 1;
      }
      if(set_lbserver(name, value) != 0) error_level = 1;
    }
    else if(section == SEC_LBNODE) {
      if(set_lbnode(node, name, value) != 0) error_level = 1;
    }
    else if(section == SEC_SSLCONFIG) {
      if(set_sslconfig(name, value) != 0) error_level = 1;
    }
  }
  if(f.bad()) {
    nt_print("ERROR - A fatal I/O error reading", cfg.config_file.c_str());
    return 1;
  }

  if(!has_lbserver) {
    nt_print("Config file missing [LBSERVER] section");
    error_level = 1;
  }
  if(cfg.nodes.empty()) {
    nt_print("Config file missing [LBNODE] sections");
    error_level = 1;
  }
  if(num_ssl_sections > 1) {
    std::ostringstream m;
    m << "ERROR - DRLB server config has " << num_ssl_sections << " [SSLCONFIG] sections " << cfg.config_file;
    nt_print(m.str());
    error_level = 1;
  }
  cfg.ssl.enabled = num_ssl_sections > 0;
  return error_level;
}

// Read the rules config.
// Return 0 if no errors, 1 if fatal error, 2 if bad rule line, 3 if bad regex
int read_rules_config()
{
  if(cfg.rules_config_file.empty()) {
    nt_print("WARNING - No rules_config_file specified in LB server config");
    return 1;
  }

  if(!std::filesystem::exists(cfg.rules_config_file)) {
    nt_print(("No rules cfg " + cfg.rules_config_file).c_str());
    nt_print("Building default rules configuration file");
    std::ofstream f(cfg.rules_config_file);
    if(!f) {
      nt_print(("write error " + cfg.rules_config_file).c_str());
      return 1;
    }
    f << "#  " << ProgramDescription << " " << VersionString << " rule set configuration file\n"
      << "#\n\n"
      << "# Default LB rules config file\n\n"
      << "# ROUTE rule set for LB_ASSIGNED scheme\n"
      << "# Route rule for assigned LB format: route IP node\n"
      << "# IP = IP address or hostname, can be extended regular expression\n"
      << "# node = node name to route traffic too. node name must match server config\n"
      << "# Route rule examples:\n"
      << "##route 192.168.122.1 lbnode1\n"
      << "##route ^192.* lbnode1\n\n\n";
    return 0;
  }

  std::ifstream f(cfg.rules_config_file);
  if(!f) {
    nt_print(("Cannot open " + cfg.rules_config_file).c_str());
    return 1;
  }

  cfg.rules.clear();
  int error_level = 0;
  std::string raw;
  while(std::getline(f, raw)) {
    std::string line = clean_line(raw);
    if(line.empty()) continue;
    std::vector<std::string> vals;
    std::istringstream words(line);
    std::string w;
    while(words >> w) vals.push_back(w);
    if(!icontains(vals[0], "route")) continue;
    if(vals.size() != 3) {
      nt_print(("ERROR - Bad ROUTE rule " + line).c_str());
      error_level = 2;
      continue;
    }
    // Remove quotes around the expression, unless the last one is escaped
    std::string &re = vals[1];
    for(char q : {'"', '\''}) {
      while(!re.empty() && re.front() == q) re.erase(0, 1);
      if(re.size() >= 2 && re.back() == q && re[re.size() - 2] != '\\') {
        while(!re.empty() && re.back() == q) re.pop_back();
      }
    }
    auto rule = std::make_unique<Rule>();
    if(regcomp(&rule->regex, re.c_str(), REG_EXTENDED | REG_NOSUB) != 0) {
      nt_print(("ERROR - Bad regex " + re).c_str());
      error_level = 3;
      continue;
    }
    if(regcomp(&rule->regex_icase, re.c_str(), REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0) {
      regfree(&rule->regex);
      nt_print(("ERROR - Bad regex " + re).c_str());
      error_level = 3;
      continue;
    }
    rule->compiled = true;
    rule->front_end_client_ip = re;
    rule->node_name = vals[2];
    cfg.rules.push_back(std::move(rule));
  }
  return error_level;
}

// Order nodes by weight, highest first, the same way as 1.60: the first
// node with each weight in weight order, then the other nodes with a
// repeated weight in reverse config order.
static int build_weight_order(std::vector<Node *> &out)
{
  std::map<int, Node *> by_weight;
  std::vector<Node *> repeated;
  for(auto &n : cfg.nodes) {
    if(!by_weight.emplace(n->weight, n.get()).second) repeated.push_back(n.get());
  }
  out.clear();
  for(auto it = by_weight.rbegin(); it != by_weight.rend(); ++it) out.push_back(it->second);
  for(auto it = repeated.rbegin(); it != repeated.rend(); ++it) out.push_back(*it);
  return (int)out.size();
}

int build_distributed_rr_node_list() { return build_weight_order(cfg.distributed_rr_node_list); }
int build_weighted_rr_node_list() { return build_weight_order(cfg.weighted_rr_node_list); }

int refactor_distribution_limits(std::vector<LimitNode> &limits, int num_connections)
{
  limits.clear();
  if(num_connections == 0) num_connections = cfg.refactor_scale;
  int total = 0;
  for(Node *n : cfg.distributed_rr_node_list) {
    float limit = ((float)n->weight / 100.0f) * num_connections;
    LimitNode ln;
    ln.limit = (int)limit <= 0 ? 1 : (unsigned)(int)limit;
    ln.node = n;
    total += ln.limit;
    limits.push_back(ln);
  }
  return total;
}

int refactor_weighted_limits(std::vector<LimitNode> &limits, int scale)
{
  limits.clear();
  if(scale <= 0) scale = 1;
  int total = 0;
  for(Node *n : cfg.weighted_rr_node_list) {
    LimitNode ln;
    ln.limit = n->weight * scale;
    ln.node = n;
    total += ln.limit;
    limits.push_back(ln);
  }
  return total;
}

int get_num_node_connections()
{
  int total = 0;
  for(auto &n : cfg.nodes) total += n->num_connections;
  return total;
}

int check_node_max_clients(Node *n, int seq_num)
{
  if(!n || n->max_connections <= 1) return 0; // Max clients not set for this node
  int num_connections = n->num_connections;
  std::ostringstream m;
  if(cfg.debug_at(5)) {
    m << "[" << seq_num << "]: Max connection limit for " << n->node_name << " is set to " << n->max_connections;
    log_debug_message(m.str());
  }
  if(num_connections >= n->max_connections) {
    m.str("");
    m << "[" << seq_num << "]: " << n->node_name << " reached " << num_connections
      << " connections. " << n->hostname << " connection will be denied";
    log_message(m.str());
    return 1;
  }
  return 0;
}

static std::string num(long v) { return std::to_string(v); }

// 5000000 as 5,000,000, as 1.60 printed sizes
static std::string num_commas(long v)
{
  std::string s = std::to_string(v);
  for(int i = (int)s.size() - 3; i > (v < 0 ? 1 : 0); i -= 3) s.insert(i, ",");
  return s;
}

// Load and check the config and print the settings. Returns 0 if the
// server can start.
int check_config()
{
  if(cfg.check_config) nt_print("Running DRLB configuration check and exiting");

  int error_level = load_config_file();
  if(error_level == 2) {
    if(cfg.check_config) return error_level;
    cfg.verbose = 1;
    nt_print("ERROR - DRLB config file was not found. A default config file was built.");
    return error_level;
  }
  if(error_level == 3) {
    cfg.verbose = 1;
    nt_print("ERROR - Could not build a default DRLB configuration file template");
    return error_level;
  }
  if(error_level != 0) {
    if(!cfg.verbose) {
      cfg.verbose = 1;
      nt_print("ERROR - DRLB config file error. Run with --verbose to print error messages");
    }
    else {
      nt_print("ERROR - DRLB config file error.");
    }
    return error_level;
  }

  nt_print("LB listening port", num(cfg.port).c_str());
  if(cfg.scheme == LB_DISTRIB) nt_print("Load balancing scheme = LB_DISTRIB");
  if(cfg.scheme == LB_RR) nt_print("Load balancing scheme = LB_RR");
  if(cfg.scheme == LB_WEIGHTED) nt_print("Load balancing scheme = LB_WEIGHTED");
  if(cfg.scheme == LB_ASSIGNED) {
    nt_print("Load balancing scheme = LB_ASSIGNED");
    switch(cfg.assigned_default) {
      case LB_RR: nt_print("INFO - Assigned connections will use LB round robin for nodes with no rules"); break;
      case LB_DISTRIB: nt_print("INFO - Assigned connections will use LB distributed for node with no rules"); break;
      case LB_WEIGHTED: nt_print("INFO - Assigned connections will use LB weighted for node with no rules"); break;
      case LB_NONE: nt_print("INFO - Connections to nodes with assign rules will only connect to assigned node"); break;
      default:
        nt_print("ERROR - Bad assigned_default value in server config");
        return 1;
    }
  }

  if(cfg.use_buffer_cache == 1) {
    nt_print("Socket buffer cache enabled");
    if(cfg.enable_buffer_overflow_detection) {
      nt_print("INFO: Buffer overflow detection is enabled");
      nt_print("INFO: Buffer overflow size", num_commas(cfg.buffer_overflow_size).c_str());
    }
    else {
      nt_print("Buffer overflow detection is disabled");
    }
  }
  else {
    nt_print("Socket buffer cache disabled");
  }
  if(cfg.max_threads >= 1) nt_print("Max client threads set to", num(cfg.max_threads).c_str());
  else nt_print("Max client threads not set");
  if(cfg.max_connections >= 1) nt_print("Max frontend server clients set to", num(cfg.max_connections).c_str());
  else nt_print("Max frontend server clients not set");
  nt_print("Max retries for dead nodes set to", num(cfg.retries).c_str());
  nt_print("Retry wait secs for dead nodes set to", num(cfg.retry_wait).c_str());
  if(cfg.use_timeout) {
    nt_print("Socket read timeouts enabled");
    nt_print("Timeout secs", num(cfg.timeout_secs).c_str());
    nt_print("Timeout usecs", num(cfg.timeout_usecs).c_str());
  }
  else {
    nt_print("Socket read timeouts disabled");
  }
  nt_print("Max queued connection requests", num(cfg.somaxconn).c_str());
  nt_print("Write timeout secs", num(cfg.write_timeout_secs).c_str());
  nt_print("Backend connect timeout secs", num(cfg.connect_timeout_secs).c_str());
  nt_print("Max bytes read before each write", num(cfg.max_cache_size).c_str());
  nt_print("Max number of log or console messages to queue", num(cfg.log_queue_size).c_str());
  nt_print("Max number of debug messages to queue", num(cfg.log_queue_debug_size).c_str());
  nt_print("Max number of process messages to queue", num(cfg.log_queue_proc_size).c_str());

  if(cfg.enable_logging) {
    nt_print("Logging is enabled");
    if(cfg.clear_log) nt_print("Log file will cleared when LB server is restarted");
    nt_print("Number of log files to keep", num(cfg.num_logs_to_keep).c_str());
    nt_print("Max log file size set to", num_commas(cfg.max_log_size).c_str());
    nt_print("Logging level set to", num(cfg.log_level).c_str());
    nt_print("Log file", cfg.logfile_name.c_str());
    if(cfg.logfile_name.empty()) {
      cfg.enable_logging = 0;
      cfg.verbose = 1;
      nt_print("ERROR - Logging is enabled but logfile_name is not set");
      return 1;
    }
    if(!cfg.check_config) {
      FILE *fp = fopen(cfg.logfile_name.c_str(), "a");
      if(!fp) {
        cfg.enable_logging = 0;
        cfg.verbose = 1;
        nt_print("ERROR - Cannot open log file", cfg.logfile_name.c_str());
        nt_print("Exiting with errors");
        return 1;
      }
      fclose(fp);
    }
  }
  else {
    nt_print("Logging is disabled");
  }

  if(cfg.enable_stats) {
    nt_print("Stats collection is enabled");
    nt_print("Number of stats files to keep", num(cfg.num_stats_to_keep).c_str());
    nt_print("Max stats file size set to", num_commas(cfg.max_stats_size).c_str());
    nt_print("Stats file", cfg.stats_file_name.c_str());
    if(!cfg.check_config && !cfg.stats_file_name.empty()) {
      FILE *fp = fopen(cfg.stats_file_name.c_str(), "a");
      if(!fp) {
        cfg.enable_stats = 0;
        cfg.verbose = 1;
        nt_print("ERROR - Cannot open stats file", cfg.stats_file_name.c_str());
        nt_print("Exiting with errors");
        return 1;
      }
      fclose(fp);
    }
    std::ostringstream m;
    m << "Stats report time is " << cfg.stats_min << " minute(s) " << cfg.stats_secs << " second(s)";
    nt_print(m.str());
  }
  else {
    nt_print("Stats collection is disabled");
  }

  if(cfg.enable_throttling) {
    nt_print("Connection throttling is enabled");
    nt_print("Number of connections to start throttling", num(cfg.throttle_every_connections).c_str());
    nt_print("Seconds to hold connection in the throttle queue", num(cfg.throttle_wait_secs).c_str());
    nt_print("Microseconds to hold connection in the throttle queue", num(cfg.throttle_wait_usecs).c_str());
    if(cfg.throttle_apply_by_load) {
      nt_print("Peak load throttling is enabled");
      nt_print("Number of connection per second to start throttling", num(cfg.throttle_connections_per_sec).c_str());
      if(!cfg.enable_stats) {
        nt_print("NOTICE - DRLB server config has stats collection is disabled");
        nt_print("NOTICE - Stats will be enabled without logging for load throttling stat collection");
        cfg.stats_file_name.clear();
        cfg.enable_stats = 1;
        std::ostringstream m;
        m << "Stats collection time is " << cfg.stats_min << " minute(s) " << cfg.stats_secs << " second(s)";
        nt_print(m.str());
        nt_print("To set faster stat collection times set the stats_min and/or stats_secs parms");
      }
    }
    else {
      nt_print("Peak load throttling is disabled");
    }
  }
  else {
    nt_print("Connection throttling is disabled");
  }

  if(cfg.enable_http_forwarding) {
    nt_print("HTTP IP address forwarding is enabled");
    std::string list;
    for(char c : cfg.http_request_strings) if(c != ' ') list += c;
    cfg.http_requests.clear();
    for(const std::string &r : split(list, ',')) if(!r.empty()) cfg.http_requests.push_back(r);
    if(cfg.http_requests.empty()) {
      nt_print("ERROR - Bad HTTP request strings", cfg.http_request_strings.c_str());
      return 1;
    }
    nt_print("HTTP request string =", cfg.http_request_strings.c_str());
    nt_print("HTTP header string =", cfg.http_hdr_str.c_str());
    nt_print("HTTP forward string =", cfg.http_forward_for_str.c_str());
  }

  if(cfg.debug) {
    nt_print("Debug is enabled");
    nt_print("Debug level set to", num(cfg.debug_level).c_str());
  }
  else {
    nt_print("Debug is disabled");
  }
  if(cfg.verbose) {
    nt_print("Verbose mode is enabled");
    nt_print("Verbose mode level set to", num(cfg.verbose_level).c_str());
  }
  else {
    nt_print("Verbose mode is disabled");
  }

  nt_print("LB node config");
  int node_cfg_error_level = 0;
  for(auto &n : cfg.nodes) {
    nt_print("Node name", n->node_name.c_str());
    nt_print("LB node host", n->hostname.c_str());
    nt_print("LB node port", num(n->port_number).c_str());
    if(n->weight >= 1) {
      if(cfg.scheme == LB_WEIGHTED) {
        nt_print("LB node set for LB_WEIGHTED mode");
        nt_print("Weight for this node is", num(n->weight).c_str());
      }
      else if(cfg.scheme == LB_DISTRIB) {
        nt_print("LB node set for LB_DISTRIB mode");
        nt_print("Percent of load for this node is", num(n->weight).c_str(), "percent");
      }
      else {
        nt_print("LB node weight", num(n->weight).c_str());
        nt_print("Node weight not used in LB_RR mode");
      }
    }
    else {
      if(cfg.scheme == LB_WEIGHTED) {
        nt_print("ERROR - Node configuration error. Using LB_WEIGHTED mode with no node weight");
        node_cfg_error_level = 1;
      }
      if(cfg.scheme == LB_DISTRIB) {
        nt_print("ERROR - Node configuration error. Using LB_DISTRIB mode with no node load percent value");
        node_cfg_error_level = 1;
      }
      if(cfg.scheme == LB_ASSIGNED && cfg.assigned_default == LB_DISTRIB) {
        nt_print("ERROR - Node configuration error. Using LB_ASSIGNED with distrib failover and no node load percent value");
        node_cfg_error_level = 1;
      }
      if(cfg.scheme == LB_ASSIGNED && cfg.assigned_default == LB_WEIGHTED) {
        nt_print("ERROR - Node configuration error. Using LB_ASSIGNED with weighted failover and no node weight value");
        node_cfg_error_level = 1;
      }
      nt_print("LB node weight not set");
    }
    if(n->max_connections >= 1) nt_print("LB node max_connections", num(n->max_connections).c_str());
    else nt_print("LB node max_connections not set");
    nt_print("LB node buffer size", num(n->buffer_size).c_str());
  }
  if(node_cfg_error_level != 0) {
    cfg.verbose = 1;
    nt_print("ERROR - Node configuration error, check your server config file");
    nt_print("Exiting with config errors");
    return 1;
  }

  if(cfg.scheme == LB_ASSIGNED) {
    nt_print("Checking rules configuration file");
    if(cfg.rules_config_file.empty()) {
      nt_print("ERROR - No rules_config_file specified in LB server config");
      return 1;
    }
    switch(read_rules_config()) {
      case 0:
        nt_print("INFO - Assignment rules config file checks");
        nt_print("INFO - Rules config will only be read once. Changes will require a server restart.");
        break;
      case 1: nt_print("ERROR - Fatal error reading rules config file"); return 1;
      case 2: nt_print("ERROR - Bad rule line in rules config file"); return 1;
      case 3: nt_print("ERROR - Bad regular expression in rules config file"); return 1;
      default: nt_print("ERROR - Unknown error reading rules config file"); return 1;
    }
  }

  if(cfg.scheme == LB_DISTRIB || (cfg.scheme == LB_ASSIGNED && cfg.assigned_default == LB_DISTRIB)) {
    nt_print("Building distributed node assignments");
    if(!build_distributed_rr_node_list()) {
      cfg.verbose = 1;
      nt_print("ERROR - Error building distributed node list");
      nt_print("Exiting with config errors");
      return 1;
    }
    int total_percent = 0;
    for(Node *n : cfg.distributed_rr_node_list) {
      nt_print(n->node_name + " will assume " + num(n->weight) + "% of the backend load");
      total_percent += n->weight;
    }
    if(total_percent == 100) nt_print("Total load percent is 100");
    if(total_percent > 100) nt_print("WARNING - Total load percent of " + num(total_percent) + " is greater than 100");
    if(total_percent < 100) nt_print("WARNING - Total load percent of " + num(total_percent) + " is less than 100");

    nt_print("Building distributed refactored assignments");
    std::vector<LimitNode> limits;
    cfg.refactored_connections = refactor_distribution_limits(limits, cfg.refactor_scale);
    if(cfg.refactored_connections <= 0) {
      cfg.verbose = 1;
      nt_print("ERROR - Error building distributed refactored assignments");
      nt_print("Exiting with config errors");
      return 1;
    }
    for(const LimitNode &l : limits) {
      nt_print(l.node->node_name + " refactored to start with " + num(l.limit) + " backend connections");
    }
  }

  if(cfg.scheme == LB_WEIGHTED || (cfg.scheme == LB_ASSIGNED && cfg.assigned_default == LB_WEIGHTED)) {
    nt_print("Building weighted node assignments");
    if(!build_weighted_rr_node_list()) {
      cfg.verbose = 1;
      nt_print("ERROR - Error building weighted node list");
      nt_print("Exiting with config errors");
      return 1;
    }
    for(Node *n : cfg.weighted_rr_node_list) {
      nt_print(n->node_name + " assigned a weight factor of " + num(n->weight) + " for backend load");
    }
    nt_print("Building weighted refactored assignments");
    std::vector<LimitNode> limits;
    cfg.refactored_connections = refactor_weighted_limits(limits, cfg.weight_scale);
    if(cfg.refactored_connections <= 0) {
      cfg.verbose = 1;
      nt_print("ERROR - Error building weighted refactored assignments");
      nt_print("Exiting with config errors");
      return 1;
    }
    for(const LimitNode &l : limits) {
      nt_print(l.node->node_name + " refactored to start with " + num(l.limit) + " backend connections");
    }
    nt_print("Starting with " + num(cfg.refactored_connections) + " refactored connections");
  }

  // SSL/TLS
  if(cfg.ssl_name && !cfg.ssl.enabled) {
    cfg.verbose = 1;
    nt_print("ERROR - drlb_ssl_server needs an [SSLCONFIG] section in", cfg.config_file.c_str());
    nt_print("ERROR - Add an [SSLCONFIG] section, or run drlb_server for a plain TCP load balancer");
    return 1;
  }
  if(cfg.ssl.enabled) {
    nt_print("Reading [SSLCONFIG] config section from DRLB config file:", cfg.config_file.c_str());
    if(tls_init() != 0) {
      cfg.verbose = 1;
      nt_print("ERROR - SSL/TLS configuration error");
      return 1;
    }
  }
  else {
    nt_print("No [SSLCONFIG] section, SSL/TLS is disabled");
  }

  return 0;
}

} // namespace drlb
