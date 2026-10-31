// DRLB TCP load balancer
// Copyright (c) 2016-2026 DataReel Software Development
// GNU General Public License version 3 or later, see the COPYING file.
//
// Backend node selection: round robin, assigned, distributed and
// weighted, the same rules as 1.60. Each function returns the node with
// a connected backend socket in s->backend_socket (and TLS session if
// ssl_encrypt_backend is set), or null.

#include "drlb.h"

#include <sstream>

namespace drlb {

static std::string seq(const ClientSocket *s)
{
  return "[" + std::to_string(s->seq_num) + "]: ";
}

// Connect to one backend node. Returns 0 if connected.
static int connect_backend(ClientSocket *s, Node *n, const char *how)
{
  if(cfg.log_level >= 2) {
    log_message(seq(s) + n->node_name + " " + how + " connect to " + n->hostname +
                " port " + std::to_string(n->port_number));
  }
  close_backend(s); // From a failed attempt on another node
  std::string error_message;
  int fd = connect_to_node(n, cfg.connect_timeout_secs, error_message);
  if(fd < 0) {
    if(cfg.log_level >= 1) {
      log_message(seq(s) + "ERROR - " + n->node_name + " cannot connect to backend host " + n->hostname +
                  " port " + std::to_string(n->port_number));
      log_message(seq(s) + error_message);
    }
    return 1;
  }
  s->backend_socket = fd;
  if(cfg.ssl.client_ctx) {
    if(tls_connect(s, n) != 0) {
      close_backend(s);
      return 1;
    }
  }
  return 0;
}

static Node *round_robin(ClientSocket *s, const std::vector<Node *> &node_list, std::atomic<unsigned long> &counter)
{
  if(node_list.empty()) return nullptr;

  // Each connection starts at the next node in the list and tries every
  // node once per pass. Nodes that refused a connection are skipped for
  // dead_node_secs, and the start node is picked among the live nodes, so
  // a dead node's share is spread over all live nodes. A failed pass is
  // retried up to retries times.
  std::vector<Node *> live;
  live.reserve(node_list.size());
  unsigned retries = cfg.retries;
  while(true) {
    time_t now = time(nullptr);
    live.clear();
    for(Node *n : node_list) if(n->down_until <= now) live.push_back(n);
    if(live.empty()) live = node_list; // All nodes are marked down, try them all
    size_t start = counter.fetch_add(1, std::memory_order_relaxed) % live.size();
    for(size_t tried = 0; tried < live.size(); tried++) {
      Node *n = live[(start + tried) % live.size()];
      if(check_node_max_clients(n, s->seq_num) != 0) continue;
      if(connect_backend(s, n, "RR") == 0) {
        n->down_until = 0;
        return n;
      }
      if(cfg.dead_node_secs > 0) n->down_until = time(nullptr) + cfg.dead_node_secs;
    }
    if(retries == 0) break;
    retries--;
    log_message(seq(s) + "ERROR - All connection attempts failed, retries left " + std::to_string(retries));
    if(cfg.retry_wait > 0) sleep_secs(cfg.retry_wait);
  }
  log_message(seq(s) + "ERROR - All connection attempts failed");
  return nullptr;
}

static std::vector<Node *> all_nodes()
{
  std::vector<Node *> v;
  for(auto &n : cfg.nodes) v.push_back(n.get());
  return v;
}

static Node *round_robin(ClientSocket *s)
{
  static const std::vector<Node *> nodes = all_nodes();
  return round_robin(s, nodes, cfg.rr_counter[0]);
}

static Node *assigned(ClientSocket *s)
{
  const Rule *match = nullptr;
  bool looked_up = false;
  int lookup_rv = 0;
  std::string hostname_str, error_message;
  for(const auto &rule : cfg.rules) {
    if(regexec(&rule->regex, s->client_name.c_str(), 0, nullptr, 0) == 0) {
      if(cfg.debug_at(5)) {
        log_debug_message(seq(s) + "INFO - Frontend IP matches regex: " + s->client_name + " match " + rule->front_end_client_ip);
      }
      match = rule.get();
      break;
    }
    if(cfg.resolve_assigned_hostnames) {
      if(!looked_up) { // One reverse lookup per connection
        lookup_rv = ip_to_hostname(s->client_name, hostname_str, error_message);
        looked_up = true;
      }
      if(lookup_rv == 0) {
        if(s->client_name != hostname_str && !hostname_str.empty()) {
          if(regexec(&rule->regex_icase, hostname_str.c_str(), 0, nullptr, 0) == 0) {
            if(cfg.debug_at(5)) {
              log_debug_message(seq(s) + "INFO - Frontend hostname matches regex: " + hostname_str + " match " + rule->front_end_client_ip);
            }
            match = rule.get();
            break;
          }
          if(cfg.debug_at(5)) {
            log_debug_message(seq(s) + "INFO - Frontend IP/hostname does not match regex: " + s->client_name +
                              "/" + hostname_str + " no match " + rule->front_end_client_ip);
          }
        }
        else if(cfg.debug_at(5)) {
          log_debug_message(seq(s) + "INFO - Frontend IP does not match regex: " + s->client_name + " no match " + rule->front_end_client_ip);
        }
      }
      else if(cfg.debug && cfg.debug_level > 3) {
        log_debug_message(seq(s) + "ERROR - Get hostname error for IP " + s->client_name + " " + error_message);
      }
    }
    else if(cfg.debug_at(5)) {
      log_debug_message(seq(s) + "INFO - Frontend IP does not match regex: " + s->client_name + " no match " + rule->front_end_client_ip);
    }
  }

  if(!match) {
    if(cfg.debug_at(5)) log_debug_message(seq(s) + "INFO - No matching rules in config file " + cfg.rules_config_file);
    return nullptr;
  }

  Node *n = nullptr;
  for(auto &node : cfg.nodes) {
    if(node->node_name == match->node_name) {
      n = node.get();
      break;
    }
  }
  if(!n) {
    if(cfg.debug && cfg.debug_level >= 2) log_message(seq(s) + "Rule config file error no LB nodes matchs rule set");
    return nullptr;
  }
  if(cfg.debug_at(5)) log_debug_message(seq(s) + "Assigned node " + n->node_name + " matches rule " + match->front_end_client_ip);
  if(check_node_max_clients(n, s->seq_num) != 0) return nullptr;
  if(connect_backend(s, n, "Assigned") != 0) return nullptr;
  return n;
}

// Shared by the distributed and weighted schemes. Rebuilds the per node
// connection limits when the number of connections grows past the
// current limits or drops below the previous ones, then picks the first
// node under its limit, or falls back to round robin over the ordered
// node list.
static Node *limited(ClientSocket *s, bool weighted)
{
  const char *how = weighted ? "Weighted" : "Distributed";
  std::vector<LimitNode> limits;
  int num_connections = get_num_node_connections();
  if(num_connections == 0) num_connections = 1;

  {
    std::lock_guard<std::mutex> lock(cfg.refactor_lock);
    if(cfg.debug) {
      log_debug_message("Number of active server connections " + std::to_string(num_connections));
      log_debug_message("Number of refactored connections " + std::to_string(cfg.refactored_connections));
      if(cfg.debug_level >= 2) {
        log_debug_message("Number of prev refactored connections " + std::to_string(cfg.prev_refactored_connections));
      }
    }
    auto set_positive = [](int &var, int value) { if(value > 0) var = value; };
    const char *change = nullptr;
    if(num_connections >= cfg.refactored_connections) {
      set_positive(cfg.prev_refactored_connections, cfg.refactored_connections);
      if(weighted) {
        cfg.weight_scale++;
        set_positive(cfg.refactored_connections, refactor_weighted_limits(limits, cfg.weight_scale));
      }
      else {
        set_positive(cfg.refactored_connections, refactor_distribution_limits(limits, num_connections));
      }
      change = "increased";
    }
    if(num_connections < cfg.prev_refactored_connections) {
      if(weighted) {
        if(--cfg.weight_scale <= 0) cfg.weight_scale = 1;
        set_positive(cfg.refactored_connections, refactor_weighted_limits(limits, cfg.weight_scale));
      }
      else {
        set_positive(cfg.refactored_connections, refactor_distribution_limits(limits, num_connections));
      }
      set_positive(cfg.prev_refactored_connections, cfg.refactored_connections);
      change = "decreased";
    }
    if(change && cfg.debug) {
      for(const LimitNode &l : limits) {
        log_debug_message(l.node->node_name + " refactor level " + change + " to " + std::to_string(l.limit) + " backend connections");
      }
    }
    if(limits.empty()) { // Build the default list
      if(weighted) refactor_weighted_limits(limits, cfg.weight_scale);
      else refactor_distribution_limits(limits, cfg.prev_refactored_connections);
    }
  }

  const std::vector<Node *> &rr_list = weighted ? cfg.weighted_rr_node_list : cfg.distributed_rr_node_list;
  std::atomic<unsigned long> &counter = cfg.rr_counter[weighted ? 2 : 1];

  Node *n = nullptr;
  for(const LimitNode &l : limits) {
    if((unsigned)(int)l.node->num_connections < l.limit) {
      if(check_node_max_clients(l.node, s->seq_num) == 0) n = l.node;
      break;
    }
  }
  if(!n) return round_robin(s, rr_list, counter);
  if(connect_backend(s, n, how) != 0) {
    if(cfg.debug_at(5)) {
      log_debug_message(seq(s) + "Connection error will default to " + (weighted ? "weighted" : "distributed") + " round robin");
    }
    return round_robin(s, rr_list, counter);
  }
  return n;
}

Node *select_node(ClientSocket *s)
{
  switch(cfg.scheme) {
    case LB_ASSIGNED: {
      Node *n = assigned(s);
      if(n) return n;
      switch(cfg.assigned_default) {
        case LB_DISTRIB:
          if(cfg.debug_at(5)) log_debug_message(seq(s) + "LB assigned will fail over to distributed");
          return limited(s, false);
        case LB_WEIGHTED:
          if(cfg.debug_at(5)) log_debug_message(seq(s) + "LB assigned will fail over to weighted");
          return limited(s, true);
        case LB_NONE:
          if(cfg.debug_at(5)) log_debug_message(seq(s) + "LB assigned will not fail over to another node");
          return nullptr;
        default:
          if(cfg.debug_at(5)) log_debug_message(seq(s) + "LB assigned will default to round robin");
          return round_robin(s);
      }
    }
    case LB_DISTRIB:
      return limited(s, false);
    case LB_WEIGHTED:
      return limited(s, true);
    default:
      return round_robin(s);
  }
}

} // namespace drlb
