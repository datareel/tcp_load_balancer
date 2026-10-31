// DRLB TCP load balancer
// Copyright (c) 2016-2026 DataReel Software Development
// GNU General Public License version 3 or later, see the COPYING file.
//
// Stats thread. Writes a report every stats_min minutes and stats_secs
// seconds, in the same format as 1.60, and keeps connections_per_second
// up to date for load based throttling.

#include "drlb.h"

#include <cstdio>
#include <sstream>
#include <thread>

#include <sys/stat.h>

namespace drlb {

namespace {

std::mutex stats_lock;
std::condition_variable stats_cond;
bool stats_stop = false;
std::thread stats_thread;
FILE *stats_fp = nullptr;
int last_stats = 0;

bool open_stats_file()
{
  if(stats_fp) return true;
  stats_fp = fopen(cfg.stats_file_name.c_str(), "a");
  return stats_fp != nullptr;
}

int rotate_stats_file()
{
  struct stat st;
  if(stat(cfg.stats_file_name.c_str(), &st) != 0 || st.st_size < cfg.max_stats_size) return 0;

  std::string pre = syslog_time() + " " + cfg.service_name + ": ";
  std::string m = pre + "Stats file exceeded " + std::to_string(cfg.max_stats_size) + " bytes\n";
  fputs(m.c_str(), stats_fp);

  int next_stats = 1;
  last_stats++;
  if(last_stats > cfg.num_stats_to_keep) last_stats = 0;
  else next_stats = last_stats;
  std::string new_name = cfg.stats_file_name + "." + std::to_string(next_stats);

  m = pre + "Rotating stats, saving prev stats file " + new_name + "\n";
  fputs(m.c_str(), stats_fp);
  fclose(stats_fp);
  stats_fp = nullptr;
  if(rename(cfg.stats_file_name.c_str(), new_name.c_str()) != 0) {
    if(open_stats_file()) {
      m = pre + "ERROR - could not rotate stats, cannot create new stats file " + new_name + "\n";
      fputs(m.c_str(), stats_fp);
      fflush(stats_fp);
    }
    return 0;
  }
  if(!open_stats_file()) {
    log_message("Error writing to stats file " + cfg.stats_file_name);
    return 0;
  }
  m = pre + "New stats file started \n";
  fputs(m.c_str(), stats_fp);
  fflush(stats_fp);
  return 1;
}

void stats_thread_main()
{
  log_message("DRLB stat reporting is enabled");
  int wait_secs = cfg.stats_min * 60 + cfg.stats_secs;
  if(wait_secs <= 0) {
    log_message("Invalid stats report time in server config, defaulting to 5 minute reporting");
    wait_secs = 300;
  }

  std::vector<unsigned long> node_prev(cfg.nodes.size());
  for(size_t i = 0; i < cfg.nodes.size(); i++) node_prev[i] = cfg.nodes[i]->connection_total;
  unsigned long prev_total_connections = cfg.connection_total;
  time_t prev_etime = time(nullptr);

  std::unique_lock<std::mutex> lock(stats_lock);
  while(!stats_stop) {
    stats_cond.wait_for(lock, std::chrono::seconds(wait_secs), [] { return stats_stop; });
    if(stats_stop || !cfg.accept_clients) break;

    time_t etime = time(nullptr);
    if(cfg.debug_at(5)) log_message("Generating DRLB stat report");
    unsigned long total_runtime_connections = cfg.connection_total;
    unsigned long elapsed_secs = etime - prev_etime;
    if(elapsed_secs == 0) elapsed_secs = 1;
    unsigned long node_current_connections = 0;

    std::ostringstream node_message;
    for(size_t i = 0; i < cfg.nodes.size(); i++) {
      Node *n = cfg.nodes[i].get();
      unsigned long node_connections = (unsigned long)(int)n->num_connections;
      unsigned long node_total = n->connection_total;
      node_current_connections += node_connections;
      node_message << "Total Runtime Connections to " << n->node_name << ": " << node_total << "\n";
      node_message << "Connections per second to " << n->node_name << ": " << (node_total - node_prev[i]) / elapsed_secs << "\n";
      node_message << "Current Connections to " << n->node_name << ": " << node_connections;
      if(i + 1 < cfg.nodes.size()) node_message << "\n";
      node_prev[i] = node_total;
    }

    unsigned long server_connection_avg = (total_runtime_connections - prev_total_connections) / elapsed_secs;
    cfg.connections_per_second = (int)server_connection_avg;

    time_t uptime = etime - cfg.etime_server_start;
    time_t interval = etime - prev_etime;
    std::ostringstream m;
    m << "\n"
      << "BEGIN " << cfg.service_name << " stats\n"
      << "Server start time: " << gmt_date_time(cfg.etime_server_start) << "\n"
      << "Stats report time: " << gmt_date_time(etime) << "\n"
      << "Uptime: " << uptime / 86400 << " days. " << (uptime % 86400) / 3600 << " hrs. "
      << (uptime % 3600) / 60 << " mins. " << uptime % 60 << " secs.\n"
      << "Total runtime connections: " << total_runtime_connections << "\n"
      << "Report interval: " << interval / 3600 << " hrs. " << (interval % 3600) / 60 << " mins. "
      << interval % 60 << " secs.\n"
      << "Connections per second: " << server_connection_avg << "\n"
      << "Current connections: " << node_current_connections << "\n"
      << node_message.str() << "\n"
      << "END " << cfg.service_name << " stats\n";

    // An empty stats_file_name only collects connections_per_second
    if(!cfg.stats_file_name.empty()) {
      if(open_stats_file()) {
        fputs(m.str().c_str(), stats_fp);
        fflush(stats_fp);
        rotate_stats_file();
      }
      else {
        log_message("ERROR - Cannot write to stats file " + cfg.stats_file_name);
      }
    }
    prev_etime = etime;
    prev_total_connections = total_runtime_connections;
  }
  if(stats_fp) {
    fclose(stats_fp);
    stats_fp = nullptr;
  }
}

} // namespace

int start_stats_thread()
{
  if(!cfg.enable_stats) {
    log_message("DRLB stat reporting is disabled");
    return 0;
  }
  try {
    stats_thread = std::thread(stats_thread_main);
  }
  catch(const std::system_error &) {
    return 1;
  }
  return 0;
}

void stop_stats_thread()
{
  if(!stats_thread.joinable()) return;
  {
    std::lock_guard<std::mutex> lock(stats_lock);
    stats_stop = true;
  }
  stats_cond.notify_one();
  stats_thread.join();
}

} // namespace drlb
