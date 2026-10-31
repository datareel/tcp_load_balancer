// DRLB TCP load balancer
// Copyright (c) 2016-2026 DataReel Software Development
// GNU General Public License version 3 or later, see the COPYING file.
//
// Logging. Client threads queue their messages and the log thread
// writes them, so a slow disk never holds up a connection. There are
// three bounded queues, sized by log_queue_size, log_queue_debug_size
// and log_queue_proc_size. When a queue is full its oldest message is
// dropped. The startup and shutdown messages (nt_print) are written
// directly.

#include "drlb.h"

#include <algorithm>
#include <cstdio>
#include <deque>
#include <iostream>
#include <thread>

#include <sys/stat.h>

namespace drlb {

namespace {

struct LogEntry {
  unsigned long long seq;
  std::string text; // Complete line with the time prefix
};

std::mutex queue_lock;
std::condition_variable queue_cond;
std::deque<LogEntry> queues[3]; // Messages, debug messages, process messages
unsigned long long next_seq = 0;
unsigned long dropped = 0;
bool log_thread_running = false;
bool log_thread_stop = false;
std::thread log_thread;

std::mutex file_lock; // Guards log_fp, last_log and console output
FILE *log_fp = nullptr;
int last_log = 0;

std::string prefix()
{
  return syslog_time() + " " + cfg.service_name + ": ";
}

// Caller holds file_lock
bool open_log_file()
{
  if(log_fp) return true;
  if(cfg.logfile_name.empty()) return false;
  log_fp = fopen(cfg.logfile_name.c_str(), "a");
  return log_fp != nullptr;
}

// Caller holds file_lock. Console output for one complete line.
void console(const std::string &line, size_t prefix_len)
{
  if(cfg.check_config) std::cout << line.substr(prefix_len); // Interactive, no time prefix
  else std::cout << line;
  std::cout.flush();
}

// Caller holds file_lock
void report_log_error(const std::string &pre)
{
  if(!cfg.verbose) return;
  console(pre + "Error writing to log file " + cfg.logfile_name + "\n", pre.size());
}

// Caller holds file_lock. Returns 1 if the log was rotated.
int rotate_log_file()
{
  if(!cfg.enable_logging) return 0;
  std::string pre = prefix();
  if(!open_log_file()) {
    report_log_error(pre);
    return 0;
  }
  struct stat st;
  if(stat(cfg.logfile_name.c_str(), &st) != 0 || st.st_size < cfg.max_log_size) return 0;

  std::string m = pre + "Log file exceeded " + std::to_string(cfg.max_log_size) + " bytes\n";
  fputs(m.c_str(), log_fp);
  if(cfg.verbose) console(m, pre.size());

  int next_log = 1;
  last_log++;
  if(last_log > cfg.num_logs_to_keep) last_log = 0;
  else next_log = last_log;
  std::string new_name = cfg.logfile_name + "." + std::to_string(next_log);

  m = pre + "Rotating log, saving prev log file " + new_name + "\n";
  fputs(m.c_str(), log_fp);
  fclose(log_fp);
  log_fp = nullptr;
  if(rename(cfg.logfile_name.c_str(), new_name.c_str()) != 0) {
    m = pre + "ERROR - could not rotate log, cannot create new log file " + new_name + "\n";
    if(open_log_file()) { fputs(m.c_str(), log_fp); fflush(log_fp); }
    if(cfg.verbose) console(m, pre.size());
    return 0;
  }
  if(cfg.verbose) console(m, pre.size());
  if(open_log_file()) {
    m = pre + "New log file started \n";
    fputs(m.c_str(), log_fp);
    fflush(log_fp);
    if(cfg.verbose) console(m, pre.size());
  }
  else {
    report_log_error(pre);
  }
  return 1;
}

// Write one queued line to the log file and console
void write_log_entry(const std::string &line)
{
  std::lock_guard<std::mutex> lock(file_lock);
  if(cfg.enable_logging) {
    if(open_log_file()) {
      fputs(line.c_str(), log_fp);
      fflush(log_fp);
      rotate_log_file();
    }
    else {
      report_log_error(prefix());
    }
  }
  if(cfg.verbose) console(line, line.find(": ") == std::string::npos ? 0 : line.find(": ") + 2);
}

void queue_message(int queue, const std::string &mesg)
{
  std::string line = prefix() + mesg + "\n";
  {
    std::lock_guard<std::mutex> lock(queue_lock);
    if(log_thread_running) {
      static const int *sizes[3] = { &cfg.log_queue_size, &cfg.log_queue_debug_size, &cfg.log_queue_proc_size };
      std::deque<LogEntry> &q = queues[queue];
      if((int)q.size() >= *sizes[queue]) {
        q.pop_front();
        dropped++;
      }
      q.push_back(LogEntry{next_seq++, std::move(line)});
      queue_cond.notify_one();
      return;
    }
  }
  write_log_entry(line); // No log thread yet, or it has stopped
}

// Take every queued message, oldest first
std::vector<std::string> take_all()
{
  std::vector<LogEntry> all;
  for(auto &q : queues) {
    for(auto &e : q) all.push_back(std::move(e));
    q.clear();
  }
  std::sort(all.begin(), all.end(), [](const LogEntry &a, const LogEntry &b) { return a.seq < b.seq; });
  std::vector<std::string> out;
  out.reserve(all.size() + 1);
  if(dropped) {
    out.push_back(prefix() + "WARNING - Log queue full, " + std::to_string(dropped) + " messages dropped\n");
    dropped = 0;
  }
  for(auto &e : all) out.push_back(std::move(e.text));
  return out;
}

void log_thread_main()
{
  std::unique_lock<std::mutex> lock(queue_lock);
  while(true) {
    queue_cond.wait_for(lock, std::chrono::seconds(1), [] {
      return log_thread_stop || !queues[0].empty() || !queues[1].empty() || !queues[2].empty();
    });
    std::vector<std::string> lines = take_all();
    bool stop = log_thread_stop;
    lock.unlock();
    for(const std::string &line : lines) write_log_entry(line);
    lock.lock();
    if(stop && queues[0].empty() && queues[1].empty() && queues[2].empty()) break;
  }
  log_thread_running = false;
}

} // namespace

void log_message(const std::string &mesg) { queue_message(0, mesg); }
void log_debug_message(const std::string &mesg) { queue_message(1, mesg); }
void log_proc_message(const std::string &mesg) { queue_message(2, mesg); }

int start_log_thread()
{
  std::lock_guard<std::mutex> lock(queue_lock);
  if(log_thread_running) return 0;
  log_thread_stop = false;
  try {
    log_thread = std::thread(log_thread_main);
  }
  catch(const std::system_error &) {
    return 1;
  }
  log_thread_running = true;
  return 0;
}

void stop_log_thread()
{
  {
    std::lock_guard<std::mutex> lock(queue_lock);
    if(!log_thread.joinable()) return;
    log_thread_stop = true;
    queue_cond.notify_one();
  }
  log_thread.join();
}

void close_log_file()
{
  std::lock_guard<std::mutex> lock(file_lock);
  if(log_fp) {
    fclose(log_fp);
    log_fp = nullptr;
  }
}

int nt_log_rotate()
{
  std::lock_guard<std::mutex> lock(file_lock);
  return rotate_log_file();
}

int clear_log_file()
{
  std::lock_guard<std::mutex> lock(file_lock);
  if(log_fp) fclose(log_fp);
  log_fp = fopen(cfg.logfile_name.c_str(), "w");
  return log_fp ? 0 : 1;
}

int nt_print(const char *mesg1, const char *mesg2, const char *mesg3)
{
  if(!mesg1) return 0;
  int verbose = cfg.verbose;
  int enable_logging = cfg.enable_logging;
  if(cfg.check_config) {
    // A config check always prints to the console and never logs
    verbose = 1;
    enable_logging = 0;
  }

  std::string pre = prefix();
  std::string line = pre + mesg1;
  if(mesg2) line += std::string(" ") + mesg2;
  if(mesg3) line += std::string(" ") + mesg3;
  line += "\n";

  std::lock_guard<std::mutex> lock(file_lock);
  if(enable_logging) {
    if(open_log_file()) {
      fputs(line.c_str(), log_fp);
      fflush(log_fp);
    }
    else {
      if(verbose) console(pre + "Error writing to log file " + cfg.logfile_name + "\n", pre.size());
    }
  }
  if(verbose) console(line, pre.size());
  return 1;
}

} // namespace drlb
