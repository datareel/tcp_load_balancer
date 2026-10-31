// DRLB TCP load balancer
// Copyright (c) 2016-2026 DataReel Software Development
// GNU General Public License version 3 or later, see the COPYING file.
//
// String, time and sleep helpers.

#include "drlb.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace drlb {

std::string trim(const std::string &s)
{
  size_t b = s.find_first_not_of(" \t\r\n");
  if(b == std::string::npos) return "";
  size_t e = s.find_last_not_of(" \t\r\n");
  return s.substr(b, e - b + 1);
}

std::string to_lower(std::string s)
{
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
  return s;
}

std::string to_upper(std::string s)
{
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::toupper(c); });
  return s;
}

bool icontains(const std::string &haystack, const std::string &needle)
{
  return to_lower(haystack).find(to_lower(needle)) != std::string::npos;
}

std::vector<std::string> split(const std::string &s, char delim)
{
  std::vector<std::string> out;
  size_t start = 0;
  while(start <= s.size()) {
    size_t end = s.find(delim, start);
    if(end == std::string::npos) end = s.size();
    out.push_back(s.substr(start, end - start));
    start = end + 1;
  }
  return out;
}

long to_long(const std::string &s)
{
  return std::strtol(s.c_str(), nullptr, 10);
}

std::string errno_string(int error_number)
{
  // Same "NAME: description" form as the 1.60 log messages
  const char *name = strerrorname_np(error_number);
  char buf[256];
  std::string text = strerror_r(error_number, buf, sizeof(buf));
  if(!name) return "UNKNOWN: " + text;
  return std::string(name) + ": " + text;
}

std::string syslog_time()
{
  time_t now = time(nullptr);
  struct tm tm;
  localtime_r(&now, &tm);
  char buf[64];
  strftime(buf, sizeof(buf), "%b %d %H:%M:%S", &tm);
  return buf;
}

std::string gmt_date_time(time_t t)
{
  struct tm tm;
  gmtime_r(&t, &tm);
  char buf[64];
  strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm);
  return buf;
}

void sleep_secs(unsigned long secs)
{
  std::this_thread::sleep_for(std::chrono::seconds(secs));
}

void sleep_usecs(unsigned long usecs)
{
  std::this_thread::sleep_for(std::chrono::microseconds(usecs));
}

} // namespace drlb
