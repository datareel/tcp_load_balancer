// DRLB TCP load balancer
// Copyright (c) 2016-2026 DataReel Software Development
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at
// your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.
//
// One program for the DRLB TCP load balancer (drlb_server) and the DRLB
// SSL bridge (drlb_ssl_server). A config file with an [SSLCONFIG]
// section terminates TLS on the frontend.

#include "drlb.h"

#include <csignal>
#include <cstdio>
#include <cstring>
#include <iostream>

#include <unistd.h>

using namespace drlb;

int main(int argc, char **argv)
{
  // A client that disconnects while we write to it must not kill the process
  signal(SIGPIPE, SIG_IGN);

  const char *name = strrchr(argv[0], '/');
  name = name ? name + 1 : argv[0];
  cfg.program_name = name;
  if(cfg.program_name == "drlb_ssl_server") cfg.ssl_name = 1;

  // Termination signals are handled in a dedicated thread. SIGSEGV and
  // SIGBUS keep the default action so a crash leaves a core file and
  // systemd can restart the service.
  if(start_signal_thread() != 0) {
    cfg.verbose = 1;
    nt_print("ERROR - Cannot start the signal handling thread");
    return 1;
  }

  if(process_args(argc, argv) != 0) {
    cfg.verbose = 1;
    nt_print("ERROR - Bad -- argument, use --help to print valid -- arguments");
    return 1;
  }

  if(!cfg.user_config_file) {
    cfg.verbose = 1;
    nt_print("ERROR - No config file specified. Use --config-file option to specify a config file");
    nt_print("INFO - If you do not have a config file the program will build a default config and exit");
    nt_print("INFO - Use the --help option to see help menu");
    return 1;
  }

  if(cfg.check_config) {
    int rv = check_config();
    tls_cleanup();
    if(rv != 0) return 1;
    nt_print("DRLB config file checks good");
    return 0;
  }

  nt_print("Starting", ProgramDescription, VersionString);
  int error_level = check_config();
  if(error_level != 0) {
    tls_cleanup();
    return error_level;
  }

  if(cfg.enable_logging) {
    nt_log_rotate();
    if(cfg.clear_log) {
      if(cfg.debug_at(3)) nt_print("INFO - Clearing log file", cfg.logfile_name.c_str());
      clear_log_file();
    }
  }

  error_level = run_server();
  nt_print("Exiting DRLB program...");
  close_log_file();
  std::cout.flush();

  if(error_level == 2) {
    // Client threads are still running. Exit without running static
    // destructors, which those threads may still be using.
    _exit(0);
  }
  tls_cleanup();
  return error_level;
}
