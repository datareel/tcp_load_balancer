# DRLB TCP load balancer 2.0: design

## Goal

One C++17 program, `drlb_server`, that replaces both 1.60/1.61 packages:

- **load-balancer** (`drlb_server`): plain TCP load balancing.
- **ssl-bridge** (`drlb_ssl_server`): the same load balancer with TLS
  termination on the frontend and optional TLS to the backends.

It is built only on the C++ standard library, POSIX and OpenSSL. No
DataReel library code is used or copied. LDM-load-balancer is not part
of this project; it stays in the `legacy_drlb` repository.

All 1.60/1.61 behavior is kept: the same config file format and
settings, the four schemes (round robin, weighted, distributed,
assigned), dead node handling, throttling, X-Forwarded-For rewriting,
log and stats files with rotation, the drlb user, systemd sandboxing,
TLS 1.2+ defaults and RHEL 8 (NetworkManager and firewalld only), 9
and 10 support.

## When TLS is used

Both old config files work unchanged:

- A config **without** an `[SSLCONFIG]` section (every 1.60
  `drlb_server` config) runs as a plain TCP load balancer.
- A config **with** an `[SSLCONFIG]` section (every 1.60
  `ssl_bridge.cfg`) terminates TLS on the frontend, exactly like
  `drlb_ssl_server` 1.60. `ssl_encrypt_backend = 1` also uses TLS to the
  backend nodes, with certificate verification on by default.

`drlb_ssl_server` is installed as a symbolic link to `drlb_server`.
When the program runs under that name, the config must have an
`[SSLCONFIG]` section. Without one it stops with an error, so an SSL
service never falls back to plain TCP by mistake.

## DataReel replacements

| DataReel 1.60 | 2.0 |
|---|---|
| gxString, UString | `std::string`, `std::ostringstream` |
| gxList, gxListNode | `std::vector`, `std::deque` |
| gxBStree (weight ordering) | `std::map` |
| gxThread, thrPool | `std::thread` and an atomic count of client threads |
| gxMutex, gxCondition | `std::mutex`, `std::condition_variable` |
| DiskFileB, LogFile | `std::ifstream`, `std::ofstream`, stdio `FILE*` for logs |
| futils_exists | `std::filesystem::exists` |
| SysTime | `std::time`, `localtime_r`, `gmtime_r`, `strftime` |
| MemoryBuffer, RelayBuffer | `std::string` |
| gxSocket | POSIX sockets (`socket`, `getaddrinfo`, `poll`) |
| gxSSL | OpenSSL API directly |
| ParseStrings | a small split helper |

Thread cancellation (`pthread_cancel` through gxThread) is gone. Every
thread checks a stop flag or waits on a condition variable, and the
accept loop waits in `poll()` on the listening socket and a wakeup pipe.

## Source layout

```
src/drlb.h       shared types, settings and function declarations
src/main.cpp     main(), startup, shutdown
src/config.cpp   command line, config file, rules file, [SSLCONFIG], startup checks
src/log.cpp      log queues, log thread, log rotation, console output
src/stats.cpp    stats thread and stats file rotation
src/net.cpp      listening socket, backend connect, reverse DNS check, errno text
src/tls.cpp      OpenSSL contexts and per connection TLS
src/relay.cpp    poll() based relay and the X-Forwarded-For filter (port of m_relay)
src/balance.cpp  round robin, weighted, distributed and assigned node selection
src/server.cpp   accept thread, client threads, signal thread
```

## Threads

- **main**: loads the config, starts the other threads, waits for a stop
  request, then shuts down in order.
- **signal**: all threads block the termination and debug signals; this
  thread receives them with `sigwait()` (same as 1.60).
- **accept**: accepts connections, applies `max_threads` and
  `max_connections`, starts one detached client thread per connection.
- **client** (one per connection): throttling, frontend TLS handshake,
  node selection, backend connect (and TLS), relay.
- **log**: writes queued log messages to the log file and console.
- **stats**: writes a stats report every `stats_min`/`stats_secs`.

Shutdown (SIGTERM or SIGINT): stop accepting, wait up to
`write_timeout_secs + 5` seconds for client threads (each relay loop
checks the stop flag every second), stop the stats and log threads,
flush the logs and exit 0.

## Config compatibility

The parser follows the 1.60 rules: `#` and `;` comment lines, inline
`#` comments, case-insensitive names, `name = value`, true/false values
(`1`, `TRUE`, `T`, `YES`, `Y`), command line overrides for logging,
stats, debug and verbose. Every 1.60 setting is accepted with the same
default. Two small differences, both only visible with malformed files:

- Setting names must match exactly. 1.60 matched some names as
  substrings (for example any name containing `buffer_size`).
- An unknown setting is reported as a warning instead of being ignored
  silently.

## Packaging

One RPM, `drlb_server` 2.0 (release 1), for RHEL 8, RHEL 9 and RHEL 10:

- `/usr/sbin/drlb_server` and the `/usr/sbin/drlb_ssl_server` link
- `drlb_server.service`, `drlb_server@.service` and
  `drlb_ssl_server.service` (same units and sandboxing as 1.60)
- `/etc/sysconfig/drlb_server`, `/etc/sysconfig/drlb_ssl_server`,
  `/etc/drlb/active_configs.list`, the example configs and
  `/etc/drlb/ssl_bridge.cfg`
- `/usr/share/doc/drlb/`: `USER_GUIDE.md`, `README.md`, the release
  notes and `example_config.cfg`
- `Obsoletes: drlb_ssl_server < 2.0` and `Provides: drlb_ssl_server`, so
  an upgrade replaces both old packages

## Documentation

[docs/USER_GUIDE.md](docs/USER_GUIDE.md) is the user documentation. It
replaces the 1.60 load-balancer and ssl-bridge READMEs and describes
2.0 behavior, so it follows the source: when a setting, default or
check changes in `src/config.cpp`, update its settings reference.

## Build

`make` (g++ with `-std=c++17 -O2 -Wall -Wextra`), or CMake. `make asan`
builds an AddressSanitizer binary for testing.

## Tests

`tests/drlb_tests.py` and `tests/ssl_bridge_tests.py` are the 1.60
regression suites, run against the new binary, plus
`tests/compat_tests.py` for 2.0 specific checks (config compatibility,
the `drlb_ssl_server` name, stats and log files).
