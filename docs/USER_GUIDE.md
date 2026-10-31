# DRLB TCP load balancer 2.0 user guide

DataReel load balancer (DRLB) 2.0, `drlb_server`.
Copyright (c) 2016-2026 DataReel Software Development.
Online docs: http://datareel.com/info_drlb.html

## Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Supported platforms](#supported-platforms)
4. [Conventions](#conventions)
5. [Installing from RPM](#installing-from-rpm)
6. [Building from source](#building-from-source)
7. [Upgrading from 1.60 and 1.61](#upgrading-from-160-and-161)
8. [Quick start](#quick-start)
9. [TCP mode and SSL mode](#tcp-mode-and-ssl-mode)
10. [Running as a service](#running-as-a-service)
11. [Service security](#service-security)
12. [Firewall settings](#firewall-settings)
13. [Command line options](#command-line-options)
14. [Signals](#signals)
15. [Config file format](#config-file-format)
16. [Settings reference](#settings-reference)
17. [Listening port and nodes](#listening-port-and-nodes)
18. [Load balancing schemes](#load-balancing-schemes)
19. [Dead node retry](#dead-node-retry)
20. [Connection and thread limits](#connection-and-thread-limits)
21. [Buffers and caching](#buffers-and-caching)
22. [Timeouts](#timeouts)
23. [Throttling](#throttling)
24. [HTTP X-Forwarded-For forwarding](#http-x-forwarded-for-forwarding)
25. [Logging](#logging)
26. [Statistics](#statistics)
27. [TLS certificates and settings](#tls-certificates-and-settings)
28. [Tuning](#tuning)
29. [Testing](#testing)
30. [Support](#support)

## Overview

`drlb_server` is a software TCP load balancer for Linux. It accepts TCP
connections on one port and relays each one to a back end server node.
It works with any TCP service. It protects back end servers from
having more clients than one server can handle, and it moves
connections away from nodes that are down.

With an `[SSLCONFIG]` section in its config file, the same program
terminates SSL/TLS on the front end (the DRLB SSL bridge). It can send
the decrypted traffic to plain HTTP back ends, or encrypt it again to
HTTPS back ends. Because the traffic is decrypted, the client address
can be added to HTTP requests with an `X-Forwarded-For` header.

Version 2.0 combines the 1.60/1.61 **load-balancer** (`drlb_server`) and
**ssl-bridge** (`drlb_ssl_server`) packages in one program. It is
written in C++17 with only the standard library, POSIX and OpenSSL.
[DESIGN.md](../DESIGN.md) describes how the code is organized.

DRLB is open source under the GNU General Public License version 3 or
later. It can be used freely by commercial, government and academic
institutions.

## Features

- **Round robin** (`LB_RR`): connections go to each node in turn.
- **Weighted** (`LB_WEIGHTED`): nodes with a higher weight get more
  connections.
- **Distributed** (`LB_DISTRIB`): each node gets a set percent of the
  connections.
- **Assigned** (`LB_ASSIGNED`): client addresses or host names are
  routed to set nodes by rules, with round robin, weighted or
  distributed fail over for everything else.
- **SSL/TLS**: TLS 1.2 and 1.3 on the front end, optional TLS with
  certificate checks to the back ends.
- **Dead node handling**: a node that refuses a connection is skipped
  for a while, and the connection goes to another node.
- **Throttling**: hold connections for a short time to protect back
  ends during load peaks.
- **Connection limits**: per server and per node.
- **HTTP forwarding**: add the client address in an `X-Forwarded-For`
  header.
- **Logging and statistics**: log and stats files with size based
  rotation.
- **Buffer overflow detection**: close clients that send more data at
  once than the application expects.
- **systemd services** with a dedicated `drlb` user and sandboxing.

## Supported platforms

DRLB is built and tested on 64-bit Red Hat Enterprise Linux and RHEL
rebuilds such as Rocky Linux and AlmaLinux.

| Platform | Support |
|---|---|
| RHEL 10 | Supported |
| RHEL 9 | Supported |
| RHEL 8 | Only with NetworkManager and firewalld. The legacy network-scripts (ifcfg `network` service) and the iptables services are not supported. |
| RHEL 7 and earlier | Not supported |

The RPM is built for each release (`el8`, `el9`, `el10`). On every
release the services run `/usr/libexec/drlb/drlb_platform_check`
before the server starts. On RHEL 8 it checks that NetworkManager and
firewalld are running and that the legacy `network` service is not
enabled. Set `DRLB_SKIP_PLATFORM_CHECK=yes` in the service's
`/etc/sysconfig` file to skip the check.

DRLB uses IPv4 for the listening socket and the back end connections.

## Conventions

- Commands that start with `$` are run from a user account.
- Commands that start with `#` are run as root.
- `...` in a config example means settings left out for brevity.

## Installing from RPM

Build each RPM on the RHEL version it is for, or in a matching UBI
container, so the binary links with the right system libraries. The
build needs these packages:

```
# dnf -y install gcc-c++ make rpm-build openssl-devel
```

Build the RPM from the top of the source tree. The argument is the
target release:

```
$ cd rpm
$ ./make_rpm_package.sh rhel10      # or rhel9, rhel8
```

The RPM is copied to `~/rpmbuild/RPMS/x86_64`. Install it:

| Release | Command |
|---|---|
| RHEL 10 | `sudo dnf -y install ~/rpmbuild/RPMS/x86_64/drlb_server-2.0-1.el10.x86_64.rpm` |
| RHEL 9 | `sudo dnf -y install ~/rpmbuild/RPMS/x86_64/drlb_server-2.0-1.el9.x86_64.rpm` |
| RHEL 8 | `sudo dnf -y install ~/rpmbuild/RPMS/x86_64/drlb_server-2.0-1.el8.x86_64.rpm` |

`make_rpm_package.sh` takes an optional second argument, the scratch
build directory (default `/tmp/drlb_build_<user>`).

The RPM installs:

| Path | Contents |
|---|---|
| `/usr/sbin/drlb_server` | The server |
| `/usr/sbin/drlb_ssl_server` | Link to `drlb_server` |
| `/usr/lib/systemd/system/drlb_server.service` | All configs in the active configs list |
| `/usr/lib/systemd/system/drlb_server@.service` | One config per service |
| `/usr/lib/systemd/system/drlb_ssl_server.service` | The SSL bridge |
| `/usr/libexec/drlb/` | `drlb_server_ctl` and `drlb_platform_check` |
| `/etc/sysconfig/drlb_server`, `/etc/sysconfig/drlb_ssl_server` | Service settings |
| `/etc/drlb/active_configs.list` | Configs started by `drlb_server.service` |
| `/etc/drlb/http_rr_test.cfg` | Example round robin config |
| `/etc/drlb/ssl_bridge.cfg` | SSL bridge config |
| `/etc/drlb/ssl/private`, `/etc/drlb/ssl/certs` | Key and certificate directories |
| `/var/log/drlb` | Log and stats files, owned by `drlb` |
| `/usr/share/doc/drlb/` | This guide, README, release notes, `example_config.cfg` |
| `/usr/share/man/man8/` | `drlb_server(8)` and `drlb_ssl_server(8)` |

The RPM creates the `drlb` system user and group. On a new install the
services are not enabled.

Useful RPM commands:

```
$ rpm -qf /usr/sbin/drlb_server    # package that owns the file
$ rpm -ql drlb_server              # files
$ rpm -qc drlb_server              # config files
$ rpm -qd drlb_server              # docs
$ sudo dnf -y remove drlb_server   # remove the package
```

## Building from source

The build needs a C++17 compiler, `make` and the OpenSSL headers:

```
# dnf -y install gcc-c++ make openssl-devel
$ make
$ ./drlb_server --version
```

| Target | Result |
|---|---|
| `make` | `drlb_server`, built with `-std=c++17 -O2 -g -Wall -Wextra` |
| `make asan` | `drlb_server_asan`, built with AddressSanitizer and UBSan, for testing |
| `make test` | Runs the regression tests, see [Testing](#testing) |
| `make install` | Installs `drlb_server` and the `drlb_ssl_server` link into `$(DESTDIR)$(PREFIX)/sbin` (default `/usr/sbin`) |
| `make clean` | Removes the build files |

GCC 8 on RHEL 8 keeps `std::filesystem` in a separate library. The
Makefile adds `-lstdc++fs` when it finds GCC 8.

CMake also works, for IDEs and out of tree builds:

```
$ cmake -S . -B build-cmake && cmake --build build-cmake
```

`make install` installs only the program. The systemd units, the
sysconfig files, the `drlb` user and the `/etc/drlb` and
`/var/log/drlb` directories come with the RPM. Use the RPM on servers.

## Upgrading from 1.60 and 1.61

The 1.60 and 1.61 releases of **load-balancer** (`drlb_server`) and
**ssl-bridge** (`drlb_ssl_server`) were the last ones built on the
DataReel library. Their sources and history, and the LDM-load-balancer
1.65 (`drlb_ldm_server`), are kept in the `legacy_drlb` repository.
2.0 replaces load-balancer and ssl-bridge. It does not replace
LDM-load-balancer.

To upgrade, install the 2.0 RPM with `dnf install` (or `dnf upgrade`):

- The `drlb_server` 2.0 RPM obsoletes `drlb_ssl_server` < 2.0, so one
  install replaces both old RPMs.
- Config files are unchanged. Your files in `/etc/drlb` and
  `/etc/sysconfig` are kept. 1.60/1.61 `drlb_server` configs run as
  plain TCP load balancers, and `ssl_bridge.cfg` (it has an
  `[SSLCONFIG]` section) runs as the SSL bridge.
- `drlb_ssl_server` is now a link to `drlb_server`.
- The services (`drlb_server`, `drlb_server@<name>`,
  `drlb_ssl_server`), the sysconfig files, the `drlb` user and the
  sandboxing are the same. If `drlb_ssl_server.service` was enabled or
  running, it is still enabled and running after the upgrade.
- The docs moved from `/usr/share/doc/drlb_ssl_bridge` to
  `/usr/share/doc/drlb`.

Behavior changes (details in
[RELEASE_NOTES_2.0.txt](../RELEASE_NOTES_2.0.txt)):

- `drlb_ssl_server` with a config that has no `[SSLCONFIG]` section
  stops with an error. 1.60 added a default section to the file.
- `--check-config` on an SSL config also loads the key, certificate
  and CA files and checks the TLS settings.
- Setting names must match exactly. Unknown settings print a warning.
  Lines longer than 1023 characters are no longer split.
- `listen_ip_addr` must be an IPv4 address. Port numbers must be
  1-65535.
- Shutdown ends as soon as open connections close.
- If a client thread cannot be created, only that connection is
  closed. The server keeps running.
- Log messages are time stamped when they are logged and are not cut
  at 254 characters. When a log queue is full the oldest message is
  dropped and the number dropped is logged.
- `LB_DISTRIB` limits now go down again after a busy period (1.60 bug
  fix).
- `LB_ASSIGNED` rules are compiled once at startup, and the client's
  reverse DNS name is looked up once per connection.
- `ssl_cert_file` may hold the certificate followed by its chain.
- Back end connect errors are logged with the system error text.

## Quick start

Write a default config file. When the file named with `--config-file`
does not exist, the server writes a commented default config and
exits:

```
$ ./drlb_server --check-config --config-file=/tmp/lb_test.cfg
```

The default config listens on port 8080 (so it can run without root)
and has four example `[LBNODE]` sections for Apache servers on port 80.
Edit the node addresses, then check the file:

```
$ ./drlb_server --check-config --config-file=/tmp/lb_test.cfg
```

Run it in the foreground with console messages, debug messages and a
log file:

```
$ ./drlb_server --verbose --debug --config-file=/tmp/lb_test.cfg --log-file=/tmp/lb_test.log
```

Stop it with Ctrl-C. More examples are in the `etc` directory of the
source tree. `etc/example_config.cfg` and `etc/ssl_bridge.cfg` show
every setting.

On a server with the RPM, keep configs in `/etc/drlb`:

```
# drlb_server --check-config --config-file=/etc/drlb/http_lb.cfg
# vi /etc/drlb/http_lb.cfg
# drlb_server --check-config --config-file=/etc/drlb/http_lb.cfg | grep -i -E 'error|warn|fail|info|notice'
```

Always check a config file after editing it, before you start or
restart the server.

## TCP mode and SSL mode

The config file decides the mode:

| Config file | Mode |
|---|---|
| No `[SSLCONFIG]` section | Plain TCP load balancer. Data is relayed unchanged (except for HTTP forwarding, if enabled). |
| `[SSLCONFIG]` section | SSL bridge. TLS is terminated on the front end. Back end connections are plain TCP, or TLS with `ssl_encrypt_backend = 1`. |

Only one `[SSLCONFIG]` section is allowed. Both modes use the same
`[LBSERVER]` and `[LBNODE]` settings and all four schemes.

The program name matters only in one case: when started as
`drlb_ssl_server` (the link), the config must have an `[SSLCONFIG]`
section. Without one the server stops with an error, so an SSL service
never falls back to plain TCP by mistake. `drlb_server` runs either
kind of config.

In SSL mode, a client connection is handled in this order: throttling,
front end TLS handshake, node selection and back end connect (and back
end TLS handshake), then the relay. A client that does not finish the
handshake within `ssl_handshake_timeout_secs` is dropped before a node
is chosen.

## Running as a service

There are three systemd services. All run as the `drlb` user with the
same sandboxing, and all read their settings from a file in
`/etc/sysconfig`.

| Service | Runs | Settings file |
|---|---|---|
| `drlb_server.service` | Every config listed in `/etc/drlb/active_configs.list`, or `SINGLECONFIG` | `/etc/sysconfig/drlb_server` |
| `drlb_server@<name>.service` | `/etc/drlb/<name>.cfg`, restarted on failure | `/etc/sysconfig/drlb_server` |
| `drlb_ssl_server.service` | `drlb_ssl_server --config-file=$CFGFILE $ARGS`, default `/etc/drlb/ssl_bridge.cfg`, restarted on failure | `/etc/sysconfig/drlb_ssl_server` |

### drlb_server.service

DRLB can run several load balancer configs on one server. This service
starts each config listed in the active configs list:

```
# vi /etc/drlb/active_configs.list

# List of active DRLB configurations
/etc/drlb/http_rr_test.cfg
/etc/drlb/smtp_lb.cfg
# All entries must use an absolute path to the .cfg file.
```

`/etc/sysconfig/drlb_server` overrides the defaults:

| Setting | Default | Meaning |
|---|---|---|
| `LBPROC` | `/usr/sbin/drlb_server` | Server binary |
| `ACTIVE_CONFIGS` | `/etc/drlb/active_configs.list` | Active configs list |
| `SINGLECONFIG` | not set | Run only this config and ignore the list |
| `STOP_TIMEOUT` | `15` | Seconds to wait for each server to stop before it is killed |
| `DRLB_SKIP_PLATFORM_CHECK` | `no` | `yes` skips the RHEL 8 NetworkManager and firewalld check |

Start the service and make it persistent:

```
# systemctl start drlb_server
# systemctl status drlb_server
# systemctl enable drlb_server
```

`systemctl reload drlb_server` stops and starts every config. To see
which configs are running:

```
# /usr/libexec/drlb/drlb_server_ctl status
```

The service starts the servers with `drlb_server_ctl`, which sends
their console output to `/dev/null`. Use a log file (see
[Logging](#logging)) for these configs. Do not run `drlb_server_ctl
start` or `restart` by hand: the server would then run as root,
outside the service sandbox.

### drlb_server@.service

Each config can run as its own service. The instance name is the
config file name in `/etc/drlb` without `.cfg`. A config run this way
is restarted on failure, and can be restarted without stopping the
others. Do not also list it in `/etc/drlb/active_configs.list`.

```
# systemctl enable --now drlb_server@http_rr_test     # /etc/drlb/http_rr_test.cfg
# systemctl status drlb_server@http_rr_test
# systemctl restart drlb_server@http_rr_test
```

### drlb_ssl_server.service

The SSL bridge service runs `drlb_ssl_server`, so its config must have
an `[SSLCONFIG]` section. `/etc/sysconfig/drlb_ssl_server` sets:

| Setting | Default | Meaning |
|---|---|---|
| `CFGFILE` | `/etc/drlb/ssl_bridge.cfg` | Config file |
| `ARGS` | empty | Extra command line options, for example `--verbose` |
| `DRLB_SKIP_PLATFORM_CHECK` | `no` | `yes` skips the RHEL 8 check |

Install a key and certificate first (see
[TLS certificates and settings](#tls-certificates-and-settings)), then:

```
# drlb_ssl_server --check-config --config-file=/etc/drlb/ssl_bridge.cfg
# systemctl enable --now drlb_ssl_server
# systemctl status drlb_ssl_server
# tail -f /var/log/drlb/ssl_bridge.log
# tail -n 25 -f /var/log/drlb/ssl_bridge_stats.log
```

`ssl_bridge.cfg` listens on port 443, uses round robin, and enables
logging, stats and HTTP forwarding.

### Messages and config changes

Startup errors go to the systemd journal. For `drlb_server@` and
`drlb_ssl_server`, add `--verbose` to see every console message there.

```
# journalctl -u drlb_server
# journalctl -u drlb_server@http_rr_test
# journalctl -u drlb_ssl_server
```

The config file and the rules file are read only at startup. After a
change, check the config and restart the service that runs it:

```
# systemctl reload drlb_server              # all configs in the active list
# systemctl restart drlb_server@http_rr_test
# systemctl restart drlb_ssl_server
```

## Service security

The services run as the `drlb` system user, created by the RPM.
systemd gives the server only the `CAP_NET_BIND_SERVICE` capability, so
it can listen on ports below 1024. The unit files also set
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
`NoNewPrivileges`, `MemoryDenyWriteExecute`, address family and
namespace restrictions, and `UMask=0027`.

This has these effects:

- The server can only write in `/var/log/drlb`. Log and stats files
  must be there.
- `/etc/drlb` is read only for the server. A missing config file or
  rules file cannot be created by the service. Create them with
  `--check-config` as root first.
- Config files, rules files and certificates must be readable by the
  `drlb` user.
- `/home` and `/tmp` of the host are not visible.

Keep private keys readable by the `drlb` group only:

```
# chgrp drlb /etc/drlb/ssl/private/server.key
# chmod 640 /etc/drlb/ssl/private/server.key
```

`/etc/drlb/ssl/private` itself is mode 0750, owner root, group drlb.

To change a unit setting, use a drop-in file so RPM updates keep it:

```
# systemctl edit drlb_server@http_rr_test
```

Assigned rules are regular expressions and are not anchored, see
[LB_ASSIGNED](#lb_assigned-assigned).

## Firewall settings

DRLB uses firewalld. iptables service rules are not supported. Open
the front end port set in the `[LBSERVER]` section of each config, for
example port 8080:

```
# firewall-cmd --permanent --add-port=8080/tcp
# firewall-cmd --reload
# firewall-cmd --list-ports
```

For the SSL bridge on port 443:

```
# firewall-cmd --permanent --add-service=https
# firewall-cmd --reload
```

To allow only some client networks, use a rich rule instead of the
open port:

```
# firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.122.0/24" port port="8080" protocol="tcp" accept'
# firewall-cmd --reload
```

On each back end server, open the back end port to the DRLB server
address only.

## Command line options

```
drlb_server --config-file=FILE [OPTIONS...]
drlb_ssl_server --config-file=FILE [OPTIONS...]
```

`--config-file` is required. Options given on the command line
override the same setting in the config file.

| Option | Meaning |
|---|---|
| `--help`, `-?` | Print the help message and exit |
| `--version` | Print the version and exit |
| `--check-config` | Check the config file and exit. Also loads the TLS key and certificates. Messages go to the console only, never to the log file. |
| `--config-file=FILE` | Config file. If it does not exist, a default one is written and the program exits. |
| `--debug`, `-d` | Enable debug mode, level 1 |
| `--debug-level=N` | Enable debug mode at level N, 1-5 |
| `--verbose`, `-v` | Echo messages to the console |
| `--verbose-level=N` | Set `verbose_level` (see the settings reference) |
| `--log-file=FILE` | Enable logging to FILE. Overrides `enable_logging` and `logfile_name`. |
| `--log-level=N` | Log level, 0-5 |
| `--log-file-clear` | Clear the log file when the program starts |
| `--log-disable` | Disable logging. Overrides `enable_logging`, `logfile_name` and `clear_log`. |
| `--stats-file=FILE` | Enable stats and write them to FILE |
| `--stats-disable` | Disable stats |

Values may be quoted: `--config-file="/etc/drlb/http_lb.cfg"`. An
unknown option is an error.

Exit status:

| Status | Meaning |
|---|---|
| 0 | Normal stop, or `--check-config` found no errors |
| 1 | Config, startup or command line error; also `--help` and `--version` |
| 2 | The config file did not exist and a default one was written (without `--check-config`) |

## Signals

| Signal | Action |
|---|---|
| `SIGTERM`, `SIGINT` | Stop accepting connections, let open connections finish (up to `write_timeout_secs` + 5 seconds), flush the logs and exit 0 |
| `SIGUSR2` | Enable debug mode, or raise the debug level by one (max 5) |
| `SIGUSR1` | Lower the debug level by one. At 0, debug mode is turned off. |
| `SIGHUP`, `SIGQUIT`, `SIGTSTP` | Logged only. `SIGHUP` does not reload the config. |

For example, to turn on debug messages for a running server:

```
# pkill -USR2 -f 'drlb_server --config-file=/etc/drlb/http_rr_test.cfg'
```

## Config file format

A config file has one `[LBSERVER]` section, one or more `[LBNODE]`
sections (one per back end node) and, for SSL mode, one `[SSLCONFIG]`
section. The sections can be in any order.

- Settings are `name = value`, one per line.
- Lines that start with `#` or `;` are comments. Text after `#` on a
  line is a comment, so a value cannot contain `#`.
- Section and setting names are not case sensitive. Setting names must
  match exactly.
- True/false settings take `1`, `TRUE`, `T`, `YES` or `Y` for true and
  `0`, `FALSE`, `F`, `NO` or `N` for false. Any number 1 or more is
  true.
- Number settings use the leading digits of the value, so `5M` is 5.
- An unknown setting prints a warning and is ignored. A line without
  `=` prints a warning and is ignored. Sections other than the three
  above are ignored.
- A bad value for a checked setting (see the tables below) is an error,
  and the server does not start.

## Settings reference

Defaults are the values used when the setting is not in the file. The
default config written by the program sets most of them explicitly.

### [LBSERVER]: server and scheme

| Setting | Default | Meaning |
|---|---|---|
| `port` | `8080` | Front end listening port, 1-65535 |
| `listen_ip_addr` | all addresses | Listen on this IPv4 address only. `0.0.0.0` (or `::0`) means all addresses. Anything else that is not an IPv4 address is an error. |
| `scheme` | `LB_RR` | `LB_RR`, `LB_WEIGHTED`, `LB_DISTRIB` or `LB_ASSIGNED`. Only one `scheme` line is allowed. |
| `rules_config_file` | not set | Rules file, required for `LB_ASSIGNED` |
| `assigned_default` | `LB_RR` | `LB_ASSIGNED` fail over: `LB_RR`, `LB_DISTRIB`, `LB_WEIGHTED` or `LB_NONE` |
| `resolve_assigned_hostnames` | `1` | `LB_ASSIGNED`: also match rules against the client's reverse DNS name |
| `service_name` | `drlb_server` | Name used in log and stats lines |
| `somaxconn` | `128` | Listen backlog, more than 0. The kernel caps it at `net.core.somaxconn`. |

### [LBSERVER]: connections, buffers and retries

| Setting | Default | Meaning |
|---|---|---|
| `max_connections` | `-1` | Front end connection limit. 1 or less means no limit. |
| `max_threads` | `-1` | Thread limit for the process. 1 or less means no limit. |
| `use_buffer_cache` | `1` | Read all data that is ready (up to `max_cache_size`) before writing it to the other side |
| `buffer_size` | `65536` | Bytes per socket read, more than 0. Default for `[LBNODE] buffer_size`. |
| `max_cache_size` | `1048576` | Max bytes read from one side before they are written to the other side, more than 0 |
| `enable_buffer_overflow_detection` | `0` | Close a client that sends `buffer_overflow_size` bytes or more at once |
| `buffer_overflow_size` | `6400000` | Overflow size in bytes, more than 0 |
| `retries` | `3` | Extra passes over the nodes when every node failed, 0 or more |
| `retry_wait` | `1` | Seconds between passes, 0 or more |
| `dead_node_secs` | `1` | Seconds a node that failed to connect is skipped, 0 or more. 0 tries every node every time. |

### [LBSERVER]: timeouts

| Setting | Default | Meaning |
|---|---|---|
| `use_timeout` | `1` | Close idle connections |
| `timeout_secs` | `300` | Idle time in seconds (no data in either direction), 0 or more |
| `timeout_usecs` | `0` | Microseconds added to `timeout_secs`, 0 or more |
| `write_timeout_secs` | `60` | Seconds to wait for a slow peer to accept data, more than 0 |
| `connect_timeout_secs` | `5` | Seconds to wait for a back end connect, more than 0 |

### [LBSERVER]: logging, stats, debug

| Setting | Default | Meaning |
|---|---|---|
| `enable_logging` | `0` | Write a log file. Needs `logfile_name`. |
| `logfile_name` | not set | Log file path |
| `log_level` | `0` | 0 (fewest messages) to 5 (most) |
| `clear_log` | `0` | Empty the log file at startup |
| `max_log_size` | `5000000` | Rotate the log at this size in bytes, 1 to 2000000000 |
| `num_logs_to_keep` | `3` | Rotated log files to keep, more than 0 |
| `log_queue_size` | `2048` | Max queued log and console messages, more than 0 |
| `log_queue_debug_size` | `4096` | Max queued debug messages, more than 0 |
| `log_queue_proc_size` | `255` | Max queued process messages (start, stop, signals), more than 0 |
| `enable_stats` | `0` | Write a stats report every `stats_min`/`stats_secs` |
| `stats_file_name` | `drlb_stats.log` | Stats file. The default is relative to the current directory; set a full path in `/var/log/drlb`. |
| `stats_min` | `5` | Minutes between reports, 0 or more |
| `stats_secs` | `0` | Seconds added to `stats_min`, 0 or more. A total of 0 means 5 minutes. |
| `max_stats_size` | `5000000` | Rotate the stats file at this size in bytes, 1 to 2000000000 |
| `num_stats_to_keep` | `3` | Rotated stats files to keep, more than 0 |
| `debug` | `0` | Debug mode, used for development and testing |
| `debug_level` | `1` | Debug level, 1-5. Level 5 greatly increases the log size. |
| `verbose` | `0` | Echo messages to the console |
| `verbose_level` | `1` | Accepted and shown by `--check-config`, but not used. As in 1.60, `verbose` alone controls console output. |

### [LBSERVER]: throttling and HTTP forwarding

| Setting | Default | Meaning |
|---|---|---|
| `enable_throttling` | `0` | Hold some connections in a wait queue |
| `throttle_every_connections` | `10` | Hold every Nth connection, more than 0. 1 holds every connection. |
| `throttle_wait_secs` | `1` | Seconds to hold a connection, 0 or more |
| `throttle_wait_usecs` | `0` | Microseconds to hold a connection, 0 or more |
| `throttle_apply_by_load` | `0` | Throttle only while the load is at or over `throttle_connections_per_sec` |
| `throttle_connections_per_sec` | `10` | Load that starts throttling, more than 0 |
| `enable_http_forwarding` | `0` | Add an `X-Forwarded-For` header to HTTP requests |
| `http_request_strings` | `DELETE,GET,HEAD,PATCH,POST,PUT` | Request methods to rewrite, comma separated |
| `http_forward_for_str` | `X-Forwarded-For` | Header name to add |
| `http_hdr_str` | `HTTP/` | Accepted and shown by `--check-config`, but not used (also not used by 1.60) |

`debug`, `debug_level`, `verbose`, `verbose_level`, `log_level`,
`enable_logging`, `logfile_name`, `clear_log`, `enable_stats` and
`stats_file_name` can be overridden on the command line.

### [LBNODE]

One section per back end node.

| Setting | Default | Meaning |
|---|---|---|
| `node_name` | `LBnode` | Node name used in logs, stats and assigned rules. Give each node a unique name. |
| `hostname` | `localhost` | Back end host name or IPv4 address |
| `port_number` | `8080` | Back end port, 1-65535 |
| `weight` | `-1` (not set) | `LB_WEIGHTED`: weight. `LB_DISTRIB`: percent of the load (a `%` sign is allowed). Required for those schemes, and for `LB_ASSIGNED` with `assigned_default` `LB_WEIGHTED` or `LB_DISTRIB`. Ignored by `LB_RR`. |
| `max_connections` | `-1` | Connection limit for this node. 1 or less means no limit. |
| `buffer_size` | `[LBSERVER] buffer_size` | Bytes per socket read for this node. 0 or less uses the server value. Set `[LBSERVER] buffer_size` before the `[LBNODE]` sections for it to be the node default. |

### [SSLCONFIG]

The section turns on SSL mode. All settings are optional.

| Setting | Default | Meaning |
|---|---|---|
| `ssl_protocol` | `TLS` | `TLS` (TLS 1.2 and 1.3), `TLSv1_2` (1.2 only) or `TLSv1_3` (1.3 only). Anything else is an error. |
| `ssl_key_file` | `/etc/drlb/ssl/private/ca.key` | Private key, PEM |
| `ssl_cert_file` | `/etc/drlb/ssl/certs/ca.crt` | Certificate, PEM, optionally followed by its chain |
| `ssh_ca_list_file` | not set | CA certificates (PEM) used to build the chain sent to clients. The `ssh_` name is kept from 1.60. |
| `ssl_use_dhparms` | `0` | Load Diffie-Hellman parameters from `ssl_dhparms_file` |
| `ssl_dhparms_file` | `/etc/drlb/ssl/certs/dhparams.pem` | DH parameters, PEM |
| `ssl_cipher_list` | system policy | TLS 1.2 cipher list (OpenSSL format) |
| `ssl_ciphersuites` | system policy | TLS 1.3 cipher suites |
| `ssl_handshake_timeout_secs` | `30` | Seconds allowed for a TLS handshake, more than 0 |
| `ssl_encrypt_backend` | `0` | Use TLS to connect to the back end nodes |
| `ssl_verify_backend_cert` | `1` | Verify back end certificates |
| `ssl_backend_hostname` | node `hostname` | Name sent as SNI and checked against back end certificates |
| `ssl_backend_ca_list_file` | `/etc/pki/tls/certs/ca-bundle.crt` | CAs trusted for back end certificates. Empty uses the OpenSSL default paths. |

## Listening port and nodes

The server listens on the `[LBSERVER]` `port` and relays connections to
the `port_number` of each `[LBNODE]`. You can have any number of
`[LBNODE]` sections. For example, with four Apache servers:

```
[LBSERVER]
port = 8080 # All incoming traffic connections here
...

[LBNODE]
node_name = lbnode1
hostname = 192.168.122.111
port_number = 80 # Port the back end host is listening on

[LBNODE]
node_name = lbnode2
hostname = 192.168.122.112
port_number = 80
...
```

Replace the ports and addresses with the ones you use. A port below
1024 needs root when you run the server from a shell. The services
can use any port. You still need to apply your own security settings
on each back end node.

## Load balancing schemes

### LB_RR (round robin)

Connections go to the nodes in turn. Use it when the back end servers
have the same or similar hardware (or the same CPU, memory and disk
for virtual machines).

```
[LBSERVER]
scheme = LB_RR

[LBNODE]
node_name = lbnode1
port_number = 80
hostname = 192.168.122.111

[LBNODE]
node_name = lbnode2
port_number = 80
hostname = 192.168.122.112
...
```

Each new connection starts at the next node. If that node cannot be
reached, the next one is tried, until every node was tried once. Nodes
that recently refused a connection are skipped, see
[Dead node retry](#dead-node-retry).

### LB_WEIGHTED (weighted)

Use it when some back end servers can handle less load than others.
The weight is a number of connections per node. Nodes with a higher
weight get more connections.

```
[LBSERVER]
scheme = LB_WEIGHTED

[LBNODE]
node_name = lbnode1
port_number = 80
hostname = 192.168.122.111
weight = 1

[LBNODE]
node_name = lbnode2
port_number = 80
hostname = 192.168.122.112
weight = 1

[LBNODE]
node_name = lbnode3
port_number = 80
hostname = 192.168.122.113
weight = 2

[LBNODE]
node_name = lbnode4
port_number = 80
hostname = 192.168.122.114
weight = 3
```

Here lbnode4 carries three times as many connections as lbnode1 and
lbnode2, and lbnode3 twice as many.

How it works: the nodes are ordered by weight, highest first. Each node
has a limit of weight x scale open connections, starting with scale 1.
A new connection goes to the first node below its limit. When the open
connections reach the sum of the limits the scale goes up by one, and
when they drop again it goes down. The weights therefore apply to
concurrent connections: at low load the node with the highest weight
takes most connections. If no node is below its limit, or the chosen
node cannot be reached, round robin over the ordered nodes is used.

### LB_DISTRIB (distributed)

Like weighted, but each node gets a percent of the load. The percents
should add up to 100; `--check-config` warns if they do not.

```
[LBSERVER]
scheme = LB_DISTRIB

[LBNODE]
node_name = lbnode1
port_number = 80
hostname = 192.168.122.111
weight = 15%

[LBNODE]
node_name = lbnode2
port_number = 80
hostname = 192.168.122.112
weight = 15%

[LBNODE]
node_name = lbnode3
port_number = 80
hostname = 192.168.122.113
weight = 30%

[LBNODE]
node_name = lbnode4
port_number = 80
hostname = 192.168.122.114
weight = 40%
```

Here lbnode4 carries 40% of the connections, lbnode3 30%, and lbnode1
and lbnode2 15% each.

How it works: each node's limit is its percent of the current number
of open connections (at least 1). The limits are rebuilt when the open
connections reach the sum of the limits or drop below the previous
level. A new connection goes to the first node, highest percent first,
that is below its limit. Otherwise round robin over the nodes is used.

### LB_ASSIGNED (assigned)

Routes clients to set nodes by their IP address or host name.
Connections without a matching rule, and connections whose assigned
node is down or full, use the `assigned_default` scheme.

| `assigned_default` | Unmatched clients and fail over |
|---|---|
| `LB_RR` (default) | Round robin |
| `LB_WEIGHTED` | Weighted. Every `[LBNODE]` needs a `weight`. |
| `LB_DISTRIB` | Distributed. Every `[LBNODE]` needs a percent `weight`. |
| `LB_NONE` | No fail over. The connection is closed, both for clients with no matching rule and when the assigned node cannot be used. |

```
[LBSERVER]
scheme = LB_ASSIGNED
rules_config_file = /etc/drlb/http_lb_rules.cfg
assigned_default = LB_RR

[LBNODE]
node_name = lbnode1
port_number = 80
hostname = 192.168.122.111
...
```

The rules file has one rule per line:

```
route <client> <node_name>
```

`<client>` is an IP address or host name, written as a POSIX extended
regular expression. `<node_name>` must match a `node_name` in the
config exactly. Quotes around `<client>` are removed. Comment lines
start with `#` or `;`. A rule line without exactly three fields, or
with a bad regular expression, is an error.

```
# vi /etc/drlb/http_lb_rules.cfg

route ^192\.168\.122\.1$ lbnode1
route ^10\. lbnode2
route ^172\.31\.1\. lbnode3
route \.example\.com$ lbnode4
```

The first rule sends 192.168.122.1 to lbnode1. The second sends the
10.0.0.0/8 network to lbnode2, the third 172.31.1.0/24 to lbnode3, and
the fourth clients whose host name ends in `.example.com` to lbnode4.
All other clients use round robin over all four nodes.

Rules are checked in file order, and the first match wins. Rules are
not anchored: `192.168.1.1` also matches `192.168.1.10` and
`10.192.168.1`, and `.` matches any character. Use `^`, `$` and `\.`
to match exactly.

With `resolve_assigned_hostnames = 1` (the default), a rule that does
not match the client IP address is also matched, without case, against
the client's reverse DNS name. The name is used only when it resolves
back to the client address, and it is looked up once per connection.
DNS lookups slow down new connections. Set
`resolve_assigned_hostnames = 0` to match IP addresses only.

If the rules file does not exist, `--check-config` writes a commented
template and continues with no rules. The rules file is read once at
startup; changes need a restart.

## Dead node retry

These `[LBSERVER]` settings control what happens when a back end node
is down for maintenance or has failed:

```
[LBSERVER]
...
retries = 3
retry_wait = 1
dead_node_secs = 1
connect_timeout_secs = 5
```

- A connect to a node that takes longer than `connect_timeout_secs` (or
  is refused) fails, and the next node is tried.
- A node that failed is skipped for `dead_node_secs` seconds, and its
  share of new connections goes to the other nodes. If all nodes are
  marked down, all are tried. `dead_node_secs = 0` tries every node on
  every connection.
- When every node failed, the server waits `retry_wait` seconds and
  tries all nodes again, up to `retries` more times. Then the client
  connection is closed and an error is logged.

This applies to round robin, and to the round robin fall back of the
weighted, distributed and assigned schemes. An assigned node is tried
once before the `assigned_default` scheme is used.

## Connection and thread limits

Limits protect servers with few resources. When a limit is reached,
new connections are closed and a message is logged, until the number
of connections drops.

| Setting | Section | Counts |
|---|---|---|
| `max_connections` | `[LBSERVER]` | Open client connections. A new connection is refused when it would make `max_connections` open connections, so at most `max_connections` - 1 are served. |
| `max_connections` | `[LBNODE]` | Open connections to this node. The node is skipped when it has `max_connections` open connections. |
| `max_threads` | `[LBSERVER]` | Threads in the process: one per client connection plus 4 server threads (5 with stats). |

A value of 1 or less means no limit. The server and thread limits are
checked when a connection is accepted. The node limit is checked when
a node is chosen; a full node is skipped like a down node.

```
[LBSERVER]
...
max_connections = 1000

[LBNODE]
node_name = lbnode1
max_connections = 1000
...

[LBNODE]
node_name = lbnode2
max_connections = 200
...
```

Each client connection uses one thread and two file descriptors.
Thread limits help when there are many persistent client connections.
See also [Open file limits](#open-file-limits).

## Buffers and caching

```
[LBSERVER]
...
use_buffer_cache = 1
buffer_size = 65536
max_cache_size = 1048576
```

- `buffer_size` is the number of bytes read from a socket at a time.
  Smaller buffers mean more reads per connection, larger buffers fewer.
  Each connection has one buffer. It can be set per node with
  `[LBNODE] buffer_size`.
- With `use_buffer_cache = 1`, the server reads all the data that is
  ready on one side, up to `max_cache_size` bytes, and then writes it
  to the other side. With `use_buffer_cache = 0` each read is written
  right away.

The relay waits on both sides of each connection with `poll()`, so
idle connections use no CPU time.

### Buffer overflow detection

If you know the largest amount of data your application's clients
send at once, you can close clients that send more:

```
[LBSERVER]
...
enable_buffer_overflow_detection = 1
buffer_overflow_size = 5000
```

A client connection is closed when the data read from the client in
one burst (before it is written to the back end) reaches
`buffer_overflow_size` bytes. With `use_buffer_cache = 1` a burst is
all the data ready at once, up to `max_cache_size`. With
`use_buffer_cache = 0` a burst is one read of at most `buffer_size`
bytes, so the size must be smaller than `buffer_size` to have an
effect. Only data from clients is checked.

## Timeouts

| Setting | Default | Applies to |
|---|---|---|
| `use_timeout`, `timeout_secs`, `timeout_usecs` | on, 300 s | A connection with no data in either direction for this time is closed. Set a longer time for services with long quiet periods, or `use_timeout = 0` to keep idle connections open. |
| `write_timeout_secs` | 60 s | A peer that does not accept data for this time is disconnected. Also sets how long shutdown waits for open connections (plus 5 seconds). |
| `connect_timeout_secs` | 5 s | Back end connect |
| `ssl_handshake_timeout_secs` | 30 s | Front end and back end TLS handshakes |

`timeout_usecs` is used with millisecond precision.

## Throttling

Throttling protects back end servers during load peaks by holding some
new connections in a wait queue before a node is chosen.

Throttle by connection count:

```
[LBSERVER]
...
enable_throttling = 1
throttle_every_connections = 10
throttle_wait_secs = 1
throttle_wait_usecs = 0
```

Every 10th connection is held for 1 second. With
`throttle_every_connections = 1` every connection is held.

Throttle only under load:

```
[LBSERVER]
...
enable_throttling = 1
throttle_apply_by_load = 1
throttle_connections_per_sec = 10
throttle_every_connections = 10
throttle_wait_secs = 1
throttle_wait_usecs = 0
```

Every 10th connection is held while the load is 10 connections per
second or more. The load is measured by the stats thread, as the
average over each stats interval (`stats_min` and `stats_secs`, 5
minutes by default). Set a shorter interval to react faster:

```
stats_min = 0
stats_secs = 30
```

If stats are disabled, `throttle_apply_by_load` turns on stats
collection without a stats file.

## HTTP X-Forwarded-For forwarding

Back end servers see the DRLB server as the client. For HTTP, DRLB
can add the client address to each request:

```
[LBSERVER]
...
enable_http_forwarding = 1
http_request_strings = DELETE,GET,HEAD,PATCH,POST,PUT
http_forward_for_str = X-Forwarded-For
```

- One `X-Forwarded-For: <client IP>` header is added to every request
  on a connection, including keep alive requests. Request bodies with
  `Content-Length` or chunked encoding are followed so the next request
  is found.
- Any `X-Forwarded-For` header (the `http_forward_for_str` name) sent by
  the client is removed first, so back end servers can trust the
  header.
- Only requests that start with a method in `http_request_strings` are
  rewritten. If the first request on a connection does not, the rest of
  the connection is passed through unchanged. WebSocket (`Upgrade`) and
  `CONNECT` tunnels are passed through after their first request.
- Responses are never changed.

In TCP mode this works only for plain HTTP. For HTTPS, use SSL mode, so
the requests are decrypted before they are rewritten.

To log forwarded addresses in Apache, add `%{X-Forwarded-For}i` to the
log format in your httpd config:

```
LogFormat "%h %l %u %t \"%r\" %>s %b %{X-Forwarded-For}i \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %b %{X-Forwarded-For}i" common
```

## Logging

Logging is off by default. For the best performance under extreme
load, leave it off or use log level 0.

```
[LBSERVER]
...
enable_logging = 1
logfile_name = /var/log/drlb/http_lb.log
log_level = 1
num_logs_to_keep = 3
max_log_size = 5000000
clear_log = 0
service_name = http_lb
```

Log lines look like this (local time, then `service_name`):

```
Oct 31 14:30:00 http_lb: [52144]: Frontend client connect: 192.168.122.1
```

The number in brackets is the client's source port, used to follow one
connection through the log.

| `log_level` | Adds |
|---|---|
| 0 | Startup, shutdown and signal messages; all nodes failed; limits reached |
| 1 | Each client connect; back end connect errors |
| 2 | Each back end connect |
| 3 | TLS handshake errors, socket read and write errors, buffer overflows |
| 4 | Idle timeouts |
| 5 | Same as 4 |

Debug mode (`--debug`, `debug = 1`, or `SIGUSR2` at run time) adds
debug messages to the log and console. Most per connection detail is
at debug level 5, which greatly increases the log size. `--verbose`
echoes log messages to the console.

### Log queues

Client threads queue their log messages, and a log thread writes them,
so a slow disk does not hold up connections. There are three queues:

| Setting | Default | Queue |
|---|---|---|
| `log_queue_size` | 2048 | Log and console messages |
| `log_queue_debug_size` | 4096 | Debug messages |
| `log_queue_proc_size` | 255 | Process messages (start, stop, signals) |

When a queue is full the oldest message is dropped, and a warning with
the number of dropped messages is logged. The queues are written at
least every 200 ms.

### Log rotation

After each write the log file size is checked. When it reaches
`max_log_size` bytes, the file is renamed to `<logfile_name>.1`, `.2`
and so on up to `.<num_logs_to_keep>`, and a new file is started. After
the last number, and after each restart of the server, numbering starts
at `.1` again. Disk space used is at most about:

```
max_log_size * (num_logs_to_keep + 1)
```

The log is also checked for rotation at startup. `clear_log = 1` (or
`--log-file-clear`) empties the log file at startup instead.

To watch the log:

```
# tail -f /var/log/drlb/http_lb.log
```

## Statistics

Stats are off by default:

```
[LBSERVER]
...
enable_stats = 1
stats_file_name = /var/log/drlb/http_lb_stats.log
stats_min = 5
stats_secs = 0
max_stats_size = 5000000
num_stats_to_keep = 3
```

A report is written every `stats_min` minutes plus `stats_secs`
seconds. Each report looks like this:

```
BEGIN http_lb stats
Server start time: Sat, 31 Oct 2026 14:00:00 GMT
Stats report time: Sat, 31 Oct 2026 14:05:00 GMT
Uptime: 0 days. 0 hrs. 5 mins. 0 secs.
Total runtime connections: 1200
Report interval: 0 hrs. 5 mins. 0 secs.
Connections per second: 4
Current connections: 12
Total Runtime Connections to lbnode1: 600
Connections per second to lbnode1: 2
Current Connections to lbnode1: 6
Total Runtime Connections to lbnode2: 600
Connections per second to lbnode2: 2
Current Connections to lbnode2: 6
END http_lb stats
```

| Line | Meaning |
|---|---|
| Total runtime connections | Client connections accepted since start, including refused ones |
| Connections per second | Average over the report interval, whole number. Used by `throttle_apply_by_load`. |
| Current connections | Open back end connections, all nodes |
| Total Runtime Connections to `<node>` | Connections relayed to the node since start |
| Connections per second to `<node>` | Average over the report interval |
| Current Connections to `<node>` | Open connections to the node |

The stats file is rotated like the log file: at `max_stats_size`
bytes, to `.1` up to `.<num_stats_to_keep>`. Disk space used is at most
about `max_stats_size * (num_stats_to_keep + 1)`.

To watch the stats:

```
# tail -n 25 -f /var/log/drlb/http_lb_stats.log
```

## TLS certificates and settings

The `[SSLCONFIG]` section sets up TLS. `etc/ssl_bridge.cfg`
(`/etc/drlb/ssl_bridge.cfg` with the RPM) is a complete example.

```
[SSLCONFIG]
ssl_protocol = TLS
ssl_key_file = /etc/drlb/ssl/private/server.key
ssl_cert_file = /etc/drlb/ssl/certs/server.crt
##ssh_ca_list_file = /etc/drlb/ssl/certs/ca_list.crt
ssl_handshake_timeout_secs = 30
##ssl_cipher_list = ECDHE+AESGCM:ECDHE+CHACHA20
##ssl_ciphersuites = TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256
##ssl_use_dhparms = 0
##ssl_dhparms_file = /etc/drlb/ssl/certs/dhparams.pem
##ssl_encrypt_backend = 0
##ssl_backend_hostname = www.example.com
##ssl_verify_backend_cert = 1
##ssl_backend_ca_list_file = /etc/pki/tls/certs/ca-bundle.crt
```

### Certificates

Before starting the SSL bridge, install your private key and
certificate and point `ssl_key_file` and `ssl_cert_file` at them. Both
are PEM files. The key must match the certificate; `--check-config`
loads both and reports a mismatch.

The certificate chain (intermediate CA certificates) can be given in
two ways:

- Put it in `ssl_cert_file` after the server certificate. This is the
  simplest way. The whole file is sent to clients.
- Put the CA certificates in `ssh_ca_list_file`. OpenSSL then builds
  the chain sent to clients from them. The setting name keeps the
  `ssh_` spelling from 1.60.

Clients do not need certificates; the server does not ask for one.

### Self-signed certificates

For test or internal HTTPS services without a certificate from a
trusted CA, create a self-signed certificate:

```
# mkdir -pv /etc/drlb/ssl/private /etc/drlb/ssl/certs
# openssl genrsa -out /etc/drlb/ssl/private/server.key 2048
# chgrp drlb /etc/drlb/ssl/private/server.key
# chmod 640 /etc/drlb/ssl/private/server.key
# openssl req -new -x509 -days 365 -key /etc/drlb/ssl/private/server.key \
    -out /etc/drlb/ssl/certs/server.crt -subj "/CN=www.example.com" \
    -addext "subjectAltName=DNS:www.example.com"
```

Replace `www.example.com` with the name clients use. Clients check the
subjectAltName, not the Common Name. The server runs as the `drlb`
user, so the key must be readable by the `drlb` group and by no other
users.

Then set the files in the config and check it:

```
[SSLCONFIG]
...
ssl_key_file = /etc/drlb/ssl/private/server.key
ssl_cert_file = /etc/drlb/ssl/certs/server.crt
```

```
# drlb_ssl_server --check-config --config-file=/etc/drlb/ssl_bridge.cfg
```

The RPM's `ssl_bridge.cfg` uses `/etc/drlb/ssl/private/ca.key` and
`/etc/drlb/ssl/certs/ca.crt`, the file names used by 1.60. Use those
names, or change the settings.

### Diffie-Hellman parameters

DH parameters are used only by the TLS 1.2 `DHE` ciphers. With OpenSSL
3 (RHEL 9 and 10) the server uses built in RFC 7919 groups when
`ssl_use_dhparms = 0`, so a DH file is not needed. To use your own
parameters:

```
# openssl dhparam -out /etc/drlb/ssl/certs/dhparams.pem 2048
```

```
[SSLCONFIG]
...
ssl_use_dhparms = 1
ssl_dhparms_file = /etc/drlb/ssl/certs/dhparams.pem
```

### Protocols

| `ssl_protocol` | Versions |
|---|---|
| `TLS` (default) | TLS 1.2 and TLS 1.3 |
| `TLSv1_2` | TLS 1.2 only |
| `TLSv1_3` | TLS 1.3 only |

The value is not case sensitive. SSLv2, SSLv3, TLS 1.0 and TLS 1.1 are
not supported, and the `SSLv23` setting from older versions is a config
error. The setting applies to the front end and the back end. On RHEL
the system crypto policy can raise the minimum further.

### Ciphers

Ciphers follow the system crypto policy, set with
`update-crypto-policies`. Use `ssl_cipher_list` (TLS 1.2, OpenSSL
cipher list format) and `ssl_ciphersuites` (TLS 1.3) only to restrict
them further for this server. A bad value is a config error. The same
settings apply to back end TLS.

### Back end TLS

By default the back end traffic is not encrypted (for example plain
HTTP on port 80). This lets existing back end web servers work without
TLS, while clients still use HTTPS.

With `ssl_encrypt_backend = 1` the server connects to the back end
nodes with TLS. Both the front end and the back end traffic are then
encrypted, and HTTP forwarding still works because the requests are
decrypted in between. Set `port_number` to the back end HTTPS port.

```
[SSLCONFIG]
...
ssl_encrypt_backend = 1
ssl_verify_backend_cert = 1
##ssl_backend_hostname = www.example.com
##ssl_backend_ca_list_file = /etc/pki/tls/certs/ca-bundle.crt
```

With `ssl_verify_backend_cert = 1` (the default), the back end
certificate must:

- be issued by a CA in `ssl_backend_ca_list_file` (the system trust
  store by default), and
- have a subjectAltName that matches `ssl_backend_hostname`, or the
  node `hostname` when `ssl_backend_hostname` is not set. An IP address
  is matched against IP address entries. Partial wildcards are not
  accepted.

The same name is sent as the TLS server name (SNI), unless it is an IP
address. If the check fails the node is treated as down, and the error
is logged. Set `ssl_verify_backend_cert = 0` only for test back ends
with self-signed certificates.

## Tuning

Any change to kernel settings or user limits must be made with care
and tested on development servers first. Wrong limits can make a
server unusable.

### Open file limits

Each client connection uses two file descriptors (client and back end)
and one thread. The default soft limit for open files on RHEL 8, 9 and
10 is 1024, which is too low for a busy load balancer.

`/etc/security/limits.conf` does not apply to systemd services. The
DRLB unit files set:

```
[Service]
LimitNOFILE=65535
```

To change it, use a drop-in file so RPM updates keep your setting:

```
# systemctl edit drlb_server        # or drlb_server@<name>, drlb_ssl_server

[Service]
LimitNOFILE=262144

# systemctl restart drlb_server
```

To change the limit of a running process for testing:

```
# pgrep -a -x 'drlb_server|drlb_ssl_server'
# prlimit --pid <pid> --nofile=32767:65535
```

When you run the server from a shell, set the limits in that shell
first:

```
# ulimit -n 32767
# ulimit -H -n 65535
```

To check the limits and the open files of the DRLB processes:

```
# pids=$(pgrep -x 'drlb_server|drlb_ssl_server')
# for p in $pids; do grep -i 'open files' /proc/$p/limits; done
# for p in $pids; do ls /proc/$p/fd | wc -l; done
```

A server started as `drlb_ssl_server` shows under that name in the
process list, so look for both names.

### Kernel tuning

A load balancer under high load needs kernel tuning. The values below
are for very high volume; you may not need many of them. Test each one
with your application and your number of front end and back end
connections.

Save the current value before you change a setting:

```
# sysctl fs.file-max | tee -a /root/sysctl_org_settings.txt
```

Put the settings in a file in `/etc/sysctl.d` and load it:

```
# vi /etc/sysctl.d/01-lb.conf
# sysctl -p /etc/sysctl.d/01-lb.conf
```

File handles, the maximum number of open files on the system:

```
fs.file-max = 25000000
```

Sockets, for large numbers of concurrent connections. The server uses
one local port per back end connection, so widen the local port range.
`net.ipv4.tcp_tw_recycle` was removed from the kernel and must not be
set.

```
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 60
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syncookies = 1
net.core.somaxconn = 4096
```

`net.core.somaxconn` caps the `somaxconn` config setting (the listen
backlog). The kernel default is 4096 on RHEL 9 and 10 and 128 on
RHEL 8. Check it with `cat /proc/sys/net/core/somaxconn`, and set
`somaxconn` in `[LBSERVER]` to match.

DRLB is a user space proxy and does not need IP forwarding. If the
server listens on a floating address (`listen_ip_addr`) that is moved
between servers, allow binding to an address that is not assigned yet:

```
net.ipv4.ip_nonlocal_bind = 1
```

Threads, the number of threads and memory maps a process can have. Do
not set a value lower than the current one (`kernel.pid_max` and
`vm.max_map_count` are already higher on some systems):

```
kernel.threads-max = 5000000
vm.max_map_count = 128000
```

Process scheduler. Increase the time a process runs before the kernel
considers moving it to another core. On RHEL 9 and 10 this setting
moved from sysctl to debugfs and is not kept across reboots:

```
RHEL 8, in /etc/sysctl.d:
kernel.sched_migration_cost_ns = 5000000

RHEL 9 and RHEL 10:
# echo 5000000 > /sys/kernel/debug/sched/migration_cost_ns
```

```
kernel.sched_autogroup_enabled = 0
```

### Process monitoring

Shell commands to watch DRLB CPU, memory, thread and file use under
load:

```
$ watch -n 1 'ps -o %cpu,%mem,pid,etime,nlwp,args -C drlb_server,drlb_ssl_server'
$ pids=$(pgrep -x 'drlb_server|drlb_ssl_server')
$ for p in $pids; do grep -i -E 'vmsize|vmrss|threads' /proc/$p/status; done
$ for p in $pids; do ls /proc/$p/fd | wc -l; done
```

`nlwp` is the number of threads. A script that logs these every
second:

```
#!/bin/bash
# Log open files, memory and threads of each DRLB server process
log=/tmp/watch_drlb_proc.log
pgrep -a -x 'drlb_server|drlb_ssl_server' | tee -a ${log}
while true; do
    date | tee -a ${log}
    for p in $(pgrep -x 'drlb_server|drlb_ssl_server'); do
        echo "pid ${p} open files: $(ls /proc/${p}/fd 2>/dev/null | wc -l)"
        grep -i -E 'vmsize|threads' /proc/${p}/status
    done | tee -a ${log}
    echo "" | tee -a ${log}
    sleep 1
done
```

The stats file shows connections per second and open connections per
node, see [Statistics](#statistics).

## Testing

### Regression tests

From the top of the source tree, after `make`:

```
$ make test
```

This runs three suites against `./drlb_server`:

| Suite | Checks |
|---|---|
| `tests/drlb_tests.py` | The 1.60 TCP regression suite: schemes, fail over, HTTP forwarding, large transfers, timeouts, resource exhaustion, shutdown |
| `tests/ssl_bridge_tests.py` | The 1.60 SSL bridge suite: front end TLS, back end TLS and certificate checks, protocols |
| `tests/compat_tests.py` | 2.0 checks: config compatibility, the `drlb_ssl_server` name, stats and log files, rotation, signals, limits, throttling |

The tests start their own back end servers on 127.0.0.1 and use ports
18000-18299. They need Python 3.7 or later and the `openssl` command.
Each check prints PASS or FAIL, and a suite exits non-zero if any check
fails.

RHEL 8's default `python3` is 3.6, which is too old. Install Python
3.11 and pass it to make:

```
# dnf -y install python3.11
$ make test PYTHON=python3.11
```

A suite can also be run on its own, for example
`python3 tests/compat_tests.py ./drlb_server`. To test with
AddressSanitizer, build `make asan` and pass `./drlb_server_asan`.

### Load tests

`tests/load/run_load_tests.py` runs load and stress tests (scale out,
fail over, mixed back end capacity, TLS overhead, idle connections)
against simulated back ends and writes CSV files and PNG charts to
`tests/load/results`. It needs `ab` (`dnf install httpd-tools`) and
matplotlib (`dnf install python3-matplotlib`; on RHEL 8 install
matplotlib for Python 3.11 with `python3.11 -m pip install matplotlib`).
See `tests/load/README.txt`.

```
$ python3 tests/load/run_load_tests.py --quick scale_out failover
```

### Testing with Apache

A simple way to test a config is with Apache on a few virtual machines.
`docs/apache_test` has two PHP pages: `index.php` shows the name of the
server that answered, and `loop.php` keeps a connection open and
prints a line every second, to test persistent connections. Copy them
to the web root of each back end:

```
$ cd docs/apache_test
$ chmod 644 *.php
$ for s in 192.168.122.111 192.168.122.112 192.168.122.113 192.168.122.114; do
>   scp -p *.php username@${s}:/var/www/html/
> done
```

Start the server with the example round robin config. It uses those
four addresses on port 80 and listens on port 8080. Its log and stats
files are in `/var/log/drlb`, so override them when you run it as a
user:

```
$ ./drlb_server --config-file=etc/http_rr_test.cfg --log-file=/tmp/http_rr.log \
    --stats-file=/tmp/http_rr_stats.log --verbose
```

Connect, assuming the server runs on 192.168.122.1:

```
$ curl http://192.168.122.1:8080/
$ curl -N http://192.168.122.1:8080/loop.php     # persistent connection
```

Repeat the first command to see each back end answer in turn.

Firefox opens at most 6 persistent connections to one server. To test
more from one browser, open `about:config`, search for
`network.http.max-persistent-connections-per-server` and raise the
value.

## Support

Bugs and questions: https://datareel.com/contact.php

Source code and downloads: https://datareel.com/downloads/drlb/
