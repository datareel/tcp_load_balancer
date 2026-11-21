# DRLB TCP load balancer 2.2.1

`drlb_server` is a TCP load balancer for Linux. It accepts connections on
one port and relays each one to a backend node chosen by round robin,
weight, load percent or client address rules. A config file with an
`[SSLCONFIG]` section also terminates SSL/TLS on the frontend (the DRLB
SSL bridge), with optional TLS to the backend nodes.

Version 2.2 adds a **port multiplexer** (`mode = MUX`): many
local TCP and UDP ports, from any number of processes, are carried over
one TLS tunnel to a peer DRLB, which delivers each channel to its
service, load balanced over `[LBNODE]`s. Channels go in both
directions over the same tunnel. It was developed to cut cloud server
costs (one server in place of two or more), to shrink firewall rule
sets to one open port, to encrypt services that are not encrypted, to
let several instances of a service keep their standard port numbers,
and to give virtual hosting to services that do not offer it. See
"Port multiplexer" in the user
guide and the example pairs `etc/mux_*_a.cfg`, `etc/mux_*_b.cfg`. "How DRLB compares" in the
user guide compares DRLB with the kinds of tools it overlaps (TCP load
balancers, TLS wrappers, SSH-style port forwarding, VPNs, tunnel and
port multiplexer tools), without naming products.

Version 2.0 combines the 1.60/1.61 **load-balancer** (`drlb_server`)
and **ssl-bridge** (`drlb_ssl_server`) packages in one program. It is
written in C++17 with only the standard library, POSIX and OpenSSL; the
DataReel library is no longer used. The 1.61 releases of both packages,
and LDM-load-balancer 1.65 (which 2.0 does not replace), are kept in the
`legacy_drlb` repository.

The full documentation is the
[user guide](docs/USER_GUIDE.md): install, services, every config
setting, the load balancing schemes, TLS, logging, stats, tuning and
testing. [DESIGN.md](DESIGN.md) describes how the code is organized.
The [security design white paper](docs/SECURITY_DESIGN.md) explains how
DRLB protects the services behind it: TLS, post-quantum key exchange,
the OpenSSL builds per RHEL release, the service sandboxing and the
October 2026 security review.

**AI-assisted install, upgrade and support:** [AGENTS.md](AGENTS.md)
(read by Gemini CLI through `GEMINI.md`, Claude Code through
`CLAUDE.md`, and other agents directly) lets an approved enterprise AI
agent assist your administrators with installing, upgrading and
troubleshooting DRLB. Human in the loop, never autonomous: your
administrators run or approve every step, and the agent never sees a
private key or password. Before any AI assistance, review your
organization's AI usage policies and get formal written management
approval; naming an AI tool is a reference only, not an endorsement.

Supported platforms: RHEL 10, RHEL 9, and RHEL 8 with NetworkManager
and firewalld (and rebuilds such as Rocky Linux and AlmaLinux).

## Upgrading from 1.60 or 1.61

- Config files are unchanged. Old `drlb_server` configs run as plain
  TCP load balancers, and `ssl_bridge.cfg` (it has an `[SSLCONFIG]`
  section) runs as the SSL bridge.
- `drlb_ssl_server` is now a link to `drlb_server`. Under that name the
  config must have an `[SSLCONFIG]` section.
- The services (`drlb_server`, `drlb_server@<config>` and
  `drlb_ssl_server`), sysconfig files, `drlb` user and sandboxing are the
  same. The 2.0 RPM replaces both old RPMs and keeps
  `drlb_ssl_server.service` enabled and running if it was.
- See [RELEASE_NOTES_2.0.txt](RELEASE_NOTES_2.0.txt) for the small
  behavior changes.

## Building

RHEL 9 or RHEL 10 with OpenSSL 3.5 or later; older OpenSSL headers stop
the build. RHEL 8 has two builds, like DRCM 1.49: `make FIPS_BUILD=1`
(the system OpenSSL 1.1.1, FIPS validated, classic TLS) and
`rpm/build_openssl35.sh` then
`make OPENSSL_PREFIX=/opt/openssl-3.5 OPENSSL_STATIC=1` (OpenSSL 3.5.9
built in, post-quantum TLS).

```
sudo dnf -y install gcc-c++ make openssl-devel
make openssl-check           # prints the OpenSSL version, fails below 3.5
make
./drlb_server --version
```

`make asan` builds `drlb_server_asan` with AddressSanitizer for testing.
CMake also works: `cmake -S . -B build-cmake && cmake --build build-cmake`.

## RPM

Build the RPM on the RHEL version it is for (also needs `rpm-build`).
The RPMs are `drlb_server-2.2.1-1.el9` and `.el10` (system OpenSSL
3.5), and on RHEL 8 either `drlb_server-2.2.1-1.el8` (FIPS build,
system OpenSSL 1.1.1) or `drlb_server-openssl35-2.2.1-1.el8` (OpenSSL 3.5 built
in, post-quantum TLS; `./make_rpm_package.sh rhel8-openssl35` after
`./build_openssl35.sh`). `dnf swap` moves a RHEL 8 host between the two:

```
cd rpm
./make_rpm_package.sh rhel10      # or rhel9, rhel8
sudo dnf -y install ~/rpmbuild/RPMS/x86_64/drlb_server-2.2.1-*.el10.x86_64.rpm
```

## Running

```
drlb_server --config-file=/etc/drlb/http_rr_test.cfg --check-config
systemctl enable --now drlb_server              # every config in /etc/drlb/active_configs.list
systemctl enable --now drlb_server@http_rr_test # one config: /etc/drlb/http_rr_test.cfg
systemctl enable --now drlb_ssl_server          # /etc/drlb/ssl_bridge.cfg
```

If the config file named with `--config-file` does not exist, a default
one is written and the program exits. `etc/example_config.cfg` and
`etc/ssl_bridge.cfg` show every setting.

Every setting is described in the
[settings reference](docs/USER_GUIDE.md#settings-reference) of the user
guide.

## TLS settings in brief

```
[SSLCONFIG]
ssl_protocol = TLS              # TLS 1.2 and 1.3; or TLSv1_2, TLSv1_3
ssl_key_file = /etc/drlb/ssl/private/ca.key
ssl_cert_file = /etc/drlb/ssl/certs/ca.crt
##ssh_ca_list_file = /etc/drlb/ssl/certs/ca_list.crt   # chain
ssl_handshake_timeout_secs = 30
##ssl_encrypt_backend = 1       # TLS to the backend nodes
##ssl_verify_backend_cert = 1   # default; checks chain and host name
##ssl_backend_hostname = www.example.com
```

Ciphers follow the system crypto policy unless `ssl_cipher_list` or
`ssl_ciphersuites` restrict them.

Post-quantum: key exchange uses hybrid ML-KEM first (`X25519MLKEM768`,
then classical X25519 and P-256 for older clients) on the frontend and
the backends, and ML-DSA certificates work. `ssl_groups` and
`ssl_sigalgs` change the lists; `system` keeps the crypto policy lists
(the default in FIPS mode). See the user guide.

## Tests

```
make test                    # RHEL 8: make test PYTHON=python3.11
```

runs `tests/drlb_tests.py` and `tests/ssl_bridge_tests.py` (the 1.60
regression suites), `tests/compat_tests.py`, `tests/pqc_tests.py`
(post-quantum TLS; FIPS checks on a FIPS build) and `tests/mux_tests.py`
(the 2.2 port multiplexer) against `./drlb_server`.
They need Python 3.7 or later and the `openssl` command (3.5 or later for
`pqc_tests.py`) and use local ports 18000-18399. `tests/load/run_load_tests.py` runs the load and
stress tests (needs `ab` and matplotlib).

## License

GNU General Public License version 3 or later, see [COPYING](COPYING).
