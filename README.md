# DRLB TCP load balancer 2.0

`drlb_server` is a TCP load balancer for Linux. It accepts connections on
one port and relays each one to a backend node chosen by round robin,
weight, load percent or client address rules. A config file with an
`[SSLCONFIG]` section also terminates SSL/TLS on the frontend (the DRLB
SSL bridge), with optional TLS to the backend nodes.

Version 2.0 combines the 1.60-beta **load-balancer** (`drlb_server`) and
**ssl-bridge** (`drlb_ssl_server`) packages in one program. It is written
in C++17 with only the standard library, POSIX and OpenSSL; the DataReel
library is no longer used. The 1.60 sources and history are kept in the
`legacy_drlb` repository. [DESIGN.md](DESIGN.md) describes how the code
is organized.

## Upgrading from 1.60

- Config files are unchanged. 1.60 `drlb_server` configs run as plain
  TCP load balancers, and `ssl_bridge.cfg` (it has an `[SSLCONFIG]`
  section) runs as the SSL bridge.
- `drlb_ssl_server` is now a link to `drlb_server`. Under that name the
  config must have an `[SSLCONFIG]` section.
- The services (`drlb_server`, `drlb_server@<config>` and
  `drlb_ssl_server`), sysconfig files, `drlb` user and sandboxing are the
  same. The 2.0 RPM replaces both 1.60 RPMs and keeps
  `drlb_ssl_server.service` enabled if it was.
- RHEL 8 is supported only with NetworkManager and firewalld, as in
  1.60.
- See [RELEASE_NOTES_2.0.txt](RELEASE_NOTES_2.0.txt) for the small
  behavior changes.

## Building

RHEL 8, RHEL 9 or RHEL 10:

```
sudo dnf -y install gcc-c++ make openssl-devel
make
./drlb_server --version
```

`make asan` builds `drlb_server_asan` with AddressSanitizer for testing.
CMake also works: `cmake -S . -B build-cmake && cmake --build build-cmake`.

## RPM

Build the RPM on the RHEL version it is for (also needs `rpm-build`):

```
cd rpm
./make_rpm_package.sh rhel10      # or rhel9, rhel8
sudo dnf -y install ~/rpmbuild/RPMS/x86_64/drlb_server-2.0-*.el10.x86_64.rpm
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

The settings are documented in
[docs/README_load_balancer_1.60.txt](docs/README_load_balancer_1.60.txt)
(load balancing, logging, stats, throttling, HTTP forwarding, limits,
tuning) and [docs/README_ssl_bridge_1.60.txt](docs/README_ssl_bridge_1.60.txt)
(certificates and TLS settings). They apply to 2.0 unchanged.

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

## Tests

```
make test
```

runs `tests/drlb_tests.py` and `tests/ssl_bridge_tests.py` (the 1.60
regression suites) and `tests/compat_tests.py` against `./drlb_server`.
They need Python 3 and the `openssl` command and use local ports
18000-18299. `tests/load/run_load_tests.py` runs the load and stress
tests.

## License

GNU General Public License version 3 or later, see [COPYING](COPYING).
