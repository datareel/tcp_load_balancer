# DRLB security design

**Release:** 2.0.1 (`drlb_server`, with `drlb_ssl_server` as a link), and
the legacy packages built on the DataReel library (load-balancer and
ssl-bridge 1.6x, LDM-load-balancer 1.6x) where noted.
**Audience:** security reviewers, administrators and anyone deciding
whether to put DRLB in front of their services. The source code is
published, so everything on this page can be checked against it; the
design does not depend on keeping it secret. The
[user guide](USER_GUIDE.md) has the settings and commands.

## 1. What DRLB protects, and from whom {#overview}

DRLB accepts TCP connections on one port and relays each one to a back end
server node. With an `[SSLCONFIG]` section it also terminates TLS on the
front end (the SSL bridge) and can use TLS again to the back ends. The
goals are:

- **Availability:** one client, or many, cannot stop the balancer or use
  up its threads, memory or CPU (connection floods, slow clients, idle
  connections, large transfers).
- **Confidentiality and integrity in transit:** in SSL mode, traffic
  between clients and DRLB, and optionally between DRLB and the back
  ends, is protected with TLS 1.2 or 1.3, with certificate checks, and
  with post-quantum key exchange where the OpenSSL in use has it.
- **Least privilege on the host:** a bug in DRLB, or a compromised
  process, can do as little as possible: no root, no write access outside
  its log folder, no access to home folders.
- **Trustworthy headers for the back ends:** in HTTP forwarding mode the
  back ends can trust the `X-Forwarded-For` header DRLB adds.

DRLB is not a firewall, a web application firewall or an authentication
gateway. It does not inspect or filter application data (apart from the
HTTP header it adds), and it does not authenticate clients. Put access
controls in firewalld and in the back end services.

<figure class="dr2-fig">
<svg viewBox="0 0 860 190" role="img" aria-label="Clients connect over TLS to drlb_server, which relays to back end nodes over plain TCP or TLS">
<rect class="b" x="10" y="60" width="150" height="70" rx="8"/>
<text x="85" y="92" text-anchor="middle">Clients</text>
<text class="s" x="85" y="112" text-anchor="middle">TLS 1.2 / 1.3</text>
<rect class="k" x="300" y="30" width="260" height="130" rx="8"/>
<text x="430" y="62" text-anchor="middle">drlb_server (drlb user)</text>
<text class="s" x="430" y="86" text-anchor="middle">TLS termination, ML-KEM hybrid groups</text>
<text class="s" x="430" y="106" text-anchor="middle">scheme, dead nodes, limits, timeouts</text>
<text class="s" x="430" y="126" text-anchor="middle">X-Forwarded-For (HTTP)</text>
<rect class="b" x="700" y="20" width="150" height="50" rx="8"/>
<text x="775" y="50" text-anchor="middle">Node 1</text>
<rect class="b" x="700" y="80" width="150" height="50" rx="8"/>
<text x="775" y="110" text-anchor="middle">Node 2</text>
<rect class="b" x="700" y="140" width="150" height="40" rx="8"/>
<text x="775" y="165" text-anchor="middle">Node N</text>
<path class="a" d="M160 95 L300 95"/>
<path class="a" d="M560 70 L700 45"/>
<path class="a" d="M560 95 L700 105"/>
<path class="a" d="M560 125 L700 160"/>
<text class="s" x="630" y="185" text-anchor="middle">plain TCP or TLS (verified)</text>
</svg>
<figcaption>The data path in SSL mode. In TCP mode the front end is plain TCP and the data is relayed unchanged.</figcaption>
</figure>

## 2. The program {#program}

Release 2.0 rewrote DRLB in C++17 with only the C++ standard library,
POSIX and OpenSSL; the DataReel library is no longer used. One program,
`drlb_server`, is both the TCP load balancer and the SSL bridge
(`drlb_ssl_server` is a link and requires an `[SSLCONFIG]` section).

- **One thread per client connection,** with a configurable limit
  (`max_threads`, `max_connections`, per node limits). Signals are handled
  in one dedicated thread with `sigwait()`, so a stop (`SIGTERM`) never
  runs inside a signal handler.
- **The relay waits with `poll()`** on both sockets with a timeout. No busy
  loops: idle connections use no CPU, and slow-client attacks gain
  nothing from it.
- **Bounded memory per connection:** each direction caches at most
  `max_cache_size` bytes (1 MB) before writing it out. Short writes are
  finished, not dropped.
- **Timeouts by default:** idle connections close after `timeout_secs`
  (300 s), blocked writes after `write_timeout_secs` (60 s), back end
  connects after `connect_timeout_secs` (5 s) and TLS handshakes after
  `ssl_handshake_timeout_secs` (30 s), so a client that sends nothing
  cannot hold a thread.
- **Accept errors are not fatal:** running out of file descriptors or
  memory (`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`) is logged, the accept
  loop backs off and keeps going.
- **Sockets are close-on-exec** and the program never runs other
  programs.
- **Config parsing** uses `std::string` (no fixed buffers), checks every
  number setting, and an error stops the server instead of running with
  a guessed value. `--check-config` runs the same checks, including
  loading the TLS key and certificates.

## 3. The host: service user and sandboxing {#host}

The RPM creates a `drlb` system user. The systemd units run the server as
that user with only `CAP_NET_BIND_SERVICE` (to listen on ports below
1024) and with `NoNewPrivileges`, `ProtectSystem=strict` (only
`/var/log/drlb` is writable), `ProtectHome`, `PrivateTmp`,
`PrivateDevices`, `MemoryDenyWriteExecute`, kernel, clock and hostname
protection, address family and namespace restrictions, and `UMask=0027`.

Private keys live in `/etc/drlb/ssl/private` (root:drlb, mode 750); a
key file should be mode 640, group drlb. The server only needs to read it.
On RHEL 8, the units refuse to start unless NetworkManager and firewalld
are active (`drlb_platform_check`).

## 4. TLS {#tls}

- **Protocols:** TLS 1.2 and TLS 1.3 only (`ssl_protocol = TLS`, the
  default), or one of them (`TLSv1_2`, `TLSv1_3`). SSLv2, SSLv3, TLS 1.0,
  TLS 1.1 and DTLS are refused; the old `SSLv23` setting is a config error.
- **Ciphers** follow the system crypto policy (`update-crypto-policies`)
  unless `ssl_cipher_list` (TLS 1.2) or `ssl_ciphersuites` (TLS 1.3)
  restrict them. They are set once at startup; nothing changes a shared
  TLS context while connections use it.
- **Certificates:** the certificate file may hold the chain. The key must
  match the certificate (checked at start and by `--check-config`). Any
  key type OpenSSL supports works: RSA, ECDSA, EdDSA and, with OpenSSL
  3.5, ML-DSA. There are no RSA-only checks.
- **Back end TLS** (`ssl_encrypt_backend = 1`): back end certificates are
  verified by default against `ssl_backend_ca_list_file` (the RHEL trust
  store by default) and the node host name or `ssl_backend_hostname`,
  checked against subjectAltName (no partial wildcards), with SNI for DNS
  names. `ssl_verify_backend_cert = 0` exists only for test back ends.
- **Clean shutdown:** both sides get a TLS `close_notify`, so clients can
  tell a complete response from a cut one.
- **Diffie-Hellman** for TLS 1.2 DHE suites uses the built-in RFC 7919
  groups unless `ssl_dhparms_file` is set.

## 5. Post-quantum TLS {#pqc}

A quantum computer that can break elliptic-curve and RSA key exchange
could decrypt TLS traffic recorded today ("harvest now, decrypt later").
Hybrid key exchange protects against that: the session key depends on
both a classical exchange and ML-KEM (NIST FIPS 203), so an attacker must
break both.

- **Key exchange:** with OpenSSL 3.5 or later, DRLB sets its own key
  exchange groups, with the hybrid groups first: `X25519MLKEM768`,
  `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, then `X25519`, `secp256r1`,
  `X448`, `secp384r1`, `secp521r1`, `ffdhe2048` and `ffdhe3072`. The same
  list is used on the front end and to the back ends. The RHEL 8 and
  RHEL 9 crypto policies do not offer ML-KEM, so without this TLS on those
  releases would be classical only (RHEL 10's policy puts
  `X25519MLKEM768` first).
- **The server prefers ML-KEM:** a client that supports `X25519MLKEM768`
  but sent only an X25519 key share is asked for an ML-KEM key share.
  Classical clients still connect with X25519 or P-256.
- **Back end connections** send both an `X25519MLKEM768` and an `X25519`
  key share, so a back end without ML-KEM still completes in one round
  trip.
- **Certificates:** the default signature algorithm list adds ML-DSA
  (FIPS 204: `mldsa65`, `mldsa87`, `mldsa44`) to the ECDSA, EdDSA, RSA-PSS
  and RSA PKCS#1 algorithms of the RHEL DEFAULT policy. A client must also
  support ML-DSA to accept an ML-DSA certificate; most do not yet, so keep
  an RSA or ECDSA certificate on public front ends. The key exchange is
  post-quantum with any certificate type.
- **Settings:** `ssl_groups` and `ssl_sigalgs` change the lists (OpenSSL
  3.5 syntax); `system` keeps the crypto policy lists. A bad value is a
  config error. TLS 1.2 has no post-quantum key exchange, so
  `ssl_protocol = TLSv1_2` logs a warning.
- **Checking it:** `openssl s_client -connect HOST:PORT -groups X25519MLKEM768 -brief`
  shows `Negotiated TLS1.3 group: X25519MLKEM768`, and `log_level = 4`
  logs the protocol, cipher and group of every connection.
- **Symmetric parts** (AES-256-GCM, ChaCha20-Poly1305, SHA-384) are
  already quantum-resistant at their key sizes.

## 6. OpenSSL versions and the RHEL 8 packages {#openssl}

DataReel ships no build on an OpenSSL older than the 3.5 LTS line, with
one exception for FIPS on RHEL 8 (below). RHEL 9 and RHEL 10 use the
system OpenSSL 3.5.

The 2.0 RHEL 8 RPM was linked to the RHEL 8 system OpenSSL 1.1.1k without
saying so: the build used whatever `openssl-devel` the build host had, and
nothing checked the version. 2.0.1 fixes that, and RHEL 8 now has two
packages, the same model as the DataReel cluster manager (DRCM 1.49):

| RHEL 8 package | OpenSSL | TLS | For |
| --- | --- | --- | --- |
| `drlb_server` | RHEL 8 system OpenSSL 1.1.1 (FIPS 140 validated by Red Hat) | classic; groups, signature algorithms and ciphers from the system crypto policy | FIPS-mode hosts |
| `drlb_server-openssl35` | OpenSSL 3.5.9 LTS built in statically | post-quantum (section 5) | every other host |

- **Build checks:** every build except the RHEL 8 FIPS build stops on
  OpenSSL headers older than 3.5, and the program stops at start on an
  older library. The FIPS build needs an explicit build flag
  (`FIPS_BUILD=1`), not a silent fallback. `drlb_server --version` prints
  the OpenSSL in use, whether it is the system or a static one, and the
  FIPS state.
- **Package checks:** the RPM build script refuses a FIPS package that
  does not link the system `libssl.so.1.1`, an openssl35 package with any
  shared libssl or libcrypto, an rpath or an OpenSSL requirement, and a
  RHEL 9/10 package that does not require `libssl.so.3(OPENSSL_3.5.0)`.
- **The static OpenSSL** is built from the official OpenSSL 3.5.9 tarball,
  checked against a pinned SHA-256 (`rpm/build_openssl35.sh`). An OpenSSL
  security fix means a new DRLB build of the openssl35 package. It is not
  FIPS validated, and it does not read the system crypto policy (its
  config path, `/opt/openssl-3.5/ssl`, is not installed), so DRLB's own
  defaults apply. Back end checks still use the RHEL trust store.
- **The FIPS build** has no post-quantum TLS. It says so in the log at
  start, and `ssl_groups`/`ssl_sigalgs` are ignored there with a warning,
  so the FIPS crypto policy decides. Use the DEFAULT or FIPS crypto
  policy on these hosts: under the LEGACY policy, TLS 1.2 also allows
  3DES.
- `drlb_server-openssl35` provides and conflicts with `drlb_server`;
  `dnf swap` moves a host between them, keeping configs and services.
- **FIPS mode** (`fips-mode-setup --enable`): use the FIPS build.
  OpenSSL 3.5 builds also default `ssl_groups` and `ssl_sigalgs` to the
  crypto policy lists when the host is in FIPS mode.

## 7. HTTP forwarding {#http}

With `enable_http_forwarding = 1`, DRLB adds one `X-Forwarded-For:
<client IP>` header to every HTTP request on a connection, at the start of
the request headers. Any `X-Forwarded-For` sent by the client is removed
first, so back ends can trust the header. Request bodies with
`Content-Length` or chunked encoding are followed so the next request is
found, and headers split across reads are handled. Only requests that
start with a method in `http_request_strings` are rewritten.

## 8. Assigned routing and DNS {#assigned}

`LB_ASSIGNED` routes clients to nodes by rules (regular expressions) on
the client address and, with `resolve_assigned_hostnames`, its reverse
DNS name. The reverse name is forward-confirmed (its addresses must
include the client address) and looked up once per connection, so a
client cannot claim a host name by controlling its own reverse zone.
Rules are not anchored: `192.168.1.1` also matches `192.168.1.10`; write
`^192\.168\.1\.1$`. Routing rules are not access control.

## 9. Security review, October 2026 {#review}

A review of the 1.60 code (load-balancer, ssl-bridge and
LDM-load-balancer) found 19 security issues (7 high, 9 medium, 3 low) and
11 other bugs. All were fixed in the 1.60 releases, and the 2.0 rewrite
keeps every fix. The new defaults (TLS 1.2 minimum, back end
verification, client `X-Forwarded-For` removed, no root) have no switch
back to the old behavior.

| ID | Severity | Issue (1.5x code) | Fix (1.60 and 2.0) |
| --- | --- | --- | --- |
| S1 | High | Log queue counters wrapped at the wrong size: heap overflow on shutdown with many connections | Each queue bounded by its own size; 2.0 uses standard containers |
| S2 | High | Five accept() errors in a row (a connection flood to the descriptor limit) stopped the server | Resource errors are transient: log, back off, keep accepting |
| S3, S4, S5 | High | LDM: protocol state not tracked (products injected without HIYA), any-match feed authorization, signed one-byte length fields (remote crash) | LDM-load-balancer only: session state, all-bits feed checks, full 32-bit lengths |
| S6 | High | SSL bridge set cipher list "ALL" on the shared TLS context for every connection (data race, weak suites) | Ciphers set once at startup, from the system crypto policy |
| S7 | High | SSLv2/SSLv3/TLS 1.0/1.1 accepted, no minimum version | TLS 1.2 minimum, TLS 1.3 enabled, old protocols are config errors |
| S8 | Medium | Back end certificates not verified by default; CN only, no SAN, no SNI | Verified by default, SAN and host name, SNI |
| S9 | Medium | Signal handler locked mutexes and wrote files (deadlock on stop) | One sigwait() thread |
| S10 | Medium | Unbounded memory per connection | `max_cache_size` per direction |
| S11 | Medium | CPU busy-spin relay | poll() with timeouts |
| S12 | Medium | No timeouts by default | Idle, write, connect and handshake timeouts by default |
| S13 | Medium | X-Forwarded-For spoofing and request corruption | Header at the start of each request, client header removed |
| S14 | Medium | Reverse DNS trusted without a forward check, blocking lookups | Forward-confirmed, once per connection |
| S15 | Medium | Servers ran as root, no sandboxing | `drlb` user and systemd sandboxing |
| S16 | Medium | LDM protocol capture files in /tmp, following symlinks | LDM-load-balancer only: private folder, O_EXCL and O_NOFOLLOW |
| S17 | Low | Config values copied into a 255-byte stack buffer | String values, no fixed buffers |
| S18 | Low | syslog format string bug (unused function) | Fixed format |
| S19 | Low | Unanchored rule regular expressions | Documented (section 8) |

2.0 and 2.0.1 were tested with AddressSanitizer and UndefinedBehavior
sanitizer builds, valgrind, and the regression suites (`tests/`:
`drlb_tests.py`, `ssl_bridge_tests.py`, `compat_tests.py`,
`pqc_tests.py`), plus load tests (`tests/load/`).

## 10. Limits, stated plainly {#limits}

- DRLB does not authenticate clients and does not filter what they send.
  Use firewalld rules and the back end services' own controls.
- In SSL mode the plaintext is in DRLB's memory while it is relayed, and
  the private key is in the process memory. Protect the host.
- With `ssl_encrypt_backend = 0` (the default), traffic from DRLB to the
  back ends is plain TCP. Use it only on a protected network, or turn on
  back end TLS.
- Client certificates (mutual TLS) on the front end are not supported in
  2.0.1.
- One thread per connection: the connection and thread limits, open file
  limits and kernel settings in the user guide's "Tuning" section decide
  how many clients one server can hold.
- Post-quantum TLS needs a client that offers ML-KEM; older clients get
  classical TLS. The RHEL 8 FIPS build has no post-quantum TLS.
- IPv4 only.

## 11. Legacy packages {#legacy}

load-balancer and ssl-bridge 1.6x (built on the DataReel library) are
replaced by 2.0; their source stays available. ssl-bridge 1.63 carries
the same OpenSSL 3.5 checks and post-quantum settings as 2.0.1. The LDM
load balancer (`drlb_ldm_server`) has no TLS; the LDM fixes in section 9
(S3, S4, S5, S16) apply to it.

## 12. Reporting a security issue {#report}

Report security issues privately through https://datareel.com/contact.php,
not in public issue trackers. Fixes go into the next release; the release
notes list every change.
