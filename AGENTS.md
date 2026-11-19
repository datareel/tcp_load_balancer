# DRLB (DataReel Load Balancer): AI-assisted install, upgrade and support

This file is for AI-assisted work on DRLB, the DataReel TCP load balancer
and SSL/TLS bridge (`drlb_server`, with `drlb_ssl_server` as a link): it
tells an AI agent (Gemini CLI, Claude Code, GitHub Copilot, Codex and
others) how to assist a site's own system administrators and developers
to install DRLB, set up a load balancer or an SSL bridge, upgrade older
releases (the 1.6x load-balancer and ssl-bridge packages, or 2.0) to the
current release, 2.0.1, maintain a fork, and troubleshoot. The agent
assists; it does not replace the administrators or DataReel support, and
it never acts autonomously (section 0). The administrators review and
approve every step, and problems the agent cannot solve go to DataReel
(section 8.4). `GEMINI.md` and `CLAUDE.md` in this folder only import this
file.

The full manual is `docs/USER_GUIDE.md` (also https://datareel.com/drlb/index.php),
with `RELEASE_NOTES_2.0.1.txt` and the `drlb_server(8)` man page. The
security design is described at https://datareel.com/drlb/security_design.php
(source: `docs/SECURITY_DESIGN.md`). This file points to them instead of
repeating them. When this file and the manual or the code disagree, the
manual and the code win: say so to the person you work for.

## Before you use AI assistance

**Review all of your agency's or company's AI usage policies, and get formal
written approval from your management team, in the form of a business use
case and justification, before you use any AI assistance with DRLB.** AI
desktops and command line tools may be used with this guide only in strict
compliance with those policies and that approval.

- **Use only approved enterprise AI models.** An AI agent working with DRLB
  may process potentially sensitive data: host names, IP addresses, back end
  server names, certificates, config files, command output and logs. Use
  only your agency's or company's enterprise AI models that have built-in
  safeguards against disclosing information and that guarantee your
  internal information will not be used to train public models.
- **Warning: public or free AI tools, open source AI models and self-built
  AI models** may expose your information to public learning models or to
  other parties, depending on how the model is hosted, configured and
  licensed. Use them only after a comprehensive review of what information
  might be exposed and what the potential risks are.
- The entire risk of AI-assisted use rests with the user. DataReel cannot
  be held accountable for actions taken, commands run or other outcomes of
  AI assistance (see https://datareel.com/terms.php).
- **No endorsement.** Any mention of a specific AI tool, model or product
  in this guide, such as Gemini, Gemini CLI, Claude Code or GitHub Copilot,
  is a reference only. It is not an endorsement or a recommendation to use
  that product. Product names are trademarks of their respective owners.

**For the agent:** at the start of a session, ask the person to confirm
that this AI-assisted use is approved under their organization's AI usage
policy and that you are an approved enterprise AI model. If they cannot
confirm it, stop and do not ask for or read any data from their systems.

## 0. Human in the loop: the agent never acts on its own

AI-assisted means the agent assists a person; it never acts
autonomously. Every change to a server is made by a person or explicitly
approved by one, one step at a time.

- **Advisory mode is the default.** The agent explains the next step and
  prints the exact command and the server it is for. The person runs it
  and pastes back only output that holds no secret (rule 5). Use this mode
  unless the organization allows the agent to run tools.
- **If tool execution is allowed,** each command still needs its own
  explicit approval before it runs. Never use auto-approve modes: no
  Gemini CLI `--yolo` or auto-accept, no Claude Code permission bypass
  (`--dangerously-skip-permissions`, bypass mode), no auto-run in other
  agents.
- **No unattended work:** no scheduled, background, batch or scripted
  runs of changing commands, and no loops over servers that the person has
  not approved as one listed step.
- **Read-only checks first** (section 8.1); they are shown and approved
  the same way.

**Works with strict AI policies.** These files contain no code that runs
by itself: `AGENTS.md`, `GEMINI.md` and `CLAUDE.md` are text. Everything in
this guide works in advisory mode, with no tool execution by the agent.

## 1. Rules for agents (read these first)

DRLB sits in front of production services: every client connection goes
through it. A wrong step drops connections, takes a service off line, or
weakens the TLS that protects it. Follow these rules on every task:

1. **One load balancer at a time.** Never run a changing command on more
   than one DRLB server in one step, and never in a loop over servers,
   unless the person has confirmed that exact step for those servers. When
   two DRLB servers share a floating IP (for example with DRCM), change the
   standby one first.
2. **Show, then the person runs or approves it.** Before any command that
   changes a server (dnf, rpm, `dnf swap`, systemctl start/stop/restart,
   edits under `/etc/drlb` or `/etc/sysconfig`, firewall-cmd, sysctl,
   update-crypto-policies), print the command and the server name. In
   advisory mode the administrator runs it; otherwise wait for an explicit
   yes for that one command (section 0).
3. **Back up before changing.** Copy `/etc/drlb` and
   `/etc/sysconfig/drlb_server` and `drlb_ssl_server` into a dated backup
   folder only root can read (`/etc/drlb/ssl/private` holds private keys)
   before any change. Never delete; move aside.
4. **Check the config before every restart:**
   `drlb_server --config-file=FILE --check-config` must end with "DRLB config
   file checks good". Stop if it does not.
5. **Never see a private key or a password.** Do not print, copy, paste or
   regenerate the files in `/etc/drlb/ssl/private` or any key passphrase.
   Check a key with `openssl pkey -noout -in KEY` run by the person, and
   compare certificates by fingerprint (`openssl x509 -noout -fingerprint
   -sha256 -in CERT`) only.
6. **Never weaken a safeguard silently.** Do not turn off firewalld or
   SELinux, do not set `ssl_verify_backend_cert = 0` on real back ends, do
   not lower `ssl_protocol` to TLSv1_2 only, do not set `ssl_groups` or
   `ssl_sigalgs` to classical-only lists, do not loosen the systemd
   sandboxing or run the service as root, and do not change the system
   crypto policy (LEGACY) to make a client connect. On RHEL 8, do not move
   a FIPS-mode host from `drlb_server` to `drlb_server-openssl35`. Report
   instead.
7. **Read-only first.** Start every task with the read-only checks in 8.1.
8. **No secrets or site data in files you write** (host names, addresses,
   certificates, keys), unless the person asks for that file on their own
   systems.
9. **Keep a log.** List each command, on which server, and its result, and
   give it to the person at the end.

## 2. What DRLB is

`drlb_server` accepts TCP connections on one port and relays each one to
a back end node (round robin, weighted, distributed or assigned by client
address). A config file with an `[SSLCONFIG]` section also terminates
SSL/TLS on the front end (the SSL bridge), with optional TLS and
certificate checks to the back ends and `X-Forwarded-For` for HTTP.
`drlb_ssl_server` is a link to `drlb_server`; under that name the config
must have an `[SSLCONFIG]` section. Release 2.0 replaced the 1.6x
load-balancer and ssl-bridge packages (the LDM load balancer stays in
the `legacy_drlb` repository).

| Item | Location (2.0.1) |
| --- | --- |
| Program | `/usr/sbin/drlb_server`, `/usr/sbin/drlb_ssl_server` (link) |
| Configs | `/etc/drlb/*.cfg`; `active_configs.list` lists the ones `drlb_server.service` runs; `ssl_bridge.cfg` for `drlb_ssl_server.service` |
| TLS files | `/etc/drlb/ssl/private` (keys, root:drlb 750), `/etc/drlb/ssl/certs` |
| systemd units | `drlb_server.service` (all active configs), `drlb_server@NAME.service` (`/etc/drlb/NAME.cfg`), `drlb_ssl_server.service` |
| Extra settings | `/etc/sysconfig/drlb_server`, `/etc/sysconfig/drlb_ssl_server` |
| Helpers | `/usr/libexec/drlb/drlb_platform_check`, `drlb_server_ctl` |
| Logs and stats | `/var/log/drlb/` (owned by the `drlb` user), `journalctl -u drlb_server` |
| Service user | `drlb`, with systemd sandboxing and only `CAP_NET_BIND_SERVICE` |

RPMs per OS (2.0.1):

| OS | Package | OpenSSL | TLS |
| --- | --- | --- | --- |
| RHEL 10, RHEL 9 | `drlb_server` | system OpenSSL 3.5 | post-quantum (hybrid ML-KEM, ML-DSA) |
| RHEL 8 | `drlb_server` | system OpenSSL 1.1.1 (FIPS 140 validated by Red Hat): the FIPS build | classic only, from the system crypto policy |
| RHEL 8 | `drlb_server-openssl35` | OpenSSL 3.5.9 built in (static), no OpenSSL package needed | post-quantum; not for FIPS-mode hosts |

Install one of the two RHEL 8 packages. `drlb_server-openssl35` provides
and conflicts with `drlb_server`; `dnf swap` moves a host between them.

Read-only status commands (run on the server):

```
drlb_server --version                 # version, linked OpenSSL, FIPS build, FIPS mode
rpm -q drlb_server drlb_server-openssl35
systemctl status drlb_server drlb_ssl_server 'drlb_server@*'
drlb_server --config-file=/etc/drlb/NAME.cfg --check-config
```

## 3. Repository layout and building (development work)

| Path | Contents |
| --- | --- |
| `src/` | the program (C++17, standard library, POSIX and OpenSSL; no DataReel library) |
| `etc/` | example and default configs, sysconfig files |
| `systemd/` | units, `drlb_platform_check`, `drlb_server_ctl` |
| `rpm/` | `drlb_server.spec`, `make_rpm_package.sh`, `build_openssl35.sh` |
| `tests/` | `drlb_tests.py`, `ssl_bridge_tests.py`, `compat_tests.py`, `pqc_tests.py`; `tests/load/` load tests |
| `docs/` | `USER_GUIDE.md`, `SECURITY_DESIGN.md` |
| `man/` | `drlb_server.8`, `drlb_ssl_server.8` |

Build: `make` (needs gcc-c++, make, openssl-devel; OpenSSL 3.5 or later).
`make test` runs every suite (`PYTHON=python3.11` on RHEL 8; the
post-quantum suite needs an OpenSSL 3.5 `openssl` command). RPMs: build
on the target OS or in a UBI container with `cd rpm &&
./make_rpm_package.sh rhel10` (or `rhel9`, `rhel8` for the FIPS build,
`rhel8-openssl35` after `./build_openssl35.sh`). The script refuses a
package whose OpenSSL linkage does not match its kind. Every release
bumps `version.txt`, `VersionString` in `src/config.cpp`, `Version:` and
`%changelog` in the spec, `CMakeLists.txt`, the man pages, README.md, the
user guide and the release notes.

## 4. New install on RHEL 8, 9 or 10

Manual: "Installing from RPM", "Quick start", "Running as a service" and
"Firewall settings" in the user guide.

1. Pick the package (section 2). On RHEL 8: `drlb_server` for FIPS-mode
   hosts (`fips-mode-setup --check`), `drlb_server-openssl35` for
   post-quantum TLS on every other host.
2. Download the RPM and its `.sha256sum` from
   https://datareel.com/downloads/drlb/ and check it:
   `sha256sum -c drlb_server-2.0.1-1.el9.x86_64.rpm.sha256sum`. Stop if it
   fails.
3. `dnf -y install ./drlb_server-2.0.1-1.el9.x86_64.rpm` (one server at a
   time, rule 1). RHEL 8 hosts need NetworkManager and firewalld.
4. Write the config from `/etc/drlb/http_rr_test.cfg`, `ssl_bridge.cfg` or
   `/usr/share/doc/drlb/example_config.cfg`. For the SSL bridge the person
   puts the key and certificate in `/etc/drlb/ssl/private` and `certs`
   (key mode 640, group drlb); the agent never sees the key (rule 5).
5. `drlb_server --config-file=FILE --check-config` (rule 4).
6. Open the listening port in firewalld (user guide, "Firewall settings").
7. Add the config to `/etc/drlb/active_configs.list`, or use
   `drlb_server@NAME`, then `systemctl enable --now` the service. Check
   `systemctl status` and the log.

## 5. AI-assisted upgrade to 2.0.1

### 5.1 What changes, and what does not

- **From 2.0:** `dnf upgrade` (or `dnf install` of the new RPM). Configs
  are unchanged. New: TLS uses hybrid ML-KEM key exchange first
  (`X25519MLKEM768`) and accepts ML-DSA certificates on OpenSSL 3.5
  builds; new `ssl_groups` and `ssl_sigalgs` settings (`system` keeps the
  crypto policy lists). On RHEL 8, `dnf upgrade` from 2.0 lands on the
  FIPS build `drlb_server` (system OpenSSL 1.1.1, classic TLS, same as
  2.0 on RHEL 8). For post-quantum TLS on a host not in FIPS mode, the
  person then runs `dnf swap drlb_server ./drlb_server-openssl35-2.0.1-1.el8.x86_64.rpm`
  as a separate, approved step.
- **From 1.60, 1.61 or 1.62 (load-balancer and ssl-bridge):** one 2.0.1
  RPM replaces both old RPMs (it obsoletes `drlb_ssl_server` < 2.0).
  Configs and services are unchanged; see "Upgrading from 1.60 and 1.61"
  in the user guide for the behavior changes.
- **LDM load balancer (`drlb_ldm_server`):** not replaced by 2.0.1; it
  stays a separate legacy package.
- The 2.0.1 release notes (`RELEASE_NOTES_2.0.1.txt`) list everything.

### 5.2 Steps (one server at a time, confirm each)

1. Read-only checks (8.1): `drlb_server --version`, `rpm -q`, every
   active config with `--check-config` using the current program, the
   service states. Note which services are enabled and running.
2. Back up `/etc/drlb` and the sysconfig files (rule 3).
3. On a pair behind a floating IP, upgrade the standby server first.
4. Install the new RPM. `.rpmnew` files are new defaults; the person
   decides whether to merge them. Never overwrite a live config.
5. `--check-config` every active config with the new program.
6. `systemctl restart` the services one at a time; check `status`, the
   log, and a test connection (for TLS:
   `openssl s_client -connect HOST:PORT -brief </dev/null`, which shows
   the protocol and the negotiated group).
7. Roll back if a check fails: reinstall the old RPM with
   `dnf downgrade` or `rpm -Uvh --oldpackage`, put the backed up configs
   back, restart, check.

## 6. Scripts and services (automation)

- The services are the supported way to run DRLB in production. Do not
  run `drlb_server` from cron or as root in a shell loop.
- Use `--check-config` in any script that changes a config, and act on
  its exit code (0 good, 1 error).
- Stats files (`enable_stats`) and the log are text; scripts may read
  them. Do not let a script change TLS settings or restart services
  without the person's approval of that script (section 0).

## 7. Forks and contributions

- Keep `make test` green, including `pqc_tests.py` on OpenSSL 3.5 and the
  FIPS checks on a FIPS build (`make FIPS_BUILD=1`).
- Keep the RHEL 8 package rules: only the FIPS build may link OpenSSL
  1.1.1, the openssl35 package must link no shared libssl/libcrypto, and
  `make_rpm_package.sh` checks both.
- Keep config files compatible with 1.60 and 2.0 (`tests/compat_tests.py`).
- Security issues: report them privately through
  https://datareel.com/contact.php, not in public issue trackers.

## 8. AI-assisted troubleshooting and support

Manual: "Logging", "Statistics", "TLS certificates and settings",
"Tuning" and "Testing" in the user guide. Diagnose read-only first;
change nothing until the person agrees on the cause and the fix (rule 2).

### 8.1 Where to look

| What | Command or file |
| --- | --- |
| Version, OpenSSL, FIPS build and FIPS mode | `drlb_server --version` |
| Installed package (RHEL 8: FIPS or openssl35) | `rpm -q drlb_server drlb_server-openssl35` |
| Config errors | `drlb_server --config-file=FILE --check-config` |
| Service state | `systemctl status drlb_server drlb_ssl_server 'drlb_server@*'` |
| Logs | `/var/log/drlb/*.log`, `journalctl -u drlb_server -u drlb_ssl_server` |
| Stats | the `stats_file_name` file in `/var/log/drlb/` |
| Listening ports | `ss -ltnp` |
| TLS from a client | `openssl s_client -connect HOST:PORT -brief </dev/null` (protocol, cipher, group) |
| Certificate | `openssl x509 -noout -subject -issuer -dates -ext subjectAltName -in CERT` |
| Crypto policy and FIPS | `update-crypto-policies --show`, `fips-mode-setup --check` |
| Firewall | `firewall-cmd --list-all` |
| Per-connection TLS details | `log_level = 4` logs protocol, cipher and group of every connection (a change: ask first, turn it back down after) |

### 8.2 Common problems

- **The service does not start.** Read `systemctl status` and the
  journal, then `--check-config`. Usual causes: an ERROR in the config, a
  key or certificate the `drlb` user cannot read, the port already in
  use, `drlb_ssl_server` with a config that has no `[SSLCONFIG]`, or on
  RHEL 8 NetworkManager or firewalld not running (`drlb_platform_check`).
- **"DRLB needs OpenSSL 3.5 or later".** The program's OpenSSL is too
  old: on RHEL 9/10 update openssl-libs; on RHEL 8 install the right
  package (section 2).
- **Clients get no post-quantum group.** Check `drlb_server --version`
  (the RHEL 8 FIPS build has no post-quantum TLS), `ssl_protocol` (TLS
  1.2 has none), `ssl_groups`, and the client: it must offer
  `X25519MLKEM768` (OpenSSL 3.5, current browsers).
- **An ML-DSA certificate fails for some clients.** The client must also
  support ML-DSA; RHEL 8/9 policies and most browsers do not yet. Keep
  an RSA or ECDSA certificate on public front ends.
- **Back end TLS fails.** The log names the certificate check that
  failed. Check `ssl_backend_ca_list_file`, `ssl_backend_hostname` and the
  back end certificate's subjectAltName. Do not turn verification off
  (rule 6).
- **Clients cannot connect at all.** firewalld, `listen_ip_addr`, the
  back end nodes (the log shows dead nodes), `max_connections`, open file
  limits ("Tuning").
- **"FIPS mode is on, but this program's built-in OpenSSL is not FIPS
  validated".** The RHEL 8 `drlb_server-openssl35` package is on a FIPS
  mode host. The person moves the host to `drlb_server` with
  `dnf swap` (section 5) as an approved step.
- **On a FIPS mode host, X25519 clients are refused.** Expected: X25519 is
  not FIPS approved; clients use P-256 or P-384.
- **A client with an old TLS stack is refused.** Expected: TLS 1.2 is the
  minimum. Report it; do not lower the protocol or the policy (rule 6).

### 8.3 Stop and escalate at once

Do not try to fix these yourself. Report to the person straight away, with
the summary in 8.4:

- A private key that may have been exposed (wrong mode, copied, pasted).
- A certificate that does not match its key, or an expired certificate on
  a production front end.
- Anything that would need a key or password to be shared, a safeguard
  to be turned off (rule 6), or a change on more than one server at once.
- Both servers of a pair down, or clients reaching a back end directly
  when they should not.

### 8.4 Support summary

When a problem is not solved, give the person a summary they can send to
their team or to DataReel (https://datareel.com/contact.php). AI-assisted
support ends here: the people take it from this summary.

1. `drlb_server --version` output and the OS (`/etc/os-release`), the
   package (`rpm -q`), and on RHEL 8 whether the host is in FIPS mode.
2. `--check-config` output for the config involved.
3. The config file with host names, addresses and certificate paths
   removed if the person asks (never a key).
4. The log lines around the problem (times included) and the
   `openssl s_client -brief` output for TLS problems.
5. What happened, when, what changed before it, and every command already
   tried with its result.

Never include private keys, passwords or key passphrases in the summary.

DRLB is free software under the GNU General Public License, provided as
is. Check every command an agent proposes before it runs; the person who
runs it is responsible for the changes made.

## 9. Report back

End every task with: the servers touched, each command and its result,
the backups made and where, every warning and what was decided, the
`.rpmnew` and `.rpmsave` files and what was done with them, and the final
`drlb_server --version` and `systemctl status` results.
