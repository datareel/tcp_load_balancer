#!/usr/bin/env python3
# DRLB post-quantum TLS tests (OpenSSL 3.5 or later)
#
# Checks the hybrid ML-KEM key exchange groups and ML-DSA certificates
# on the frontend and on TLS backends, the ssl_groups setting, and the
# OpenSSL 3.5 build. Uses "openssl s_client" as the client and
# "openssl s_server" as TLS backends, because they report the negotiated
# group.
#
# Usage: python3 tests/pqc_tests.py [path to drlb_server or drlb_ssl_server]
# Needs Python 3, the OpenSSL 3.5 openssl command and the server.
# Uses ports 18300-18399.

import http.client
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, '..', 'drlb_server'))
LB_PORT = 18300
BE_PORT = 18311
WORK = tempfile.mkdtemp(prefix='drlb_pqc_tests_')
results = []
# Signature algorithms for the openssl s_client/s_server peers in the
# ML-DSA tests. The RHEL 9 DEFAULT crypto policy has none of the ML-DSA
# algorithms, so a peer that uses the policy cannot verify or sign with
# ML-DSA at all; DRLB's own default list includes them.
MLDSA_PEER_SIGALGS = 'mldsa65:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256'


def sh(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=WORK)


def make_ca(prefix, alg):
    sh('openssl', 'req', '-x509', '-newkey', alg, '-nodes', '-keyout', prefix + 'ca.key',
       '-out', prefix + 'ca.crt', '-days', '2', '-subj', '/CN=DRLB PQC Test CA ' + prefix)


def make_leaf(prefix, name, alg, san):
    sh('openssl', 'req', '-newkey', alg, '-nodes', '-keyout', prefix + name + '.key',
       '-out', prefix + name + '.csr', '-subj', '/CN=' + name)
    ext = os.path.join(WORK, prefix + name + '.ext')
    with open(ext, 'w') as f:
        f.write('subjectAltName=%s\n' % san)
    sh('openssl', 'x509', '-req', '-in', prefix + name + '.csr', '-CA', prefix + 'ca.crt',
       '-CAkey', prefix + 'ca.key', '-CAcreateserial', '-out', prefix + name + '.crt', '-days', '2',
       '-extfile', ext)


def make_certs():
    make_ca('rsa_', 'rsa:2048')
    make_ca('mldsa_', 'mldsa65')
    for p, alg in (('rsa_', 'rsa:2048'), ('mldsa_', 'mldsa65')):
        make_leaf(p, 'front', alg, 'DNS:localhost,IP:127.0.0.1')
        make_leaf(p, 'back', alg, 'DNS:backend.test,IP:127.0.0.1')


def wait_port(port, proc):
    for _ in range(50):
        if proc.poll() is not None:
            return False
        try:
            socket.create_connection(('127.0.0.1', port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


class Backend:
    """openssl s_server -www as a TLS backend"""

    def __init__(self, prefix, groups=None):
        args = ['openssl', 's_server', '-accept', str(BE_PORT), '-www', '-quiet',
                '-cert', prefix + 'back.crt', '-key', prefix + 'back.key']
        if groups:
            args += ['-groups', groups]
        if prefix == 'mldsa_':
            # The RHEL 9 DEFAULT crypto policy has no ML-DSA signature
            # algorithms, so the test server lists them itself
            args += ['-sigalgs', MLDSA_PEER_SIGALGS]
        self.proc = subprocess.Popen(args, cwd=WORK, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     stdin=subprocess.DEVNULL)
        self.started = wait_port(BE_PORT, self.proc)

    def stop(self):
        self.proc.kill()
        self.proc.wait()


class Bridge:
    def __init__(self, name, ssl_opts, prefix='rsa_', node_port=BE_PORT):
        self.name = name
        lines = ['[SSLCONFIG]', 'ssl_key_file = %s/%sfront.key' % (WORK, prefix),
                 'ssl_cert_file = %s/%sfront.crt' % (WORK, prefix)]
        lines += list(ssl_opts)
        lines += ['[LBSERVER]', 'port = %d' % LB_PORT, 'enable_logging = 1', 'log_level = 4',
                  'logfile_name = %s/%s.log' % (WORK, name), 'retries = 0']
        lines += ['[LBNODE]', 'node_name = node1', 'hostname = 127.0.0.1', 'port_number = %d' % node_port]
        cfg = os.path.join(WORK, name + '.cfg')
        with open(cfg, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        self.out = open(os.path.join(WORK, name + '.out'), 'w')
        self.proc = subprocess.Popen([SERVER, '--config-file=' + cfg], stdout=self.out, stderr=subprocess.STDOUT)
        self.started = wait_port(LB_PORT, self.proc)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        try:
            rc = self.proc.wait(30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            rc = 'killed'
        self.out.close()
        return rc

    def output(self):
        text = open(self.out.name).read()
        try:
            text += open(os.path.join(WORK, self.name + '.log')).read()
        except OSError:
            pass
        return text


def s_client(cafile, groups=None, extra=()):
    """Returns (negotiated group, signature type, verified) or None if the handshake failed"""
    args = ['openssl', 's_client', '-connect', '127.0.0.1:%d' % LB_PORT, '-servername', 'localhost',
            '-brief', '-verify_return_error', '-CAfile', os.path.join(WORK, cafile)]
    if groups:
        args += ['-groups', groups]
    args += list(extra)
    try:
        p = subprocess.run(args, input=b'', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
    except subprocess.TimeoutExpired:
        return None
    out = p.stdout.decode(errors='replace')
    if 'CONNECTION ESTABLISHED' not in out:
        return None
    info = {}
    for line in out.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            info[k.strip()] = v.strip()
    group = info.get('Negotiated TLS1.3 group')
    if not group and 'Peer Temp Key' in info:  # Classical groups: "X25519, 253 bits", "ECDH, prime256v1, 256 bits"
        parts = [x.strip() for x in info['Peer Temp Key'].split(',')]
        group = parts[1] if parts[0] == 'ECDH' else parts[0]
        group = {'prime256v1': 'secp256r1'}.get(group, group)
    return (group, info.get('Signature type'), info.get('Verification') == 'OK')


def https_get(cafile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(os.path.join(WORK, cafile))
    c = http.client.HTTPSConnection('localhost', LB_PORT, context=ctx, timeout=20)
    try:
        c.request('GET', '/')
        r = c.getresponse()
        r.read()
        return r.status
    except Exception:
        return None
    finally:
        c.close()


def check(name, ok, detail=''):
    results.append((name, ok, detail))
    print('%-4s %s %s' % ('PASS' if ok else 'FAIL', name, detail))


def test_openssl_version():

    ldd = subprocess.run(['ldd', SERVER], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode()
    check('server links libssl.so.3 (not 1.1)', 'libssl.so.3' in ldd and 'libssl.so.1.1' not in ldd)
    lib = subprocess.run(['openssl', 'version'], stdout=subprocess.PIPE).stdout.decode().split()
    ok = len(lib) > 1 and tuple(int(x) for x in lib[1].split('-')[0].split('.')[:2]) >= (3, 5)
    check('openssl command is 3.5 or later', ok, ' '.join(lib[:2]))


def test_frontend_groups():
    be = Backend('rsa_')
    b = Bridge('front_default', ['ssl_protocol = TLS'])
    check('bridge starts with the default groups', b.started)
    r = s_client('rsa_ca.crt', 'X25519MLKEM768')
    check('frontend X25519MLKEM768', r is not None and r[0] == 'X25519MLKEM768', str(r))
    r = s_client('rsa_ca.crt', 'SecP256r1MLKEM768')
    check('frontend SecP256r1MLKEM768', r is not None and r[0] == 'SecP256r1MLKEM768', str(r))
    r = s_client('rsa_ca.crt', 'SecP384r1MLKEM1024')
    check('frontend SecP384r1MLKEM1024', r is not None and r[0] == 'SecP384r1MLKEM1024', str(r))
    r = s_client('rsa_ca.crt', 'X25519:X25519MLKEM768')
    check('frontend prefers ML-KEM over a classical key share (HRR)',
          r is not None and r[0] == 'X25519MLKEM768', str(r))
    r = s_client('rsa_ca.crt', 'X25519')
    check('frontend classical X25519 client still works', r is not None and r[0] == 'X25519', str(r))
    r = s_client('rsa_ca.crt', 'secp256r1')
    check('frontend classical P-256 client still works', r is not None and r[0] == 'secp256r1', str(r))
    r = s_client('rsa_ca.crt')
    check('frontend with the client default groups', r is not None, str(r))
    b.stop()
    be.stop()


def test_ssl_groups_setting():
    b = Bridge('front_classical', ['ssl_groups = X25519:secp256r1'])
    r = s_client('rsa_ca.crt', 'X25519MLKEM768')
    check('ssl_groups = X25519:secp256r1 refuses an ML-KEM only client', b.started and r is None, str(r))
    r = s_client('rsa_ca.crt', 'X25519')
    check('ssl_groups = X25519:secp256r1 allows X25519', r is not None and r[0] == 'X25519', str(r))
    b.stop()
    b = Bridge('front_system', ['ssl_groups = system', 'ssl_sigalgs = system'])
    r = s_client('rsa_ca.crt', 'X25519')
    check('ssl_groups = system starts and works', b.started and r is not None, str(r))
    b.stop()
    b = Bridge('front_bad', ['ssl_groups = NotAGroup'])
    check('bad ssl_groups refused at startup', not b.started and 'Bad ssl_groups' in b.output())
    b.stop()
    b = Bridge('front_bad_sig', ['ssl_sigalgs = not_a_sigalg'])
    check('bad ssl_sigalgs refused at startup', not b.started and 'Bad ssl_sigalgs' in b.output())
    b.stop()
    b = Bridge('front_tls12', ['ssl_protocol = TLSv1_2'])
    check('ssl_protocol = TLSv1_2 warns there is no post-quantum key exchange',
          b.started and 'no post-quantum key exchange' in b.output())
    b.stop()


def test_mldsa_frontend():
    b = Bridge('front_mldsa', [], prefix='mldsa_')
    check('bridge starts with an ML-DSA-65 certificate', b.started, b.output()[-300:] if not b.started else '')
    r = s_client('mldsa_ca.crt', 'X25519MLKEM768', ['-sigalgs', MLDSA_PEER_SIGALGS])
    check('frontend ML-DSA-65 certificate verified', r is not None and r[1] == 'mldsa65' and r[2], str(r))
    b.stop()


def backend_case(name, prefix, be_groups, ssl_opts, expect):
    be = Backend(prefix, be_groups)
    b = Bridge('be_' + name.replace(' ', '_'), ['ssl_encrypt_backend = 1', 'ssl_verify_backend_cert = 1',
                                                  'ssl_backend_ca_list_file = %s/%sca.crt' % (WORK, prefix)]
               + list(ssl_opts))
    status = https_get('rsa_ca.crt') if b.started and be.started else None
    b.stop()
    be.stop()
    log = b.output()
    ok = (status == 200) == expect
    check('backend %s %s' % (name, 'accepted' if expect else 'rejected'), ok, 'status %s' % status)
    return log


def test_backends():
    log = backend_case('X25519MLKEM768 only', 'rsa_', 'X25519MLKEM768', [], True)
    check('backend log shows group X25519MLKEM768 (log_level 4)', 'group X25519MLKEM768' in log)
    backend_case('X25519 only (no ML-KEM)', 'rsa_', 'X25519', [], True)
    backend_case('SecP256r1MLKEM768 only', 'rsa_', 'SecP256r1MLKEM768', [], True)
    backend_case('ML-DSA-65 certificate', 'mldsa_', None, [], True)
    backend_case('ML-KEM only with ssl_groups = X25519', 'rsa_', 'X25519MLKEM768', ['ssl_groups = X25519'], False)


def main():
    if not os.access(SERVER, os.X_OK):
        print('Server binary not found: %s' % SERVER)
        return 2
    make_certs()
    for t in (test_openssl_version, test_frontend_groups, test_ssl_groups_setting, test_mldsa_frontend,
              test_backends):
        try:
            t()
        except Exception as e:
            check(t.__name__, False, 'exception: %s' % e)
    failed = [r for r in results if not r[1]]
    print('\n%d passed, %d failed. Logs: %s' % (len(results) - len(failed), len(failed), WORK))
    if not failed:
        shutil.rmtree(WORK, ignore_errors=True)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
