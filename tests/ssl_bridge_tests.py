#!/usr/bin/env python3
# DRLB SSL bridge regression tests
#
# Creates a test CA and certificates with the openssl command, starts
# local plain and TLS back ends and drlb_ssl_server, then checks the
# TLS protocol versions, ciphers, large transfers, back end certificate
# verification, X-Forwarded-For and the handshake timeout.
#
# Usage: python3 tests/ssl_bridge_tests.py [path to drlb_ssl_server]
# Needs Python 3, the openssl command and the server. Uses ports 18100-18199.

import http.client
import http.server
import os
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, '..', 'ssl_bridge', 'drlb_ssl_server'))
LB_PORT = 18100
PLAIN_PORT = 18111
TLS_PORT = 18112      # CA signed, subjectAltName DNS:backend.test and IP:127.0.0.1
SELF_PORT = 18113     # self-signed
WORK = tempfile.mkdtemp(prefix='drlb_ssl_tests_')
results = []


def sh(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=WORK)


def make_certs():
    sh('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt',
       '-days', '2', '-subj', '/CN=DRLB Test CA')
    for name, san in (('front', 'DNS:localhost,IP:127.0.0.1'), ('back', 'DNS:backend.test,IP:127.0.0.1')):
        sh('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', name + '.key', '-out', name + '.csr',
           '-subj', '/CN=' + name)
        with open(os.path.join(WORK, name + '.ext'), 'w') as f:
            f.write('subjectAltName=%s\n' % san)
        sh('openssl', 'x509', '-req', '-in', name + '.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
           '-CAcreateserial', '-out', name + '.crt', '-days', '2', '-extfile', name + '.ext')
    sh('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'self.key', '-out', 'self.crt',
       '-days', '2', '-subj', '/CN=127.0.0.1')


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        if self.path.startswith('/big/'):
            body = b'y' * int(self.path[5:])
        else:
            xff = '|'.join(self.headers.get_all('X-Forwarded-For') or [])
            body = ('node=%d xff=%s\n' % (self.server.server_address[1], xff)).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_backend(port, cert=None, key=None):
    srv = ThreadedServer(('127.0.0.1', port), Backend)
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(WORK, cert), os.path.join(WORK, key))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


class Bridge:
    def __init__(self, name, ssl_opts, node_port, server_opts=()):
        self.name = name
        lines = ['[SSLCONFIG]', 'ssl_key_file = %s/front.key' % WORK, 'ssl_cert_file = %s/front.crt' % WORK]
        lines += list(ssl_opts)
        lines += ['[LBSERVER]', 'port = %d' % LB_PORT, 'enable_logging = 1', 'log_level = 3',
                  'logfile_name = %s/%s.log' % (WORK, name), 'enable_http_forwarding = 1']
        lines += list(server_opts)
        lines += ['[LBNODE]', 'node_name = node1', 'hostname = 127.0.0.1', 'port_number = %d' % node_port]
        cfg = os.path.join(WORK, name + '.cfg')
        with open(cfg, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        self.out = open(os.path.join(WORK, name + '.out'), 'w')
        self.proc = subprocess.Popen([SERVER, '--config-file=' + cfg], stdout=self.out, stderr=subprocess.STDOUT)
        self.started = False
        for _ in range(50):
            if self.proc.poll() is not None:
                return
            try:
                socket.create_connection(('127.0.0.1', LB_PORT), timeout=0.2).close()
                self.started = True
                return
            except OSError:
                time.sleep(0.1)

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

    def log(self):
        try:
            return open(os.path.join(WORK, self.name + '.log')).read()
        except OSError:
            return ''


def client_ctx(minv=None, maxv=None, ciphers=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(os.path.join(WORK, 'ca.crt'))
    if minv:
        ctx.minimum_version = minv
    if maxv:
        ctx.maximum_version = maxv
    if ciphers:
        ctx.set_ciphers(ciphers)
    return ctx


def get(path, ctx=None, timeout=20):
    c = http.client.HTTPSConnection('localhost', LB_PORT, context=ctx or client_ctx(), timeout=timeout)
    c.request('GET', path, headers={'X-Forwarded-For': '6.6.6.6'})
    body = c.getresponse().read()
    c.close()
    return body


def handshake(ctx):
    try:
        with socket.create_connection(('127.0.0.1', LB_PORT), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname='localhost') as t:
                return t.version()
    except (ssl.SSLError, OSError):
        return None


def check(name, ok, detail=''):
    results.append((name, ok, detail))
    print('%-4s %s %s' % ('PASS' if ok else 'FAIL', name, detail))


def test_frontend():
    b = Bridge('front', ['ssl_protocol = TLS'], PLAIN_PORT)
    check('bridge starts with ssl_protocol = TLS', b.started)
    v12 = handshake(client_ctx(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2))
    v13 = handshake(client_ctx(ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3))
    old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    old.check_hostname = False
    old.verify_mode = ssl.CERT_NONE
    try:
        old.minimum_version = ssl.TLSVersion.TLSv1
        old.maximum_version = ssl.TLSVersion.TLSv1_1
        old.set_ciphers('ALL:@SECLEVEL=0')
        v11 = handshake(old)
    except (ValueError, ssl.SSLError):
        v11 = None
    check('TLS 1.2 accepted', v12 == 'TLSv1.2', str(v12))
    check('TLS 1.3 accepted', v13 == 'TLSv1.3', str(v13))
    check('TLS 1.0 and 1.1 refused', v11 is None, str(v11))
    weak = client_ctx(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
    try:
        weak.set_ciphers('DES-CBC3-SHA:@SECLEVEL=0')
        w = handshake(weak)
    except ssl.SSLError:
        w = None
    check('3DES cipher refused', w is None, str(w))
    body = get('/')
    check('X-Forwarded-For replaced over TLS', b'xff=127.0.0.1\n' in body, body.decode().strip())
    size = 20 * 1024 * 1024
    start = time.time()
    n = len(get('/big/%d' % size, timeout=60))
    check('20 MB response over TLS', n == size, '%.0f MB/s' % (size / (time.time() - start) / 1e6))
    rc = b.stop()
    check('bridge exits cleanly', rc == 0, 'exit %s' % rc)


def test_old_protocol_setting():
    b = Bridge('sslv23', ['ssl_protocol = SSLv23'], PLAIN_PORT)
    rc = b.stop()
    check('ssl_protocol = SSLv23 is refused at startup', not b.started and 'Unsupported ssl_protocol' in open(b.out.name).read() + b.log())


def test_handshake_timeout():
    b = Bridge('hs', ['ssl_protocol = TLS', 'ssl_handshake_timeout_secs = 2'], PLAIN_PORT)
    s = socket.create_connection(('127.0.0.1', LB_PORT))
    s.settimeout(10)
    start = time.time()
    try:
        closed = s.recv(1) == b''
    except OSError:
        closed = True
    secs = time.time() - start
    s.close()
    b.stop()
    check('client that never sends a TLS hello is dropped', closed and secs < 5, '%.1f s' % secs)


def test_backend_verify():
    cases = [
        ('valid certificate, node IP', TLS_PORT, ['ssl_verify_backend_cert = 1'], True),
        ('valid certificate, ssl_backend_hostname', TLS_PORT,
         ['ssl_verify_backend_cert = 1', 'ssl_backend_hostname = backend.test'], True),
        ('wrong host name', TLS_PORT, ['ssl_verify_backend_cert = 1', 'ssl_backend_hostname = other.test'], False),
        ('self-signed certificate', SELF_PORT, ['ssl_verify_backend_cert = 1'], False),
        ('self-signed with verification off', SELF_PORT, ['ssl_verify_backend_cert = 0'], True),
    ]
    for name, port, opts, expect in cases:
        b = Bridge('be_%d_%d' % (port, len(results)),
                   ['ssl_protocol = TLS', 'ssl_encrypt_backend = 1',
                    'ssl_backend_ca_list_file = %s/ca.crt' % WORK] + opts, port, ['retries = 0'])
        try:
            ok = b'node=%d' % port in get('/', timeout=10)
        except Exception:
            ok = False
        if ok and expect:
            try:
                ok = len(get('/big/5000000', timeout=30)) == 5000000
            except Exception:
                ok = False
        b.stop()
        check('backend TLS: %s %s' % (name, 'accepted' if expect else 'rejected'), ok == expect)


def main():
    if not os.access(SERVER, os.X_OK):
        print('Server binary not found: %s' % SERVER)
        return 2
    make_certs()
    start_backend(PLAIN_PORT)
    start_backend(TLS_PORT, 'back.crt', 'back.key')
    start_backend(SELF_PORT, 'self.crt', 'self.key')
    for t in (test_frontend, test_old_protocol_setting, test_handshake_timeout, test_backend_verify):
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
