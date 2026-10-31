#!/usr/bin/env python3
# DRLB regression tests
#
# Starts local HTTP back ends and drlb_server with generated configs on
# 127.0.0.1, then checks load balancing, fail over, HTTP forwarding,
# large transfers, timeouts, resource exhaustion and shutdown.
#
# Usage: python3 tests/drlb_tests.py [path to drlb_server]
# Needs only Python 3 and the server binary. Uses ports 18000-18099.

import hashlib
import http.client
import http.server
import os
import resource
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, '..', 'drlb_server'))
LB_PORT = 18000
BACKEND_PORTS = [18011, 18012, 18013]
WORK = tempfile.mkdtemp(prefix='drlb_tests_')
results = []


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def reply(self, body):
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            data = b''
            while True:
                size = int(self.rfile.readline().strip(), 16)
                if size == 0:
                    self.rfile.readline()
                    return data
                data += self.rfile.read(size)
                self.rfile.readline()
        n = int(self.headers.get('Content-Length', 0))
        return self.rfile.read(n) if n else b''

    def do_GET(self):
        if self.path.startswith('/big/'):
            self.reply(b'x' * int(self.path[5:]))
            return
        xff = '|'.join(self.headers.get_all('X-Forwarded-For') or [])
        self.reply(('node=%d xff=%s\n' % (self.server.server_address[1], xff)).encode())

    def do_POST(self):
        body = self.read_body()
        xff = '|'.join(self.headers.get_all('X-Forwarded-For') or [])
        self.reply(('node=%d sha=%s xff=%s\n' % (self.server.server_address[1],
                                                 hashlib.sha256(body).hexdigest(), xff)).encode())

    def log_message(self, *args):
        pass


class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 512


backends = {}


def start_backend(port):
    srv = ThreadedServer(('127.0.0.1', port), Backend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    backends[port] = srv


def stop_backend(port):
    srv = backends.pop(port)
    srv.shutdown()
    srv.server_close()


def write_config(name, server_opts, nodes):
    lines = ['[LBSERVER]', 'port = %d' % LB_PORT, 'enable_logging = 1', 'log_level = 1',
             'logfile_name = %s/%s.log' % (WORK, name)]
    lines += server_opts
    for i, (port, extra) in enumerate(nodes):
        lines += ['[LBNODE]', 'node_name = node%d' % (i + 1), 'hostname = 127.0.0.1',
                  'port_number = %d' % port] + extra
    path = os.path.join(WORK, name + '.cfg')
    with open(path, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    return path


class LB:
    def __init__(self, name, server_opts, nodes, nofile=None):
        self.name = name
        cfg = write_config(name, server_opts, nodes)
        def limits():
            if nofile:
                resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
        self.out = open(os.path.join(WORK, name + '.out'), 'w')
        self.proc = subprocess.Popen([SERVER, '--config-file=' + cfg], stdout=self.out,
                                     stderr=subprocess.STDOUT, preexec_fn=limits)
        for _ in range(50):
            try:
                socket.create_connection(('127.0.0.1', LB_PORT), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError('%s did not start, see %s' % (name, self.out.name))

    def alive(self):
        return self.proc.poll() is None

    def stop(self, timeout=30):
        if self.alive():
            self.proc.send_signal(signal.SIGTERM)
        try:
            rc = self.proc.wait(timeout)
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


def get(path, headers=None, timeout=10):
    c = http.client.HTTPConnection('127.0.0.1', LB_PORT, timeout=timeout)
    c.request('GET', path, headers=headers or {})
    r = c.getresponse()
    body = r.read()
    c.close()
    return body


def node_of(body):
    return int(body.split(b'node=')[1].split()[0])


def check(name, ok, detail=''):
    results.append((name, ok, detail))
    print('%-4s %s %s' % ('PASS' if ok else 'FAIL', name, detail))


def test_round_robin():
    lb = LB('rr', ['scheme = LB_RR'], [(p, []) for p in BACKEND_PORTS])
    counts = {}
    for _ in range(300):
        n = node_of(get('/'))
        counts[n] = counts.get(n, 0) + 1
    rc = lb.stop()
    check('round robin spreads 300 requests over 3 nodes',
          len(counts) == 3 and max(counts.values()) - min(counts.values()) <= 3, str(counts))
    check('round robin server exits cleanly', rc == 0, 'exit %s' % rc)


def test_retries_zero():
    # B12: with retries = 0 every other connection used to fail
    lb = LB('rr0', ['scheme = LB_RR', 'retries = 0'], [(BACKEND_PORTS[0], [])])
    ok = 0
    for _ in range(20):
        try:
            if node_of(get('/')) == BACKEND_PORTS[0]:
                ok += 1
        except Exception:
            pass
    lb.stop()
    check('single node with retries = 0 serves every request', ok == 20, '%d/20' % ok)


def test_failover():
    dead = 18019  # nothing listens here
    lb = LB('fo', ['scheme = LB_RR', 'retries = 1', 'retry_wait = 0'],
            [(dead, []), (BACKEND_PORTS[0], []), (BACKEND_PORTS[1], [])])
    nodes = set()
    errors = 0
    for _ in range(30):
        try:
            nodes.add(node_of(get('/')))
        except Exception:
            errors += 1
    lb.stop()
    check('dead node is skipped', errors == 0 and dead not in nodes and len(nodes) == 2,
          'errors=%d nodes=%s' % (errors, sorted(nodes)))


def test_weighted_and_distributed():
    nodes = [(BACKEND_PORTS[0], ['weight = 3']), (BACKEND_PORTS[1], ['weight = 1'])]
    for scheme in ('LB_WEIGHTED', 'LB_DISTRIB'):
        if scheme == 'LB_DISTRIB':
            nodes = [(BACKEND_PORTS[0], ['weight = 75']), (BACKEND_PORTS[1], ['weight = 25'])]
        lb = LB(scheme.lower(), ['scheme = %s' % scheme], nodes)
        # Hold connections open so the connection counts build up
        socks = []
        for _ in range(40):
            s = socket.create_connection(('127.0.0.1', LB_PORT))
            s.sendall(b'GET / HTTP/1.1\r\nHost: x\r\n\r\n')
            socks.append(s)
            time.sleep(0.01)
        counts = {}
        for s in socks:
            data = b''
            while b'\n' not in data.split(b'\r\n\r\n', 1)[-1] or b'\r\n\r\n' not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            n = node_of(data)
            counts[n] = counts.get(n, 0) + 1
            s.close()
        lb.stop()
        a, b = counts.get(BACKEND_PORTS[0], 0), counts.get(BACKEND_PORTS[1], 0)
        check('%s sends most connections to the heavier node' % scheme, a > b and b > 0,
              str(counts))


def test_http_forwarding():
    lb = LB('xff', ['scheme = LB_RR', 'enable_http_forwarding = 1'], [(BACKEND_PORTS[0], [])])
    body = get('/', {'X-Forwarded-For': '6.6.6.6'})
    check('client X-Forwarded-For is replaced', b'xff=127.0.0.1\n' in body, body.decode().strip())
    # Keep alive: two requests on one connection both get the header
    c = http.client.HTTPConnection('127.0.0.1', LB_PORT, timeout=10)
    xffs = []
    for _ in range(2):
        c.request('GET', '/')
        xffs.append(c.getresponse().read())
    c.close()
    check('every keep alive request gets X-Forwarded-For', all(b'xff=127.0.0.1\n' in x for x in xffs))
    # Request bodies, plain and chunked, arrive unchanged
    payload = os.urandom(300000)
    c = http.client.HTTPConnection('127.0.0.1', LB_PORT, timeout=10)
    c.request('POST', '/p', body=payload)
    r1 = c.getresponse().read()
    c.request('POST', '/c', body=iter([payload[:1000], payload[1000:]]), encode_chunked=True,
              headers={'Transfer-Encoding': 'chunked'})
    r2 = c.getresponse().read()
    c.request('GET', '/', headers={'X-Forwarded-For': '7.7.7.7'})
    r3 = c.getresponse().read()
    c.close()
    sha = hashlib.sha256(payload).hexdigest().encode()
    check('POST body passes unchanged', sha in r1)
    check('chunked POST body passes unchanged', sha in r2)
    check('request after a chunked body is still rewritten', b'xff=127.0.0.1\n' in r3, r3.decode().strip())
    lb.stop()


def test_large_transfer():
    for cache in ('1', '0'):
        lb = LB('big%s' % cache, ['use_buffer_cache = %s' % cache], [(BACKEND_PORTS[0], [])])
        size = 50 * 1024 * 1024
        start = time.time()
        body = get('/big/%d' % size, timeout=60)
        secs = time.time() - start
        lb.stop()
        check('50 MB response with use_buffer_cache = %s' % cache, len(body) == size,
              '%.0f MB/s' % (size / secs / 1e6))


def test_idle_timeout_and_cpu():
    lb = LB('idle', ['use_timeout = 1', 'timeout_secs = 3'], [(BACKEND_PORTS[0], [])])
    socks = [socket.create_connection(('127.0.0.1', LB_PORT)) for _ in range(200)]
    time.sleep(1)
    t0 = os.times()
    with open('/proc/%d/stat' % lb.proc.pid) as f:
        cpu0 = sum(int(x) for x in f.read().split()[13:15])
    time.sleep(1.5)
    with open('/proc/%d/stat' % lb.proc.pid) as f:
        cpu1 = sum(int(x) for x in f.read().split()[13:15])
    ticks = os.sysconf('SC_CLK_TCK')
    cpu_pct = (cpu1 - cpu0) / ticks / 1.5 * 100
    check('200 idle connections use almost no CPU', cpu_pct < 5, '%.1f%% CPU' % cpu_pct)
    time.sleep(3)
    closed = 0
    for s in socks:
        s.settimeout(2)
        try:
            if s.recv(1) == b'':
                closed += 1
        except OSError:
            closed += 1
        s.close()
    lb.stop()
    check('idle connections close after timeout_secs', closed == 200, '%d/200 closed' % closed)


def test_fd_exhaustion():
    # S2: running out of file descriptors must not stop the server
    lb = LB('fd', ['use_timeout = 1', 'timeout_secs = 20'], [(BACKEND_PORTS[0], [])], nofile=128)
    socks = []
    for _ in range(300):
        try:
            socks.append(socket.create_connection(('127.0.0.1', LB_PORT), timeout=1))
        except OSError:
            pass
    time.sleep(2)
    for s in socks:
        s.close()
    time.sleep(2)
    try:
        ok = node_of(get('/', timeout=10)) == BACKEND_PORTS[0]
    except Exception:
        ok = False
    alive = lb.alive()
    lb.stop()
    check('server survives running out of file descriptors', alive and ok,
          'alive=%s request_ok=%s' % (alive, ok))


def test_shutdown_with_connections():
    # S9: SIGTERM with open connections used to crash the server
    lb = LB('stop', ['use_timeout = 1', 'timeout_secs = 60'], [(BACKEND_PORTS[0], [])])
    socks = [socket.create_connection(('127.0.0.1', LB_PORT)) for _ in range(300)]
    time.sleep(1)
    start = time.time()
    rc = lb.stop()
    for s in socks:
        s.close()
    check('SIGTERM with 300 open connections exits cleanly', rc == 0,
          'exit %s in %.1f s' % (rc, time.time() - start))


def test_assigned_rules():
    rules = os.path.join(WORK, 'rules.cfg')
    with open(rules, 'w') as f:
        f.write('route ^127\\.0\\.0\\.1$ node2\n')
    lb = LB('assigned', ['scheme = LB_ASSIGNED', 'rules_config_file = %s' % rules,
                         'resolve_assigned_hostnames = 0', 'assigned_default = LB_RR'],
            [(BACKEND_PORTS[0], []), (BACKEND_PORTS[1], [])])
    nodes = set(node_of(get('/')) for _ in range(10))
    lb.stop()
    check('assigned rule sends 127.0.0.1 to node2', nodes == {BACKEND_PORTS[1]}, str(sorted(nodes)))


def main():
    if not os.access(SERVER, os.X_OK):
        print('Server binary not found: %s' % SERVER)
        return 2
    for p in BACKEND_PORTS:
        start_backend(p)
    tests = [test_round_robin, test_retries_zero, test_failover, test_weighted_and_distributed,
             test_assigned_rules, test_http_forwarding, test_large_transfer,
             test_idle_timeout_and_cpu, test_fd_exhaustion, test_shutdown_with_connections]
    for t in tests:
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
