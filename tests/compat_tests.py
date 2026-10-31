#!/usr/bin/env python3
# DRLB 2.0 compatibility tests
#
# Checks that are not in the 1.60 regression suites: stats and log
# files, log rotation, config file quirks, signals, connection limits,
# throttling, assigned rules without fail over, listen_ip_addr, the
# default config file, and the drlb_ssl_server program name. Most checks
# also pass with the 1.60 binaries; the ones marked "2.0" are new.
#
# Usage: python3 tests/compat_tests.py [path to drlb_server]
# Needs only Python 3 and the server binary. Uses ports 18200-18299.

import concurrent.futures
import http.client
import http.server
import os
import re
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
LB_PORT = 18200
BACKEND_PORTS = [18211, 18212]
WORK = tempfile.mkdtemp(prefix='drlb_compat_tests_')
results = []


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        if self.path.startswith('/slow/'):
            time.sleep(float(self.path[6:]))
        body = ('node=%d\n' % self.server.server_address[1]).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 512


def start_backend(port):
    srv = ThreadedServer(('127.0.0.1', port), Backend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def write_file(name, text):
    path = os.path.join(WORK, name)
    with open(path, 'w', newline='') as f:
        f.write(text)
    return path


def config(name, server_opts, nodes=None, raw=None):
    if raw is not None:
        return write_file(name + '.cfg', raw)
    lines = ['[LBSERVER]', 'port = %d' % LB_PORT, 'enable_logging = 1', 'log_level = 1',
             'logfile_name = %s/%s.log' % (WORK, name)] + server_opts
    for i, port in enumerate(nodes or BACKEND_PORTS):
        lines += ['[LBNODE]', 'node_name = node%d' % (i + 1), 'hostname = 127.0.0.1', 'port_number = %d' % port]
    return write_file(name + '.cfg', '\n'.join(lines) + '\n')


class LB:
    def __init__(self, name, cfg_path, binary=None, wait=True):
        self.name = name
        self.out = open(os.path.join(WORK, name + '.out'), 'w')
        self.proc = subprocess.Popen([binary or SERVER, '--config-file=' + cfg_path],
                                     stdout=self.out, stderr=subprocess.STDOUT)
        self.started = False
        if not wait:
            return
        for _ in range(50):
            if self.proc.poll() is not None:
                return
            try:
                socket.create_connection(('127.0.0.1', LB_PORT), timeout=0.2).close()
                self.started = True
                return
            except OSError:
                time.sleep(0.1)

    def stop(self, timeout=30):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        try:
            rc = self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            rc = 'killed'
        self.out.close()
        return rc

    def output(self):
        with open(self.out.name) as f:
            return f.read()


def read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ''


def get(path='/', timeout=10, host='127.0.0.1'):
    c = http.client.HTTPConnection(host, LB_PORT, timeout=timeout)
    c.request('GET', path)
    body = c.getresponse().read()
    c.close()
    return body


def check(name, ok, detail=''):
    results.append((name, ok, detail))
    print('%-4s %s %s' % ('PASS' if ok else 'FAIL', name, detail))


def test_stats_file():
    stats = os.path.join(WORK, 'stats.log')
    lb = LB('stats', config('stats', ['enable_stats = 1', 'stats_min = 0', 'stats_secs = 2',
                                      'stats_file_name = %s' % stats]))
    for _ in range(10):
        get()
    time.sleep(2.5)
    rc = lb.stop()
    text = read(stats)
    totals = [int(x) for x in re.findall(r'Total runtime connections: (\d+)', text)]
    nodes = re.findall(r'Total Runtime Connections to node\d: (\d+)', text)
    ok = ('BEGIN drlb_server stats' in text and 'END drlb_server stats' in text and
          'Uptime:' in text and totals and max(totals) >= 10 and len(nodes) >= 2)
    check('stats report written with connection counts', ok and rc == 0,
          'totals=%s nodes=%s' % (totals[-1:] if totals else None, nodes[-2:]))


def test_log_rotation():
    log = os.path.join(WORK, 'rot.log')
    lb = LB('rot', config('rot', ['max_log_size = 2000', 'num_logs_to_keep = 2', 'log_level = 2']))
    for _ in range(60):
        get()
    time.sleep(1.5)
    lb.stop()
    rotated = sorted(os.path.basename(p) for p in os.listdir(WORK) if p.startswith('rot.log.'))
    check('log file rotates and keeps num_logs_to_keep files', rotated == ['rot.log.1', 'rot.log.2'],
          str(rotated))
    check('log has the 1.60 line format', re.search(r'^[A-Z][a-z]{2} [ 0-9]\d \d\d:\d\d:\d\d drlb_server: ',
                                                     read(log), re.M) is not None)


def test_config_quirks():
    # [SSLCONFIG]-free config with CRLF line endings, upper case names,
    # tabs, inline comments, a % weight and ; comments
    raw = ('; comment line\r\n'
           '[LBSERVER]\r\n'
           'PORT = %d   # inline comment\r\n'
           'Scheme\t=\tLB_RR\r\n'
           'enable_logging = yes\r\n'
           'logfile_name = %s/quirks.log\r\n'
           '[LBNODE]\r\n'
           'node_name = node1\r\nhostname = 127.0.0.1\r\nport_number = %d\r\nweight = 75%%\r\n'
           '[ LBNODE ]\r\n'
           'node_name = node2\r\nhostname = 127.0.0.1\r\nport_number = %d\r\nweight = 25%%\r\n'
           % (LB_PORT, WORK, BACKEND_PORTS[0], BACKEND_PORTS[1]))
    path = config('quirks', None, raw=raw)
    p = subprocess.run([SERVER, '--check-config', '--config-file=' + path],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    weights = re.findall(r'LB node weight (\d+)', p.stdout)
    lb = LB('quirks', path)
    time.sleep(1)  # Let the startup probe connection finish
    nodes = {}
    for _ in range(40):
        try:
            n = int(get().split(b'node=')[1])
            nodes[n] = nodes.get(n, 0) + 1
        except Exception:
            pass
    lb.stop()
    check('CRLF, case, tabs, comments and % weights parse', lb.started and nodes == {
          BACKEND_PORTS[0]: 20, BACKEND_PORTS[1]: 20} and weights == ['75', '25'],
          'nodes=%s weights=%s' % (nodes, weights))


def test_debug_signals():
    lb = LB('sig', config('sig', []))
    for s in (signal.SIGUSR2, signal.SIGUSR2, signal.SIGUSR1, signal.SIGHUP):
        lb.proc.send_signal(s)
        time.sleep(0.3)
    get()
    alive = lb.proc.poll() is None
    time.sleep(1.5)
    rc = lb.stop()
    log = read(os.path.join(WORK, 'sig.log'))
    ok = ('Debug mode has been enabled' in log and 'Debug level increased to 3' in log and
          'lowering debug level' in log and 'Process received hangup' in log)
    check('SIGUSR1/SIGUSR2 change the debug level, SIGHUP is logged', ok and alive and rc == 0)


def test_max_connections():
    lb = LB('maxconn', config('maxconn', ['max_connections = 3']))
    time.sleep(1)  # Let the startup probe connection finish
    socks = []
    for _ in range(2):
        s = socket.create_connection(('127.0.0.1', LB_PORT))
        socks.append(s)
    time.sleep(0.5)
    denied = False
    try:
        get(timeout=3)
    except Exception:
        denied = True
    for s in socks:
        s.close()
    time.sleep(1.5)
    after = get()
    lb.stop()
    check('max_connections denies the extra connection', denied and b'node=' in after,
          'denied=%s' % denied)


def test_throttling():
    lb = LB('throttle', config('throttle', ['enable_throttling = 1', 'throttle_every_connections = 1',
                                            'throttle_wait_secs = 1']))
    start = time.time()
    get()
    elapsed = time.time() - start
    lb.stop()
    check('throttling holds a connection for throttle_wait_secs', 0.9 <= elapsed < 3, '%.2f s' % elapsed)


def test_assigned_none():
    rules = write_file('rules_none.cfg', 'route ^10\\.9\\.9\\.9$ node1\n')
    lb = LB('anone', config('anone', ['scheme = LB_ASSIGNED', 'rules_config_file = %s' % rules,
                                      'resolve_assigned_hostnames = 0', 'assigned_default = LB_NONE']))
    refused = False
    try:
        get(timeout=3)
    except Exception:
        refused = True
    lb.stop()
    check('LB_ASSIGNED with LB_NONE drops clients with no rule', refused)


def test_listen_ip():
    lb = LB('listen', config('listen', ['listen_ip_addr = 127.0.0.1']))
    ok = b'node=' in get()
    other = None
    try:
        addrs = [a for a in socket.gethostbyname_ex(socket.gethostname())[2] if not a.startswith('127.')]
        if addrs:
            try:
                socket.create_connection((addrs[0], LB_PORT), timeout=1).close()
                other = 'reachable'
            except OSError:
                other = 'refused'
    except OSError:
        pass
    lb.stop()
    check('listen_ip_addr binds one address', ok and other != 'reachable', 'other interface: %s' % other)


def test_parallel_load():
    lb = LB('par', config('par', ['log_level = 0']))
    def one(_):
        try:
            return b'node=' in get('/slow/0.2', timeout=20)
        except Exception:
            return False
    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
        ok = sum(ex.map(one, range(1000)))
    elapsed = time.time() - start
    rc = lb.stop()
    check('1000 requests with 200 in parallel', ok == 1000 and rc == 0,
          '%d ok in %.1f s' % (ok, elapsed))


def test_default_config():
    path = os.path.join(WORK, 'new_default.cfg')
    p = subprocess.run([SERVER, '--config-file=' + path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    built = p.returncode == 2 and os.path.exists(path)
    p2 = subprocess.run([SERVER, '--check-config', '--config-file=' + path],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check('missing config builds a default that passes --check-config', built and p2.returncode == 0,
          'build rc=%d check rc=%d' % (p.returncode, p2.returncode))


def test_ssl_name_needs_sslconfig():
    # 2.0: drlb_ssl_server is a link to drlb_server
    link = os.path.join(WORK, 'drlb_ssl_server')
    os.symlink(SERVER, link)
    lb = LB('sslname', config('sslname', []), binary=link)
    out = lb.output()
    rc = lb.stop()
    check('2.0: drlb_ssl_server refuses a config without [SSLCONFIG]',
          not lb.started and 'needs an [SSLCONFIG] section' in out + read(os.path.join(WORK, 'sslname.log')),
          'rc=%s' % rc)


def test_bad_args():
    p = subprocess.run([SERVER, '--no-such-option', '--config-file=/dev/null'],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p2 = subprocess.run([SERVER, '--version'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check('unknown -- argument is an error, --version prints the version',
          p.returncode == 1 and b'version' in p2.stdout, 'rc=%d' % p.returncode)


def main():
    if not os.access(SERVER, os.X_OK):
        print('Server binary not found: %s' % SERVER)
        return 2
    for p in BACKEND_PORTS:
        start_backend(p)
    tests = [test_stats_file, test_log_rotation, test_config_quirks, test_debug_signals,
             test_max_connections, test_throttling, test_assigned_none, test_listen_ip,
             test_parallel_load, test_default_config, test_bad_args, test_ssl_name_needs_sslconfig]
    if len(sys.argv) > 2 and sys.argv[2] == '--legacy':
        tests.remove(test_ssl_name_needs_sslconfig)
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
