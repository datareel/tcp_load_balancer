#!/usr/bin/env python3
# DRLB 2.2 port multiplexer tests (mode = MUX)
#
#   python3 tests/mux_tests.py /path/to/drlb_server
#
# Two DRLB processes on this host: A connects the tunnel to B (mutual
# TLS with a test CA). TCP and UDP channels go from A to B and one TCP
# channel from B back to A, over the same tunnel. Needs the openssl
# command. Uses ports 18300-18399.

import os
import random
import re
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
WORK = tempfile.mkdtemp(prefix='drlb_mux_tests_')
results = []

TUN_PORT = 18300      # B accepts tunnels here
A_ECHO = 18301        # A: channel echo (TCP) -> B -> echo server
A_UDP = 18302         # A: channel udpecho (UDP) -> B -> UDP echo server
A_LB = 18303          # A: channel lb (TCP) -> B -> node1/node2 round robin
A_SINK = 18304        # A: channel sink (TCP) -> B -> server that never reads
A_DEAD = 18305        # A: channel dead (TCP) -> B -> nothing listening
A_EOF = 18306         # A: channel eofecho -> B -> replies after the client half closes
A_WLB = 18307         # A: channel wlb -> B -> node1 weight 3, node2 weight 1
B_BACK = 18310        # B: channel back (TCP) -> A -> echo server (reverse direction)
ECHO = 18320
UDP_ECHO = 18321
NODE1 = 18322
NODE2 = 18323
SINK = 18324
DEAD = 18325
EOF_ECHO = 18326
A_ECHO_REV = 18327    # Echo server on A's side, for channel back
PLAIN_TUN = 18330     # Plain tunnel instance for the protocol checks
P_ECHO = 18331


def check(name, ok, detail=''):
    results.append(ok)
    print('%s %s %s' % ('PASS' if ok else 'FAIL', name, detail if not ok else ''), flush=True)


def sh(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=WORK)


def make_certs():
    for ca in ('ca', 'badca'):
        sh('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', ca + '.key', '-out', ca + '.crt',
           '-days', '2', '-subj', '/CN=DRLB MUX Test ' + ca)
    for name, ca in (('drlb-a', 'ca'), ('drlb-b', 'ca'), ('rogue', 'badca'), ('drlb-c', 'ca')):
        sh('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', name + '.key', '-out', name + '.csr',
           '-subj', '/CN=' + name)
        with open(os.path.join(WORK, name + '.ext'), 'w') as f:
            f.write('subjectAltName=DNS:%s,IP:127.0.0.1\n' % name)
        sh('openssl', 'x509', '-req', '-in', name + '.csr', '-CA', ca + '.crt', '-CAkey', ca + '.key',
           '-CAcreateserial', '-out', name + '.crt', '-days', '2', '-extfile', name + '.ext')


# ---------------------------------------------------------------------
# Test servers

class TS(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    request_queue_size = 1024
    daemon_threads = True


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                d = self.request.recv(65536)
                if not d:
                    break
                self.request.sendall(d)
        except OSError:
            pass


def tagged(tag):
    class Tagged(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                self.request.recv(100)
                self.request.sendall(tag.encode())
            except OSError:
                pass
    return Tagged


class Sink(socketserver.BaseRequestHandler):
    def handle(self):
        time.sleep(30)  # Never reads


class EofEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data = b''
        while True:
            d = self.request.recv(65536)
            if not d:
                break
            data += d
        self.request.sendall(b'GOT %d' % len(data))


def tcp_server(port, handler):
    srv = TS(('127.0.0.1', port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def udp_echo(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', port))

    def run():
        while True:
            d, a = s.recvfrom(65536)
            s.sendto(d, a)
    threading.Thread(target=run, daemon=True).start()


# ---------------------------------------------------------------------
# DRLB processes

def write_file(name, text):
    path = os.path.join(WORK, name)
    with open(path, 'w') as f:
        f.write(text)
    return path


def ssl_section(name, verify_client=True, client_ca='ca.crt'):
    s = ['[SSLCONFIG]',
         'ssl_key_file = %s/%s.key' % (WORK, name),
         'ssl_cert_file = %s/%s.crt' % (WORK, name),
         'ssl_backend_ca_list_file = %s/ca.crt' % WORK,
         'ssl_client_ca_list_file = %s/%s' % (WORK, client_ca),
         'ssl_crypto_policy_file = none']
    if not verify_client:
        s.append('ssl_verify_client = 0')
    return s


def lbserver(name, extra):
    return ['[LBSERVER]', 'mode = MUX', 'service_name = ' + name, 'enable_logging = 1', 'log_level = 2',
            'logfile_name = %s/%s.log' % (WORK, name), 'enable_stats = 1', 'stats_min = 0', 'stats_secs = 2',
            'stats_file_name = %s/%s_stats.log' % (WORK, name), 'mux_keepalive_secs = 2', 'mux_retry_secs = 1',
            'connect_timeout_secs = 2', 'retries = 0', 'mux_peer_name = ' + name] + extra


def port(channel, p, proto='TCP', peer=None):
    s = ['[MUXPORT]', 'channel = ' + channel, 'protocol = ' + proto, 'listen_ip_addr = 127.0.0.1', 'port = %d' % p]
    if peer:
        s.append('peer = ' + peer)
    return s


def dest(channel, p=None, proto='TCP', nodes=None, scheme=None):
    s = ['[MUXDEST]', 'channel = ' + channel, 'protocol = ' + proto]
    if nodes:
        s += ['nodes = ' + nodes]
        if scheme:
            s.append('scheme = ' + scheme)
    else:
        s += ['hostname = 127.0.0.1', 'port = %d' % p]
    return s


def node(name, p, weight=None):
    s = ['[LBNODE]', 'node_name = ' + name, 'hostname = 127.0.0.1', 'port_number = %d' % p]
    if weight:
        s.append('weight = %d' % weight)
    return s


def config_a(extra=None, tunnel_port=TUN_PORT, name='drlb-a', ssl_name=None, connections=1):
    lines = lbserver(name, extra or [])
    lines += ['[MUXTUNNEL]', 'name = to-b', 'remote_host = 127.0.0.1', 'remote_port = %d' % tunnel_port,
              'ssl_hostname = drlb-b', 'tunnel_connections = %d' % connections]
    lines += port('echo', A_ECHO) + port('udpecho', A_UDP, 'UDP') + port('lb', A_LB) + port('sink', A_SINK)
    lines += port('dead', A_DEAD) + port('eofecho', A_EOF) + port('wlb', A_WLB)
    lines += dest('back', A_ECHO_REV)
    lines += ssl_section(ssl_name or name)
    return write_file(name + '.cfg', '\n'.join(lines) + '\n')


def config_b(extra=None):
    lines = lbserver('drlb-b', ['mux_listen = 1', 'port = %d' % TUN_PORT, 'listen_ip_addr = 127.0.0.1',
                                'mux_allowed_peers = drlb-a, drlb-c'] + (extra or []))
    lines += dest('echo', ECHO) + dest('udpecho', UDP_ECHO, 'UDP') + dest('lb', nodes='node1, node2')
    lines += dest('wlb', nodes='node1, node2', scheme='LB_WEIGHTED')
    lines += dest('sink', SINK) + dest('dead', DEAD) + dest('eofecho', EOF_ECHO)
    lines += port('back', B_BACK)
    lines += node('node1', NODE1, 3) + node('node2', NODE2, 1)
    lines += ssl_section('drlb-b')
    return write_file('drlb-b.cfg', '\n'.join(lines) + '\n')


class Proc:
    def __init__(self, name, cfg_path, extra_args=()):
        self.name = name
        self.out = open(os.path.join(WORK, name + '.out'), 'w')
        self.proc = subprocess.Popen([SERVER, '--config-file=' + cfg_path] + list(extra_args),
                                     stdout=self.out, stderr=subprocess.STDOUT)

    def stop(self, sig=signal.SIGTERM, timeout=30):
        if self.proc.poll() is None:
            self.proc.send_signal(sig)
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


def wait_for(fn, secs=10):
    end = time.time() + secs
    while time.time() < end:
        try:
            if fn():
                return True
        except OSError:
            pass
        time.sleep(0.1)
    return False


def roundtrip(p, data, timeout=10):
    s = socket.create_connection(('127.0.0.1', p), timeout=timeout)
    s.sendall(data)
    got = b''
    while len(got) < len(data):
        d = s.recv(65536)
        if not d:
            break
        got += d
    s.close()
    return got


def tunnel_up(p=A_ECHO):
    return wait_for(lambda: roundtrip(p, b'ping', 2) == b'ping', 15)


def check_config(cfg_path):
    r = subprocess.run([SERVER, '--config-file=' + cfg_path, '--check-config'], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
    return r.returncode, r.stdout


# ---------------------------------------------------------------------
# Tests

def test_basic():
    check('A to B TCP echo through the tunnel', tunnel_up())
    data = os.urandom(1000000)
    check('1 MB echo is byte for byte equal', roundtrip(A_ECHO, data, 30) == data)
    check('reverse channel B to A works on the same tunnel', wait_for(lambda: roundtrip(B_BACK, b'back', 2) == b'back'))


def test_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    ok = 0
    for i in range(50):
        msg = b'dgram %d ' % i + os.urandom(random.randint(1, 1400))
        s.sendto(msg, ('127.0.0.1', A_UDP))
        try:
            d, _ = s.recvfrom(65536)
            if d == msg:
                ok += 1
        except socket.timeout:
            pass
    check('UDP datagrams echo with boundaries kept', ok >= 48, '%d of 50' % ok)
    big = os.urandom(60000)
    s.sendto(big, ('127.0.0.1', A_UDP))
    try:
        d, _ = s.recvfrom(65536)
    except socket.timeout:
        d = b''
    check('60000 byte UDP datagram carried whole', d == big)
    flows = []
    for i in range(20):
        f = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        f.settimeout(3)
        f.sendto(b'flow %d' % i, ('127.0.0.1', A_UDP))
        flows.append(f)
    good = 0
    for i, f in enumerate(flows):
        try:
            d, _ = f.recvfrom(100)
            good += d == b'flow %d' % i
        except socket.timeout:
            pass
    check('20 UDP flows each get their own replies', good == 20, '%d of 20' % good)


def test_load_balance():
    seen = []
    for _ in range(20):
        s = socket.create_connection(('127.0.0.1', A_LB), timeout=5)
        s.sendall(b'x')
        seen.append(s.recv(10))
        s.close()
    n1, n2 = seen.count(b'node1'), seen.count(b'node2')
    check('LB_RR channel spreads connections over node1 and node2', n1 >= 8 and n2 >= 8, 'node1 %d node2 %d' % (n1, n2))
    # Weighted: keep 8 connections open at once; node1 (weight 3) gets about 6
    socks = []
    for _ in range(8):
        s = socket.create_connection(('127.0.0.1', A_WLB), timeout=5)
        socks.append(s)
        time.sleep(0.15)
    tags = []
    for s in socks:
        s.sendall(b'x')
        tags.append(s.recv(10))
    for s in socks:
        s.close()
    w1 = tags.count(b'node1')
    check('LB_WEIGHTED channel gives node1 (weight 3) most open connections', 5 <= w1 <= 7, 'node1 %d of 8' % w1)


def test_concurrent():
    errors = []

    def one(i):
        try:
            data = os.urandom(random.randint(1, 200000))
            if roundtrip(A_ECHO, data, 60) != data:
                errors.append(i)
        except OSError as e:
            errors.append('%d %s' % (i, e))
    threads = [threading.Thread(target=one, args=(i,)) for i in range(300)]
    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check('300 concurrent streams echo correctly', not errors, str(errors[:5]))
    print('     300 concurrent streams in %.1f secs' % (time.time() - t0))


def test_throughput():
    size = 64 * 1024 * 1024
    s = socket.create_connection(('127.0.0.1', A_ECHO), timeout=30)
    block = os.urandom(1 << 20)
    got = [0]

    def reader():
        while got[0] < size:
            d = s.recv(1 << 20)
            if not d:
                break
            got[0] += len(d)
    t = threading.Thread(target=reader)
    t0 = time.time()
    t.start()
    for _ in range(size // len(block)):
        s.sendall(block)
    t.join(120)
    secs = time.time() - t0
    s.close()
    mbit = size * 8 / secs / 1e6
    check('64 MB through the tunnel and back', got[0] == size, '%d bytes' % got[0])
    print('     echo throughput %.0f Mbit/s each way (%.1f secs)' % (mbit, secs))


def test_head_of_line():
    # Fill the sink channel: its server never reads, so its stream window
    # fills and only that stream stops
    sink = socket.create_connection(('127.0.0.1', A_SINK), timeout=5)
    sink.setblocking(False)
    sent = 0
    end = time.time() + 3
    while time.time() < end:
        try:
            sent += sink.send(b'x' * 65536)
        except BlockingIOError:
            time.sleep(0.05)
    t0 = time.time()
    ok = roundtrip(A_ECHO, b'still moving', 5) == b'still moving'
    check('echo channel answers while the sink stream is stalled', ok and time.time() - t0 < 2,
          'took %.2f secs, sink took %d bytes' % (time.time() - t0, sent))
    check('a stalled stream is held at its window, not buffered without limit', sent < 16 * 1024 * 1024, '%d bytes' % sent)
    sink.close()


def test_half_close():
    s = socket.create_connection(('127.0.0.1', A_EOF), timeout=10)
    s.sendall(b'a' * 100000)
    s.shutdown(socket.SHUT_WR)
    got = b''
    while True:
        d = s.recv(1000)
        if not d:
            break
        got += d
    s.close()
    check('half close: the server sees EOF and its reply comes back', got == b'GOT 100000', repr(got))


def test_dead_destination():
    s = socket.create_connection(('127.0.0.1', A_DEAD), timeout=10)
    t0 = time.time()
    try:
        s.sendall(b'hello')
        d = s.recv(10)
    except OSError:
        d = b''
    s.close()
    check('channel with a dead destination closes the client', d == b'' and time.time() - t0 < 8)


def test_stats(a, b):
    time.sleep(3)
    sa = read(os.path.join(WORK, 'drlb-a_stats.log'))
    sb = read(os.path.join(WORK, 'drlb-b_stats.log'))
    check('stats show the tunnel up with round trip time', re.search(r'Tunnel .*: up .*round trip', sa) is not None)
    check('stats show per port and per channel counters', 'Port echo tcp' in sa and 'Channel echo tcp' in sb and
          'Channel dead tcp' in sb and 'connect failures' in sb)


def test_reconnect(b_cfg):
    global proc_b
    rc = proc_b.stop()
    check('B stops on SIGTERM with exit 0', rc == 0, str(rc))
    check('A logs the GOAWAY from B', wait_for(lambda: 'peer closed the tunnel: server stopping' in read(os.path.join(WORK, 'drlb-a.log')), 5))
    # With no tunnel up A holds a new client for mux_hold_secs (3 here), then closes it
    t0 = time.time()
    try:
        d = roundtrip(A_ECHO, b'down?', 10)
    except OSError:
        d = b''
    took = time.time() - t0
    check('with the tunnel down A holds a new client, then closes it after mux_hold_secs', d == b'' and 2.5 < took < 6, '%.1f secs' % took)
    check('A logs the held client it closed', wait_for(lambda: 'No tunnel up for this channel within mux_hold_secs' in read(os.path.join(WORK, 'drlb-a.log')), 3))
    # A client held while B starts again goes through once the tunnel is up
    got = {}
    def held_client():
        try:
            got['d'] = roundtrip(A_ECHO, b'held until up', 15)
        except OSError as e:
            got['d'] = repr(e).encode()
    th = threading.Thread(target=held_client)
    th.start()
    time.sleep(0.5)
    proc_b = Proc('drlb-b-2', b_cfg)
    th.join(20)
    check('a client held while the tunnel is down goes through when it comes up', got.get('d') == b'held until up', repr(got.get('d')))
    check('A reconnects when B is back', tunnel_up())


def config_peer(name, cert, peer_name):
    lines = lbserver(name, [])
    lines = [l if not l.startswith('mux_peer_name') else 'mux_peer_name = ' + peer_name for l in lines]
    lines += ['[MUXTUNNEL]', 'remote_host = 127.0.0.1', 'remote_port = %d' % TUN_PORT, 'ssl_hostname = drlb-b']
    lines += dest('back', A_ECHO_REV) + ssl_section(cert)
    return write_file(name + '.cfg', '\n'.join(lines) + '\n')


def test_tls_checks():
    # A client certificate from another CA is refused
    p = Proc('rogue', config_peer('rogue', 'rogue', 'rogue'))
    time.sleep(3)
    p.stop()
    log_b = read(os.path.join(WORK, 'drlb-b.log'))
    check('tunnel with a client certificate from another CA is refused', 'refused: TLS handshake failed' in log_b, log_b[-400:])
    # drlb-c has a certificate from the right CA but says it is drlb-x
    p = Proc('drlb-c', config_peer('drlb-c', 'drlb-c', 'drlb-x'))
    time.sleep(3)
    p.stop()
    log_b = read(os.path.join(WORK, 'drlb-b.log'))
    check('peer name not in mux_allowed_peers is refused', 'drlb-x is not in mux_allowed_peers' in log_b)
    check('the refused peer logs why', 'refused, peer drlb-x is not in mux_allowed_peers' in read(os.path.join(WORK, 'drlb-c.log')))
    # drlb-c says it is drlb-a: allowed name, but not in its certificate
    p = Proc('drlb-c3', config_peer('drlb-c3', 'drlb-c', 'drlb-a'))
    time.sleep(3)
    p.stop()
    log_b = read(os.path.join(WORK, 'drlb-b.log'))
    check('peer name that is not in the peer certificate is refused', 'drlb-a is not in its certificate' in log_b)


def test_config_checks():
    rc, out = check_config(config_a())
    check('--check-config passes for the A config', rc == 0 and 'DRLB config file checks good' in out, out[-300:])
    raw = '\n'.join(lbserver('x', ['mux_listen = 1', 'port = 18399']) + dest('echo', ECHO)) + '\n'
    rc, out = check_config(write_file('plain_no.cfg', raw))
    check('no [SSLCONFIG] and no mux_allow_plain fails the check', rc != 0 and 'needs an [SSLCONFIG]' in out)
    raw = '\n'.join(lbserver('x', ['mux_listen = 1', 'port = 18399', 'mux_allow_plain = 1']) + dest('echo', ECHO)) + '\n'
    rc, out = check_config(write_file('plain_yes.cfg', raw))
    check('mux_allow_plain = 1 passes with a warning', rc == 0 and 'NOT encrypted' in out)
    raw = '\n'.join(lbserver('x', ['mux_listen = 1', 'mux_allow_plain = 1']) + dest('echo', ECHO) + dest('echo', ECHO) +
                    dest('lb', nodes='nope') + port('p', 18398) + port('q', 18398)) + '\n'
    rc, out = check_config(write_file('bad.cfg', raw))
    check('duplicate channel, unknown node and port clash are config errors',
          rc != 0 and 'more than one [MUXDEST]' in out and 'has no [LBNODE]' in out and 'both use' in out, out[-500:])
    raw = '\n'.join(lbserver('x', ['mux_allow_plain = 1']) + port('p', 18398)) + '\n'
    rc, out = check_config(write_file('notunnel.cfg', raw))
    check('[MUXPORT] without a tunnel is a config error', rc != 0)


def test_protocol_errors():
    raw = '\n'.join(lbserver('plain-b', ['mux_listen = 1', 'port = %d' % PLAIN_TUN, 'listen_ip_addr = 127.0.0.1',
                                         'mux_allow_plain = 1']) + dest('echo', ECHO)) + '\n'
    p = Proc('plain-b', write_file('plain-b.cfg', raw))
    wait_for(lambda: socket.create_connection(('127.0.0.1', PLAIN_TUN), timeout=1).close() or True)
    out = p.output()
    check('plain tunnel prints the not encrypted warning at start', 'NOT encrypted' in out + read(os.path.join(WORK, 'plain-b.log')))
    cases = [
        ('garbage', os.urandom(100)),
        ('frame before HELLO', bytes([1, 5, 0, 0, 0, 0, 0, 1, 0, 3, 0, 0]) + b'abc'),
        ('bad version', bytes([9, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
        ('truncated huge frame', bytes([1, 1, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0]) + b'x' * 100),
    ]
    for name, data in cases:
        try:
            s = socket.create_connection(('127.0.0.1', PLAIN_TUN), timeout=3)
            s.sendall(data)
            s.settimeout(3)
            try:
                while s.recv(65536):
                    pass
            except socket.timeout:
                pass
            s.close()
        except OSError:
            pass
    # A HELLO then DATA past the window and a bad OPEN
    hello = b'DRMX 1\npeer fuzz\nwindow 65536\n'
    s = socket.create_connection(('127.0.0.1', PLAIN_TUN), timeout=3)
    s.sendall(bytes([1, 1, 0, 0, 0, 0, 0, 0]) + len(hello).to_bytes(2, 'big') + b'\0\0' + hello)
    s.sendall(bytes([1, 2, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0]))  # OPEN stream 1 channel 1 (echo)
    for _ in range(6):  # 6 x 65535 > 262144 window
        s.sendall(bytes([1, 5, 0, 0, 0, 0, 0, 1, 255, 255, 0, 0]) + b'z' * 65535)
    s.settimeout(5)
    try:
        while s.recv(65536):
            pass
    except OSError:
        pass
    s.close()
    time.sleep(1)
    log = read(os.path.join(WORK, 'plain-b.log'))
    check('malformed frames end the tunnel with a log message',
          'not a DRLB tunnel peer' in log and 'frame before HELLO' in log and 'past the stream window' in log, log[-800:])
    check('the server is still running after bad peers', p.proc.poll() is None)
    rc = p.stop()
    check('plain instance stops cleanly', rc == 0, str(rc))


def test_udp_idle():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(b'idle test', ('127.0.0.1', A_UDP))
    s.recvfrom(100)
    time.sleep(5)  # mux_udp_idle_secs = 3 on A
    log = read(os.path.join(WORK, 'drlb-a.log'))
    check('idle UDP flows are closed after mux_udp_idle_secs', 'UDP flow idle' in log)


proc_b = None


def main():
    global proc_b
    if not os.path.exists(SERVER):
        print('No server binary', SERVER)
        return 1
    make_certs()
    tcp_server(ECHO, Echo)
    tcp_server(A_ECHO_REV, Echo)
    tcp_server(NODE1, tagged('node1'))
    tcp_server(NODE2, tagged('node2'))
    tcp_server(SINK, Sink)
    tcp_server(EOF_ECHO, EofEcho)
    udp_echo(UDP_ECHO)

    test_config_checks()
    b_cfg = config_b()
    a_cfg = config_a(['mux_udp_idle_secs = 3', 'mux_hold_secs = 3'])
    proc_b = Proc('drlb-b', b_cfg)
    time.sleep(0.5)
    proc_a = Proc('drlb-a', a_cfg)
    try:
        test_basic()
        test_udp()
        test_load_balance()
        test_concurrent()
        test_throughput()
        test_head_of_line()
        test_half_close()
        test_dead_destination()
        test_udp_idle()
        test_stats(proc_a, proc_b)
        test_reconnect(b_cfg)
        test_tls_checks()
        test_protocol_errors()
    finally:
        rc = proc_a.stop()
        check('A stops on SIGTERM with exit 0', rc == 0, str(rc))
        if proc_b:
            proc_b.stop()
    failed = results.count(False)
    print('\n%d passed, %d failed. Logs: %s' % (results.count(True), failed, WORK))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
