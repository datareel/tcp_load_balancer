#!/usr/bin/env python3
# DRLB simulated load and stress tests
#
# Runs on one host with simulated back ends (backend_sim.py) and writes
# CSV results and PNG charts to tests/load/results:
#
#   1 scale_out     Throughput and p95 latency as back ends are added
#   2 failover      Requests per second while one of three back ends fails,
#                   DRLB compared with clients rotating over the back ends
#                   themselves (DNS round robin style)
#   3 mixed         Back ends with different capacity: LB_RR, LB_WEIGHTED
#                   and LB_DISTRIB
#   4 overhead      Latency and transfer rate added by DRLB and the SSL bridge
#   5 idle          CPU and memory with many idle long lived connections
#
# Usage: python3 tests/load/run_load_tests.py [--quick] [experiment ...]
# Needs the ab command (httpd-tools), Python 3 with matplotlib, and the
# built servers. The SSL bridge test also needs ../ssl-bridge and openssl.

import argparse
import asyncio
import csv
import os
import re
import resource
import signal
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TOP = os.path.abspath(os.path.join(HERE, '..', '..'))
DRLB = os.path.join(TOP, 'drlb_server', 'drlb_server')
SSL_BRIDGE = os.path.abspath(os.path.join(TOP, '..', 'ssl-bridge', 'ssl_bridge', 'drlb_ssl_server'))
OUT = os.path.join(HERE, 'results')
WORK = tempfile.mkdtemp(prefix='drlb_load_')
LB_PORT = 18300
BE_BASE = 18311

# Simulated application server: 4 requests in service at once, 10 ms each,
# so one back end tops out near 400 requests per second.
WORKERS = 4
SERVICE_MS = 10

# Chart colors (validated categorical palette, light mode)
C1, C2, C3, C4 = '#2a78d6', '#eb6834', '#1baf7a', '#6250d6'
INK, INK2, GRID = '#0b0b0b', '#52514e', '#e4e3df'

procs = []


def start_backend(port, workers=WORKERS, service_ms=SERVICE_MS):
    p = subprocess.Popen([sys.executable, os.path.join(HERE, 'backend_sim.py'), '--port', str(port),
                          '--workers', str(workers), '--service-ms', str(service_ms)])
    procs.append(p)
    wait_port(port)
    return p


def wait_port(port, tries=100):
    for _ in range(tries):
        try:
            socket.create_connection(('127.0.0.1', port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError('port %d did not open' % port)


def stop(p):
    if p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(30)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
    if p in procs:
        procs.remove(p)


def start_drlb(name, server_opts, nodes, binary=DRLB, ssl_opts=None):
    lines = []
    if ssl_opts:
        lines += ['[SSLCONFIG]'] + ssl_opts
    lines += ['[LBSERVER]', 'port = %d' % LB_PORT, 'somaxconn = 4096', 'retries = 2', 'retry_wait = 0',
              'connect_timeout_secs = 1', 'enable_logging = 1', 'log_level = 0',
              'logfile_name = %s/%s.log' % (WORK, name)] + server_opts
    for i, (port, extra) in enumerate(nodes):
        lines += ['[LBNODE]', 'node_name = be%d' % (i + 1), 'hostname = 127.0.0.1',
                  'port_number = %d' % port] + extra
    cfg = os.path.join(WORK, name + '.cfg')
    with open(cfg, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    out = open(os.path.join(WORK, name + '.out'), 'w')
    p = subprocess.Popen([binary, '--config-file=' + cfg], stdout=out, stderr=subprocess.STDOUT)
    procs.append(p)
    wait_port(LB_PORT)
    return p


def ab(url, concurrency, secs, extra=()):
    """Run ab and return requests/s, failed count, p50 and p95 latency (ms)."""
    cmd = ['ab', '-q', '-r', '-s', '10', '-t', str(secs), '-n', '10000000', '-c', str(concurrency)] + list(extra) + [url]
    r = subprocess.run(cmd, capture_output=True, text=True)
    txt = r.stdout
    def grab(pat, cast=float, default=0):
        m = re.search(pat, txt)
        return cast(m.group(1)) if m else default
    return {
        'rps': grab(r'Requests per second:\s+([\d.]+)'),
        'failed': grab(r'Failed requests:\s+(\d+)', int) + grab(r'Non-2xx responses:\s+(\d+)', int),
        'complete': grab(r'Complete requests:\s+(\d+)', int),
        'p50': grab(r'\n\s+50%\s+(\d+)'),
        'p95': grab(r'\n\s+95%\s+(\d+)'),
        'p99': grab(r'\n\s+99%\s+(\d+)'),
        'mbps': grab(r'Transfer rate:\s+([\d.]+)') * 1024 / 1e6,
    }


def write_csv(name, rows):
    path = os.path.join(OUT, name + '.csv')
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print('wrote', path)


def style(ax, title, xlabel, ylabel):
    ax.set_title(title, loc='left', fontsize=12, color=INK, pad=10)
    ax.set_xlabel(xlabel, color=INK2)
    ax.set_ylabel(ylabel, color=INK2)
    ax.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ('top', 'right'):
        ax.spines[s].set_visible(False)
    for s in ('left', 'bottom'):
        ax.spines[s].set_color('#bdbcb7')
    ax.tick_params(colors=INK2)


# ------------------------------------------------------------------ #
# 1. Scale out
# ------------------------------------------------------------------ #
def exp_scale_out(quick):
    levels = [8, 32, 64, 128, 256] if not quick else [8, 64, 256]
    secs = 4 if not quick else 2
    rows = []
    be = [start_backend(BE_BASE + i) for i in range(8)]
    for c in levels:
        r = ab('http://127.0.0.1:%d/' % BE_BASE, c, secs)
        rows.append({'setup': 'direct, 1 back end', 'backends': 1, 'clients': c, **r})
        print(rows[-1])
    for n in (2, 4, 8):
        lb = start_drlb('scale%d' % n, ['scheme = LB_RR'], [(BE_BASE + i, []) for i in range(n)])
        for c in levels:
            r = ab('http://127.0.0.1:%d/' % LB_PORT, c, secs)
            rows.append({'setup': 'DRLB, %d back ends' % n, 'backends': n, 'clients': c, **r})
            print(rows[-1])
        stop(lb)
    for p in be:
        stop(p)
    write_csv('scale_out', rows)

    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    colors = {'direct, 1 back end': '#8a8984', 'DRLB, 2 back ends': C1, 'DRLB, 4 back ends': C2, 'DRLB, 8 back ends': C3}
    for setup, color in colors.items():
        pts = [r for r in rows if r['setup'] == setup]
        x = [r['clients'] for r in pts]
        axes[0].plot(x, [r['rps'] for r in pts], marker='o', markersize=5, linewidth=2, color=color, label=setup)
        axes[1].plot(x, [r['p95'] for r in pts], marker='o', markersize=5, linewidth=2, color=color, label=setup)
        axes[0].annotate(setup, (x[-1], pts[-1]['rps']), xytext=(6, 0), textcoords='offset points',
                         va='center', fontsize=8.5, color=INK2)
    style(axes[0], 'Throughput grows with each back end added', 'Concurrent clients', 'Requests per second')
    style(axes[1], 'p95 latency stays low as load rises', 'Concurrent clients', 'p95 latency (ms)')
    for ax in axes:
        ax.set_xscale('log', base=2)
        ax.set_xticks(levels)
        ax.set_xticklabels([str(v) for v in levels])
    axes[0].set_xlim(right=levels[-1] * 3)
    axes[1].legend(frameon=False, fontsize=9)
    fig.text(0.01, 0.01, 'Each simulated back end serves 4 requests at a time, 10 ms each (about 400 requests/s). '
             'New TCP connection per request (ab).', fontsize=8, color=INK2)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(os.path.join(OUT, 'scale_out.png'), dpi=150)
    plt.close(fig)


# ------------------------------------------------------------------ #
# 2. Fail over
# ------------------------------------------------------------------ #
async def timeline_client(targets, concurrency, secs, events):
    """Each worker sends requests in a loop. targets is a list of ports;
    with more than one, workers rotate over them like DNS round robin."""
    start = time.time()
    counts = {}
    rr = [0]

    async def one(port):
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', port), 2)
            w.write(b'GET / HTTP/1.0\r\nHost: test\r\n\r\n')
            await w.drain()
            data = await asyncio.wait_for(r.read(), 3)
            w.close()
            return data.startswith(b'HTTP/1.1 200') or data.startswith(b'HTTP/1.0 200')
        except Exception:
            return False

    async def worker():
        while True:
            now = time.time() - start
            if now >= secs:
                return
            port = targets[rr[0] % len(targets)]
            rr[0] += 1
            ok = await one(port)
            sec = int(time.time() - start)
            c = counts.setdefault(sec, [0, 0])
            c[0 if ok else 1] += 1
            if not ok:
                await asyncio.sleep(0.05)  # Back off like a real client

    async def control():
        for at, action in events:
            await asyncio.sleep(max(0, at - (time.time() - start)))
            action()

    await asyncio.gather(control(), *[worker() for _ in range(concurrency)])
    return counts


def exp_failover(quick):
    secs = 40 if not quick else 24
    down, up = (10, 25) if not quick else (6, 15)
    concurrency = 32
    rows = []
    for mode in ('DRLB', 'direct rotation'):
        be = [start_backend(BE_BASE + i) for i in range(3)]
        state = {'p': be[1]}
        lb = None
        if mode == 'DRLB':
            lb = start_drlb('failover', ['scheme = LB_RR'], [(BE_BASE + i, []) for i in range(3)])
            targets = [LB_PORT]
        else:
            targets = [BE_BASE + i for i in range(3)]

        def kill():
            state['p'].kill()
            state['p'].wait()

        def restart():
            state['p'] = start_backend(BE_BASE + 1)
        counts = asyncio.run(timeline_client(targets, concurrency, secs, [(down, kill), (up, restart)]))
        for sec in range(secs):
            ok, err = counts.get(sec, [0, 0])
            rows.append({'mode': mode, 'second': sec, 'ok': ok, 'errors': err})
        if lb:
            stop(lb)
        for p in be + [state['p']]:
            if p.poll() is None:
                stop(p)
        print(mode, 'ok', sum(r['ok'] for r in rows if r['mode'] == mode),
              'errors', sum(r['errors'] for r in rows if r['mode'] == mode))
    write_csv('failover', rows)

    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2), sharex=True)
    for mode, color in (('DRLB', C1), ('direct rotation', C2)):
        pts = [r for r in rows if r['mode'] == mode]
        x = [r['second'] for r in pts]
        axes[0].plot(x, [r['ok'] for r in pts], linewidth=2, color=color, label=mode)
        axes[1].plot(x, [r['errors'] for r in pts], linewidth=2, color=color, label=mode)
    for ax in axes:
        ax.axvspan(down, up, color='#f2f1ee', zorder=0)
        ax.text((down + up) / 2, 0.97, 'back end 2 down', transform=ax.get_xaxis_transform(),
                ha='center', va='top', fontsize=8.5, color=INK2)
    style(axes[0], 'Successful requests per second', 'Seconds', 'Requests per second')
    style(axes[1], 'Failed requests per second', 'Seconds', 'Failed requests per second')
    axes[0].set_ylim(bottom=0)
    axes[1].set_ylim(bottom=0)
    axes[0].legend(frameon=False, fontsize=9, loc='lower left')
    fig.text(0.01, 0.01, '3 back ends, 32 clients. "direct rotation" = clients rotate over the back end addresses '
             'themselves, as with DNS round robin and no health checks.', fontsize=8, color=INK2)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(os.path.join(OUT, 'failover.png'), dpi=150)
    plt.close(fig)


# ------------------------------------------------------------------ #
# 3. Mixed capacity back ends
# ------------------------------------------------------------------ #
def exp_mixed(quick):
    # Three servers: 8, 4 and 1 requests at a time (about 800, 400, 100 req/s)
    caps = [8, 4, 1]
    concurrency = 64
    secs = 6 if not quick else 3
    setups = [
        ('LB_RR', ['scheme = LB_RR'], [[], [], []]),
        ('LB_WEIGHTED 8:4:1', ['scheme = LB_WEIGHTED'], [['weight = 8'], ['weight = 4'], ['weight = 1']]),
        ('LB_DISTRIB 62/31/7 %', ['scheme = LB_DISTRIB'], [['weight = 62'], ['weight = 31'], ['weight = 7']]),
    ]
    rows = []
    be = [start_backend(BE_BASE + i, workers=caps[i]) for i in range(3)]
    for name, opts, node_opts in setups:
        lb = start_drlb('mixed', opts, [(BE_BASE + i, node_opts[i]) for i in range(3)])
        ab('http://127.0.0.1:%d/' % LB_PORT, concurrency, 1)  # warm up
        r = ab('http://127.0.0.1:%d/' % LB_PORT, concurrency, secs)
        rows.append({'setup': name, 'clients': concurrency, **r})
        print(rows[-1])
        stop(lb)
    for p in be:
        stop(p)
    write_csv('mixed', rows)

    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    names = [r['setup'] for r in rows]
    y = range(len(rows))
    axes[0].barh(y, [r['rps'] for r in rows], color=C1, height=0.55)
    axes[1].barh(y, [r['p95'] for r in rows], color=C2, height=0.55)
    for ax, key, fmt in ((axes[0], 'rps', '{:.0f}'), (axes[1], 'p95', '{:.0f} ms')):
        for i, r in enumerate(rows):
            ax.text(r[key], i, ' ' + fmt.format(r[key]), va='center', fontsize=9, color=INK)
        ax.set_yticks(list(y))
        ax.set_yticklabels(names)
        ax.invert_yaxis()
    style(axes[0], 'Throughput', 'Requests per second', '')
    style(axes[1], 'p95 latency (lower is better)', 'Milliseconds', '')
    axes[1].set_yticklabels([])
    for ax in axes:
        ax.grid(axis='y', visible=False)
        ax.set_xlim(right=max(r['rps' if ax is axes[0] else 'p95'] for r in rows) * 1.25)
    fig.text(0.01, 0.01, 'Back ends with 8, 4 and 1 workers (about 800, 400 and 100 requests/s), 64 clients.',
             fontsize=8, color=INK2)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(os.path.join(OUT, 'mixed.png'), dpi=150)
    plt.close(fig)


# ------------------------------------------------------------------ #
# 4. Overhead
# ------------------------------------------------------------------ #
def make_cert():
    key, crt = os.path.join(WORK, 'lb.key'), os.path.join(WORK, 'lb.crt')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                    '-keyout', key, '-out', crt, '-days', '2', '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
    return key, crt


def exp_overhead(quick):
    secs = 5 if not quick else 2
    rows = []
    fast = start_backend(BE_BASE, workers=1, service_ms=0)
    setups = [('direct', None), ('DRLB', 'plain')]
    if os.access(SSL_BRIDGE, os.X_OK):
        setups.append(('SSL bridge (TLS)', 'tls'))
    key, crt = make_cert()
    for name, kind in setups:
        lb = None
        if kind == 'plain':
            lb = start_drlb('ovh', ['scheme = LB_RR'], [(BE_BASE, [])])
        elif kind == 'tls':
            lb = start_drlb('ovh_tls', ['scheme = LB_RR'], [(BE_BASE, [])], binary=SSL_BRIDGE,
                            ssl_opts=['ssl_protocol = TLS', 'ssl_key_file = ' + key, 'ssl_cert_file = ' + crt])
        port = BE_BASE if kind is None else LB_PORT
        scheme = 'https' if kind == 'tls' else 'http'
        r = ab('%s://127.0.0.1:%d/' % (scheme, port), 8, secs)
        big = ab('%s://127.0.0.1:%d/big/%d' % (scheme, port, 50 * 1024 * 1024), 4, secs)
        rows.append({'setup': name, 'rps': r['rps'], 'p50_ms': r['p50'], 'p99_ms': r['p99'],
                     'failed': r['failed'] + big['failed'], 'transfer_MBps': big['mbps']})
        print(rows[-1])
        if lb:
            stop(lb)
    stop(fast)
    write_csv('overhead', rows)

    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 3, figsize=(12, 3.8))
    names = [r['setup'] for r in rows]
    for ax, key, title, unit, color in ((axes[0], 'rps', 'Small requests', 'Requests per second', C1),
                                        (axes[1], 'p99_ms', 'p99 latency, small requests', 'Milliseconds', C2),
                                        (axes[2], 'transfer_MBps', 'Large transfers (50 MB)', 'MB per second', C3)):
        ax.bar(names, [r[key] for r in rows], color=color, width=0.55)
        for i, r in enumerate(rows):
            ax.text(i, r[key], '{:.0f}'.format(r[key]), ha='center', va='bottom', fontsize=9, color=INK)
        style(ax, title, '', unit)
        ax.grid(axis='x', visible=False)
        ax.tick_params(axis='x', labelsize=8.5)
    fig.text(0.01, 0.01, 'One fast back end with no service delay, a new connection per request. '
             'The Python test back end, not DRLB, limits small request rates.', fontsize=8, color=INK2)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(os.path.join(OUT, 'overhead.png'), dpi=150)
    plt.close(fig)


# ------------------------------------------------------------------ #
# 5. Idle connections
# ------------------------------------------------------------------ #
def proc_stats(pid):
    with open('/proc/%d/stat' % pid) as f:
        st = f.read().split()
    cpu = (int(st[13]) + int(st[14])) / os.sysconf('SC_CLK_TCK')
    rss = 0
    with open('/proc/%d/status' % pid) as f:
        for line in f:
            if line.startswith('VmRSS:'):
                rss = int(line.split()[1]) / 1024
            if line.startswith('Threads:'):
                threads = int(line.split()[1])
    return cpu, rss, threads


def exp_idle(quick):
    levels = [0, 1000, 2500, 5000, 10000] if not quick else [0, 1000, 3000]
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 65536), hard))
    binaries = [('DRLB 1.60', DRLB)]
    # Set DRLB_OLD to a DRLB 1.59 drlb_server binary to compare with it
    if os.environ.get('DRLB_OLD'):
        binaries.append(('DRLB 1.59', os.environ['DRLB_OLD']))
    be = start_backend(BE_BASE, workers=1, service_ms=0)
    rows = []
    for label, binary in binaries:
        lb = start_drlb('idle', ['scheme = LB_RR', 'use_timeout = 0'], [(BE_BASE, [])], binary=binary)
        socks = []
        for n in levels:
            while len(socks) < n:
                try:
                    socks.append(socket.create_connection(('127.0.0.1', LB_PORT), timeout=5))
                except OSError as e:
                    print('connect failed at', len(socks), e)
                    break
            if len(socks) < n:
                break
            time.sleep(3)
            if lb.poll() is not None:
                print(label, 'exited with', lb.returncode, 'at', len(socks), 'connections')
                break
            cpu0, _, _ = proc_stats(lb.pid)
            time.sleep(5)
            if lb.poll() is not None:
                print(label, 'exited with', lb.returncode, 'at', len(socks), 'connections')
                break
            cpu1, rss, threads = proc_stats(lb.pid)
            rows.append({'version': label, 'connections': len(socks),
                         'cpu_percent': round((cpu1 - cpu0) / 5 * 100, 2),
                         'rss_MB': round(rss, 1), 'threads': threads})
            print(rows[-1])
        for s in socks:
            s.close()
        stop(lb)
        time.sleep(2)
    stop(be)
    write_csv('idle', rows)

    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(11, 3.8))
    for (label, _), color in zip(binaries, (C1, '#8a8984')):
        pts = [r for r in rows if r['version'] == label]
        x = [r['connections'] for r in pts]
        axes[0].plot(x, [r['cpu_percent'] for r in pts], marker='o', markersize=5, linewidth=2, color=color, label=label)
        axes[1].plot(x, [r['rss_MB'] for r in pts], marker='o', markersize=5, linewidth=2, color=color, label=label)
    style(axes[0], 'CPU used by idle connections', 'Open idle connections', 'CPU (% of one core)')
    style(axes[1], 'Resident memory', 'Open idle connections', 'RSS (MB)')
    axes[0].set_ylim(bottom=0)
    axes[1].set_ylim(bottom=0)
    if len(binaries) > 1:
        axes[0].legend(frameon=False, fontsize=9)
    fig.text(0.01, 0.01, 'Long lived connections with no traffic, such as LDM feeds or keep alive clients.',
             fontsize=8, color=INK2)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(os.path.join(OUT, 'idle.png'), dpi=150)
    plt.close(fig)


EXPERIMENTS = {'scale_out': exp_scale_out, 'failover': exp_failover, 'mixed': exp_mixed,
               'overhead': exp_overhead, 'idle': exp_idle}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quick', action='store_true', help='shorter runs')
    ap.add_argument('experiments', nargs='*', default=list(EXPERIMENTS))
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    try:
        for name in a.experiments:
            print('==', name)
            EXPERIMENTS[name](a.quick)
    finally:
        for p in list(procs):
            stop(p)
    print('Results in', OUT, '- logs in', WORK)


if __name__ == '__main__':
    main()
