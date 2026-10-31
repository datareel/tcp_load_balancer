#!/usr/bin/env python3
# Simulated back end server for DRLB load tests.
#
# An HTTP server with a fixed capacity: at most --workers requests are in
# service at once and each takes --service-ms milliseconds. Requests over
# capacity wait in a queue, like a real application server. GET /big/N
# returns N bytes with no service delay.
#
# Usage: backend_sim.py --port 18311 [--workers 4] [--service-ms 10]

import argparse
import asyncio

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, required=True)
parser.add_argument('--workers', type=int, default=4)
parser.add_argument('--service-ms', type=float, default=10.0)
args = parser.parse_args()

BIG = b'z' * (1 << 20)


async def handle(reader, writer, sem):
    try:
        while True:
            head = await reader.readuntil(b'\r\n\r\n')
            line = head.split(b'\r\n', 1)[0].decode('latin-1')
            keep_alive = b'keep-alive' in head.lower() or b'HTTP/1.1' in line.encode()
            path = line.split(' ')[1] if ' ' in line else '/'
            if path.startswith('/big/'):
                n = int(path[5:])
                writer.write(b'HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n' % n)
                while n > 0:
                    chunk = BIG[:min(n, len(BIG))]
                    writer.write(chunk)
                    await writer.drain()
                    n -= len(chunk)
                keep_alive = False
            else:
                if args.service_ms > 0:
                    async with sem:
                        await asyncio.sleep(args.service_ms / 1000.0)
                body = b'node %d\n' % args.port
                conn = b'keep-alive' if keep_alive else b'close'
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: %s\r\n\r\n%s'
                             % (len(body), conn, body))
                await writer.drain()
            if not keep_alive:
                break
    except (asyncio.IncompleteReadError, ConnectionError, asyncio.LimitOverrunError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    sem = asyncio.Semaphore(args.workers)
    srv = await asyncio.start_server(lambda r, w: handle(r, w, sem), '127.0.0.1', args.port, backlog=4096)
    async with srv:
        await srv.serve_forever()

asyncio.run(main())
