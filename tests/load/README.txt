DRLB simulated load and stress tests
------------------------------------
run_load_tests.py runs five experiments on one host with simulated back
end servers and writes CSV results and PNG charts to tests/load/results:

  scale_out  Throughput and p95 latency with 1, 2, 4 and 8 back ends
  failover   Requests per second while one of three back ends is down,
             DRLB compared with clients that rotate over the back end
             addresses themselves (DNS round robin with no health checks)
  mixed      Back ends with different capacity under LB_RR, LB_WEIGHTED
             and LB_DISTRIB
  overhead   Latency and transfer rate added by DRLB and the SSL bridge
  idle       CPU and memory with up to 10,000 idle long lived connections

Each simulated back end (backend_sim.py) serves 4 requests at a time and
each request takes 10 ms, so one back end tops out near 400 requests per
second, like an application server with a fixed worker pool.

Requirements: ab (dnf install httpd-tools), Python 3 with matplotlib
(dnf install python3-matplotlib), the built drlb_server, and for the
overhead test the SSL bridge built in ../ssl-bridge and openssl.

Run all experiments (about 10 minutes):

$ python3 tests/load/run_load_tests.py

Run some, with shorter runs:

$ python3 tests/load/run_load_tests.py --quick scale_out failover

To compare idle connection CPU with an older release, set DRLB_OLD to
that release's drlb_server binary:

$ DRLB_OLD=/path/to/drlb_server-1.59 python3 tests/load/run_load_tests.py idle

The load generator, the back ends and DRLB all run on the same host, so
the numbers show relative behavior, not the limits of a dedicated
load balancer server.
