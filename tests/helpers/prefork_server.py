"""A pre-fork TCP server, the pattern gunicorn and nginx use: bind once, fork N workers.

usage: prefork_server.py PORT WORKERS graceful|naive

graceful: the master stops its workers on SIGTERM (like gunicorn's arbiter)
naive:    the master just dies; the workers are orphaned and keep holding the port
"""
import os
import signal
import socket
import sys
import time

port, n, mode = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen()

children = []
for _ in range(n):
    pid = os.fork()
    if pid == 0:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        while True:
            time.sleep(1)
    children.append(pid)

if mode == "graceful":
    def stop(*_):
        for c in children:
            os.kill(c, signal.SIGTERM)
        for c in children:
            os.waitpid(c, 0)
        sys.exit(0)
    signal.signal(signal.SIGTERM, stop)

while True:
    time.sleep(1)
