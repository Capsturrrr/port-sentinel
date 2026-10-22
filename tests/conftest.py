import os
import signal
import socket
import subprocess
import sys
import time

import pytest

from port_sentinel import tools

HERE = os.path.dirname(__file__)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_listening(port: int, timeout: float = 5.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        if tools.find_process_by_port(port)["in_use"]:
            return
        time.sleep(0.05)
    raise RuntimeError(f"nothing started listening on {port}")


def start_http(port: int, bind: str = "127.0.0.1") -> subprocess.Popen:
    p = subprocess.Popen([sys.executable, "-m", "http.server", str(port), "--bind", bind],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end = time.time() + 5
    while time.time() < end:   # wait for THIS process, not just "something on the port"
        if any(s["target_pid"] == p.pid for s in tools.find_process_by_port(port)["services"]):
            return p
        time.sleep(0.05)
    raise RuntimeError(f"http.server did not start on {bind}:{port}")


def start_prefork(port: int, workers: int = 3, mode: str = "graceful") -> subprocess.Popen:
    p = subprocess.Popen([sys.executable, os.path.join(HERE, "helpers", "prefork_server.py"),
                          str(port), str(workers), mode], start_new_session=True)
    end = time.time() + 5
    while time.time() < end:
        r = tools.find_process_by_port(port)
        if r["services"] and len(r["services"][0]["workers"]) == workers:
            return p
        time.sleep(0.05)
    raise RuntimeError("prefork server did not start")


def kill_group(p: subprocess.Popen) -> None:
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    p.wait()


@pytest.fixture
def server():
    port = free_port()
    proc = start_http(port)
    yield port, proc
    if proc.poll() is None:
        proc.kill()
        proc.wait()
