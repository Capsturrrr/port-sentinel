"""Core tools against the real kernel: real servers on real ports, no mocks."""

import os

import pytest

from port_sentinel import tools
from port_sentinel.safety import Session, gate

from .conftest import free_port


def test_hex_decoding():
    assert tools._hex_to_ip("0100007F", False) == "127.0.0.1"
    assert tools._hex_to_ip("00000000", False) == "0.0.0.0"
    assert tools._hex_to_ip("00000000000000000000000001000000", True) == "::1"
    assert tools._hex_to_ip("0000000000000000FFFF00000100007F", True) == "::ffff:127.0.0.1"


def test_listing_includes_server(server):
    port, proc = server
    row = next(r for r in tools.list_listening_ports("tcp")["listening"] if r["port"] == port)
    assert row["target_pid"] == proc.pid and row["workers"] == []


def test_find_by_port(server):
    port, proc = server
    res = tools.find_process_by_port(port)
    svc = res["services"][0]
    assert res["in_use"] and svc["target_pid"] == proc.pid
    assert "http.server" in svc["target"]["cmdline"]
    assert any("127.0.0.1 (loopback only (IPv4))" in a for a in svc["listening_on"])


def test_unused_port():
    res = tools.find_process_by_port(free_port())
    assert res["in_use"] is False and "No process is listening" in res["message"]


def test_process_details(server):
    _, proc = server
    d = tools.get_process_details(proc.pid)
    assert d["ppid"] == os.getpid() and d["protected"] is False and d["memory_rss_mb"] > 0
    assert d["start_time"] == tools._starttime(proc.pid)


def test_sigterm_frees_port(server):
    port, proc = server
    res = tools.send_signal(proc.pid, "SIGTERM", expected_start=tools._starttime(proc.pid))
    proc.wait(timeout=5)
    assert res["ok"] and res["exited"]
    assert tools.verify_port_free(port)["free"]


def test_hard_rules():
    assert tools.send_signal(1)["ok"] is False
    assert tools.send_signal(os.getpid())["ok"] is False
    assert tools.send_signal(999999)["ok"] is False
    assert tools.send_signal(os.getpid(), "SIGSTOP")["ok"] is False


def test_kernel_thread_detected_by_flag():
    kthreads = [int(p) for p in os.listdir("/proc") if p.isdigit() and tools._is_kernel_thread(int(p))]
    if not kthreads:
        pytest.skip("no kernel threads visible (PID namespace)")
    allowed, reason = tools.check_kill_safety(max(kthreads))
    assert not allowed and ("kernel thread" in reason or "protected" in reason)


def test_user_decline_does_not_kill(server):
    _, proc = server
    session = Session("stop it")
    session.record(tools.get_process_details(proc.pid))
    ok, _ = gate({"pid": proc.pid}, session, confirm=lambda m: False)
    assert ok is False and proc.poll() is None
