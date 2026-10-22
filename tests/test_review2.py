"""Review 2: worker pools, TIME_WAIT, PID reuse, IPv6, supervisors, ownership messages."""

import os
import socket
import time

import pytest

from port_sentinel import tools

from .conftest import free_port, kill_group, start_http, start_prefork


# ---------------------------------------------------------------- worker pools

def test_prefork_master_is_the_target():
    port = free_port()
    p = start_prefork(port, workers=3)
    try:
        svc = tools.find_process_by_port(port)["services"]
        assert len(svc) == 1
        assert svc[0]["target_pid"] == p.pid
        assert len(svc[0]["workers"]) == 3 and p.pid not in svc[0]["workers"]
    finally:
        kill_group(p)


def test_stopping_master_releases_port():
    port = free_port()
    p = start_prefork(port, workers=3, mode="graceful")
    try:
        res = tools.send_signal(p.pid, "SIGTERM", expected_start=tools._starttime(p.pid))
        p.wait(timeout=5)
        assert res["ok"] and res["exited"]
        assert tools.verify_port_free(port)["free"]
    finally:
        kill_group(p)


def test_orphaned_workers_are_reported_after_naive_master_dies():
    port = free_port()
    p = start_prefork(port, workers=2, mode="naive")
    try:
        tools.send_signal(p.pid, "SIGTERM")
        p.wait(timeout=5)
        time.sleep(0.2)
        v = tools.verify_port_free(port)
        assert v["free"] is False
        assert v["still_listening"][0]["target_pid"] != p.pid     # a surviving worker is now the target
    finally:
        kill_group(p)


# ---------------------------------------------------------------- TIME_WAIT

def test_time_wait_is_not_reported_as_ready():
    port = free_port()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen()
    cli = socket.create_connection(("127.0.0.1", port))
    conn, _ = srv.accept()
    conn.close()                  # server closes first, so the server side enters TIME_WAIT
    cli.recv(1)
    cli.close()
    srv.close()

    found = tools.find_process_by_port(port)
    assert found["in_use"] is False and found["connections"].get("TIME_WAIT", 0) >= 1
    v = tools.verify_port_free(port)
    assert v["free"] is True
    assert v["time_wait_connections"] >= 1
    assert v["bind_without_reuseaddr"] == "EADDRINUSE"
    assert "SO_REUSEADDR" in v["note"]


def test_close_wait_names_the_leaking_process():
    port = free_port()
    srv = socket.socket()
    srv.bind(("127.0.0.1", port))
    srv.listen()
    cli = socket.create_connection(("127.0.0.1", port))
    conn, _ = srv.accept()
    cli.close()                   # peer closes; we never close conn -> CLOSE_WAIT held by this process
    time.sleep(0.1)
    try:
        r = tools.find_process_by_port(port)
        assert r["connections"].get("CLOSE_WAIT") == 1
        assert os.getpid() in r["close_wait_holders"]
    finally:
        conn.close()
        srv.close()


# ---------------------------------------------------------------- PID reuse

def test_reused_pid_is_not_signalled(server):
    _, proc = server
    stale_start = tools._starttime(proc.pid) - 1          # pretend we looked up an older process
    res = tools.send_signal(proc.pid, "SIGTERM", expected_start=stale_start)
    assert res["ok"] is False and "reused" in res["error"]
    assert proc.poll() is None


def test_pidfd_path_is_used():
    assert hasattr(os, "pidfd_open"), "pidfd_open needs Python 3.9+ and Linux 5.3+"


# ---------------------------------------------------------------- addresses and IPv6

def test_split_listeners_on_one_port_are_both_reported():
    port = free_port()
    a = start_http(port, "127.0.0.1")
    b = start_http(port, "127.0.0.2")
    try:
        svc = tools.find_process_by_port(port)["services"]
        assert {s["target_pid"] for s in svc} == {a.pid, b.pid}
    finally:
        for p in (a, b):
            p.kill()
            p.wait()


def _row(sl, ip_hex, port, state, inode):
    return (f"   {sl}: {ip_hex}:{port:04X} {'0' * len(ip_hex)}:0000 {state} 00000000:00000000 00:00000000 "
            f"00000000     0        0 {inode} 1 0000000000000000 100 0 0 10 0\n")


@pytest.fixture
def fake_net(tmp_path, monkeypatch):
    """Crafted /proc/net tables in kernel format. The sandbox has IPv6 disabled, so IPv6 rows are
    simulated; their inodes point at a real socket held by a real process."""
    def make(rows6="", rows4=""):
        hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        (tmp_path / "tcp").write_text(hdr + rows4)
        (tmp_path / "tcp6").write_text(hdr + rows6)
        (tmp_path / "udp").write_text(hdr)
        (tmp_path / "udp6").write_text(hdr)
        monkeypatch.setattr(tools, "NET_DIR", str(tmp_path))
    return make


def _real_inode(port):
    return next(s["inode"] for s in tools._parse_net_file("tcp") if s["local_port"] == port and s["state"] == "LISTEN")


def test_ipv6_loopback_listener(server, fake_net):
    port, proc = server
    inode = _real_inode(port)
    fake_net(rows6=_row(0, "00000000000000000000000001000000", port, "0A", inode))
    svc = tools.find_process_by_port(port)["services"][0]
    assert svc["target_pid"] == proc.pid
    assert svc["listening_on"] == [f"tcp6 ::1 (loopback only (IPv6))"]


def test_dual_stack_listener_is_labelled(server, fake_net):
    port, proc = server
    fake_net(rows6=_row(0, "0" * 32, port, "0A", _real_inode(port)))
    svc = tools.find_process_by_port(port)["services"][0]
    assert "IPv4 and IPv6" in svc["listening_on"][0]


def test_unowned_listener_explains_why(fake_net):
    fake_net(rows4=_row(0, "00000000", 4242, "0A", 999999999))   # inode no process holds
    svc = tools.find_process_by_port(4242)["services"][0]
    assert svc["target_pid"] is None
    expected = "PID namespace" if os.geteuid() == 0 else "sudo"
    assert expected in svc["note"]


# ---------------------------------------------------------------- supervisors

@pytest.mark.parametrize("text,kind,unit", [
    ("0::/system.slice/nginx.service\n", "systemd", "nginx.service"),
    ("0::/user.slice/user-1000.slice/user@1000.service/app.slice/vite.service\n", "systemd", "vite.service"),
    ("0::/system.slice/docker-3f2a9c1e5b7d.scope\n", "docker", None),
    ("0::/user.slice/user-1000.slice/session-2.scope\n", None, None),
], ids=["systemd-service", "systemd-user-service", "docker", "plain-login-session"])
def test_supervisor_detection(text, kind, unit):
    r = tools.parse_cgroup(text)
    assert (r or {}).get("kind") == kind
    if unit:
        assert r["unit"] == unit and f"systemctl stop {unit}" in r["advice"]


def test_sigkill_only_after_sigterm_was_ignored():
    """SIGKILL is allowed only once SIGTERM has been sent AND the process survived it."""
    import subprocess, sys
    from port_sentinel.safety import Session
    from port_sentinel.agent import run_tool

    port = free_port()
    code = ("import signal,socket,time;signal.signal(signal.SIGTERM, signal.SIG_IGN);"
            f"s=socket.socket();s.setsockopt(1,2,1);s.bind(('127.0.0.1',{port}));s.listen();time.sleep(600)")
    p = subprocess.Popen([sys.executable, "-c", code], start_new_session=True)
    try:
        s = Session("stop it")
        for _ in range(100):
            if any(x["target_pid"] == p.pid for x in tools.find_process_by_port(port)["services"]):
                break
            time.sleep(0.05)
        s.record(tools.find_process_by_port(port))
        confirm = lambda m: True
        r = run_tool("send_signal", {"pid": p.pid, "signal_name": "SIGKILL"}, s, confirm, False)
        assert "send SIGTERM first" in r["error"] and p.poll() is None     # no SIGTERM yet: refused

        r = run_tool("send_signal", {"pid": p.pid, "signal_name": "SIGTERM"}, s, confirm, False)
        assert r["ok"] and r["exited"] is False and p.poll() is None      # ignored, still alive

        r = run_tool("send_signal", {"pid": p.pid, "signal_name": "SIGKILL"}, s, confirm, False)
        assert r["ok"] and r["exited"] is True                           # now justified
    finally:
        if p.poll() is None:
            p.kill()
        p.wait()
