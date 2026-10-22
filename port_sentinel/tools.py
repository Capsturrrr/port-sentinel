"""
Port Sentinel - OS tools (Review 2).

Kernel interfaces used:
  * /proc/net/{tcp,tcp6,udp,udp6}      socket table: local address, state, owner uid, inode
  * /proc/<pid>/fd/*  (readlink)       "socket:[inode]"  ->  which processes hold a socket
  * /proc/<pid>/{stat,status,cmdline,cgroup}   process details, parent, start time, supervisor
  * pidfd_open(2) + pidfd_send_signal(2)       race-free signalling (falls back to kill(2))
  * bind(2) probe                              ground truth for "can a new server use this port?"

Every tool returns plain JSON-serialisable data for the LLM.
"""

from __future__ import annotations

import errno
import os
import pwd
import re
import select
import signal
import socket
import struct
import time

PROC = "/proc"
NET_DIR = "/proc/net"          # tests point this at crafted tables (e.g. IPv6 when the host has none)

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

ALLOWED_SIGNALS = {"SIGTERM": signal.SIGTERM, "SIGKILL": signal.SIGKILL, "SIGINT": signal.SIGINT,
                   "SIGHUP": signal.SIGHUP, "SIGQUIT": signal.SIGQUIT}

PROTECTED_NAMES = {"systemd", "init", "sshd", "dbus-daemon", "Xorg", "gdm", "login", "kthreadd",
                   "NetworkManager", "systemd-journald", "systemd-logind", "polkitd"}

PF_KTHREAD = 0x00200000        # include/linux/sched.h: task is a kernel thread


# ------------------------------------------------------------------ /proc helpers

def _hex_to_ip(hex_addr: str, v6: bool) -> str:
    """/proc/net stores addresses as 32-bit words in host (little-endian) byte order."""
    raw = bytes.fromhex(hex_addr)
    if not v6:
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", struct.unpack(">I", raw)[0]))
    return socket.inet_ntop(socket.AF_INET6, struct.pack("<4I", *struct.unpack(">4I", raw)))


def _parse_net_file(proto: str) -> list[dict]:
    out = []
    try:
        with open(f"{NET_DIR}/{proto}") as f:
            next(f, None)
            for line in f:
                p = line.split()
                if len(p) < 10:
                    continue
                lip, lport = p[1].split(":")
                rip, rport = p[2].split(":")
                if proto.startswith("tcp"):
                    state = TCP_STATES.get(p[3], p[3])
                else:  # UDP has no handshake; an unconnected bound socket (07) is the "listener"
                    state = "LISTEN" if p[3] == "07" and int(rport, 16) == 0 else "CONNECTED"
                out.append({"proto": proto, "local_ip": _hex_to_ip(lip, proto.endswith("6")),
                            "local_port": int(lport, 16), "remote_port": int(rport, 16),
                            "state": state, "uid": int(p[7]), "inode": int(p[9])})
    except FileNotFoundError:
        pass  # IPv6 disabled, or protocol not present
    return out


def _protocols(protocol: str) -> list[str]:
    return {"tcp": ["tcp", "tcp6"], "udp": ["udp", "udp6"]}.get(protocol, ["tcp", "tcp6", "udp", "udp6"])


def _inode_to_pid_map(wanted: set[int] | None = None) -> dict[int, list[int]]:
    """Map socket inode -> PIDs by reading every /proc/<pid>/fd link.

    Processes may exit at any point during the walk; every per-process step is
    wrapped so a vanished process is simply skipped. No file descriptors are held:
    listdir() and readlink() are single system calls.
    """
    mapping: dict[int, list[int]] = {}
    try:
        pids = [int(p) for p in os.listdir(PROC) if p.isdigit()]
    except OSError:
        return mapping
    for pid in pids:
        fd_dir = f"{PROC}/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:            # exited, permission denied, or zombie
            continue
        for fd in fds:
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:        # fd closed or process exited mid-scan
                continue
            if target.startswith("socket:["):
                inode = int(target[8:-1])
                if wanted is None or inode in wanted:
                    holders = mapping.setdefault(inode, [])
                    if pid not in holders:
                        holders.append(pid)
    return mapping


def _read(path: str) -> str | None:
    try:
        with open(path, "rb") as f:
            return f.read().decode(errors="replace")
    except OSError:
        return None


def _stat(pid: int) -> list[str] | None:
    """Fields of /proc/<pid>/stat after the command name. Index 0 = field 3 (state)."""
    s = _read(f"{PROC}/{pid}/stat")
    if not s:
        return None
    return s[s.rfind(")") + 2:].split()


def _ppid(pid: int) -> int | None:
    f = _stat(pid)
    return int(f[1]) if f else None


def _starttime(pid: int) -> int | None:
    """Start time in clock ticks since boot (field 22). Unique per process: a reused PID has a new value."""
    f = _stat(pid)
    return int(f[19]) if f else None


def _is_kernel_thread(pid: int) -> bool:
    f = _stat(pid)
    return bool(f and int(f[6]) & PF_KTHREAD)


def _user(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _proc_basic(pid: int) -> dict | None:
    comm = _read(f"{PROC}/{pid}/comm")
    stat = _stat(pid)
    if comm is None or stat is None:
        return None
    cmd = (_read(f"{PROC}/{pid}/cmdline") or "").replace("\0", " ").strip()
    status = _read(f"{PROC}/{pid}/status") or ""
    m = re.search(r"^Uid:\s+(\d+)", status, re.M)
    return {"pid": pid, "name": comm.strip(), "cmdline": cmd or f"[{comm.strip()}]",
            "user": _user(int(m.group(1))) if m else None, "start_time": int(stat[19])}


def parse_cgroup(text: str) -> dict | None:
    """Detect a supervisor from /proc/<pid>/cgroup content."""
    if re.search(r"docker[-/]|/docker\b|containerd", text):
        return {"kind": "docker", "advice": "Stop it with `docker stop <container>`; killing it breaks the container."}
    units = re.findall(r"/([\w@.\-]+\.service)", text)
    units = [u for u in units if not u.startswith("user@")]
    if units:
        unit = units[-1]
        return {"kind": "systemd", "unit": unit,
                "advice": f"Managed by systemd; a killed process may be restarted. Use `systemctl stop {unit}`."}
    return None


def _supervisor(pid: int) -> dict | None:
    info = _proc_basic(pid)
    if info and info["name"] == "docker-proxy":
        return {"kind": "docker", "advice": "docker-proxy publishes a container port. Use `docker stop <container>`."}
    return parse_cgroup(_read(f"{PROC}/{pid}/cgroup") or "")


def _scope(ip: str) -> str:
    return {"0.0.0.0": "all IPv4 interfaces", "::": "all interfaces (IPv4 and IPv6 unless IPV6_V6ONLY)",
            "127.0.0.1": "loopback only (IPv4)", "::1": "loopback only (IPv6)"}.get(
        ip, "IPv4-mapped " + ip[7:] if ip.startswith("::ffff:") else f"single address {ip}")


def _unowned_reason(uid: int) -> str:
    if os.geteuid() != 0 and uid != os.geteuid():
        return (f"Socket belongs to user '{_user(uid)}'. Its process is hidden from non-root users; "
                f"re-run with sudo to identify and stop it.")
    return ("No process visible from here holds this socket, even with full /proc access. Likely causes: "
            "a process in another PID namespace or container, or a socket held outside any process file table.")


# ------------------------------------------------------------------ grouping: master vs workers

def _group_holders(pids: list[int]) -> list[dict]:
    """Split the processes holding a port into services: a root (master) plus its workers.

    Pre-fork servers (gunicorn, nginx, uvicorn --workers) bind once and fork, so the master and
    every worker share one socket. The master is the holder whose parent is not itself a holder.
    """
    holders = set(pids)
    parents = {p: _ppid(p) for p in holders}
    roots = sorted(p for p in holders if parents.get(p) not in holders)
    groups = []
    for r in roots:
        members, frontier = {r}, {r}
        while frontier:
            frontier = {p for p in holders if parents.get(p) in frontier} - members
            members |= frontier
        groups.append({"target": r, "workers": sorted(members - {r})})
    return groups


def _port_report(port: int | None, protocol: str = "all") -> list[dict]:
    """One entry per (port, service). Shared by list/find so both see masters and workers the same way."""
    sockets = [s for proto in _protocols(protocol) for s in _parse_net_file(proto)
               if s["state"] == "LISTEN" and (port is None or s["local_port"] == port)]
    inode_map = _inode_to_pid_map({s["inode"] for s in sockets})
    by_port: dict[int, list[dict]] = {}
    for s in sockets:
        by_port.setdefault(s["local_port"], []).append(s)

    report = []
    for p, socks in sorted(by_port.items()):
        held = {pid for s in socks for pid in inode_map.get(s["inode"], [])}
        for g in _group_holders(sorted(held)):
            members = {g["target"], *g["workers"]}
            mine = [s for s in socks if set(inode_map.get(s["inode"], [])) & members]
            report.append({
                "port": p,
                "listening_on": sorted({f"{s['proto']} {s['local_ip']} ({_scope(s['local_ip'])})" for s in mine}),
                "target": _proc_basic(g["target"]),
                "target_pid": g["target"],
                "workers": g["workers"],
                "parent": (_proc_basic(_ppid(g["target"]) or 0) or {}).get("name"),
                "managed_by": _supervisor(g["target"]),
            })
        for s in socks:
            if not inode_map.get(s["inode"]):
                report.append({"port": p, "listening_on": [f"{s['proto']} {s['local_ip']} ({_scope(s['local_ip'])})"],
                               "target": None, "target_pid": None, "owner": _user(s["uid"]),
                               "note": _unowned_reason(s["uid"])})
    return report


# ------------------------------------------------------------------ TOOLS

def list_listening_ports(protocol: str = "all") -> dict:
    """Every listening port, grouped into services (master + workers)."""
    rows = _port_report(None, protocol)
    return {"count": len(rows), "listening": rows}


def find_process_by_port(port: int, protocol: str = "all") -> dict:
    """Who is listening on a port, plus a summary of other connections on it."""
    port = int(port)
    services = _port_report(port, protocol)
    conns: dict[str, int] = {}
    close_wait_pids: set[int] = set()
    other = [s for proto in _protocols(protocol) for s in _parse_net_file(proto)
             if s["local_port"] == port and s["state"] != "LISTEN"]
    cw_map = _inode_to_pid_map({s["inode"] for s in other if s["state"] == "CLOSE_WAIT"})
    for s in other:
        conns[s["state"]] = conns.get(s["state"], 0) + 1
        if s["state"] == "CLOSE_WAIT":
            close_wait_pids.update(cw_map.get(s["inode"], []))
    result = {"port": port, "in_use": bool(services), "services": services, "connections": conns}
    if not services:
        result["message"] = f"No process is listening on port {port}."
        if conns.get("TIME_WAIT"):
            result["message"] += (f" {conns['TIME_WAIT']} closed connection(s) are in TIME_WAIT; they belong to no "
                                  "process and clear within 60 seconds.")
    if close_wait_pids:
        result["close_wait_holders"] = sorted(close_wait_pids)
        result["close_wait_note"] = "CLOSE_WAIT means the peer closed but this process never called close(): an app bug."
    return result


def get_process_details(pid: int) -> dict:
    pid = int(pid)
    base = _proc_basic(pid)
    f = _stat(pid)
    if not base or not f:
        return {"pid": pid, "error": "No such process (or not permitted)."}
    hz = os.sysconf("SC_CLK_TCK")
    uptime = float((_read(f"{PROC}/uptime") or "0").split()[0])
    age = uptime - int(f[19]) / hz
    cpu = (int(f[11]) + int(f[12])) / hz
    status = _read(f"{PROC}/{pid}/status") or ""
    rss = re.search(r"^VmRSS:\s+(\d+)", status, re.M)
    thr = re.search(r"^Threads:\s+(\d+)", status, re.M)
    ppid = int(f[1])
    return {**base, "state": f[0], "ppid": ppid, "parent": (_proc_basic(ppid) or {}).get("name"),
            "running_for_seconds": round(age), "cpu_time_seconds": round(cpu, 2),
            "lifetime_avg_cpu_percent": round(100 * cpu / age, 1) if age > 0 else 0,
            "memory_rss_mb": round(int(rss.group(1)) / 1024, 1) if rss else 0,
            "threads": int(thr.group(1)) if thr else 1, "managed_by": _supervisor(pid),
            "protected": not check_kill_safety(pid)[0]}


def check_kill_safety(pid: int) -> tuple[bool, str]:
    """Hard rules. Enforced in code; neither the LLM nor a 'yes' from the user can override them."""
    pid = int(pid)
    if pid <= 1:
        return False, "Refusing to signal PID 0/1 (init)."
    if pid in (os.getpid(), os.getppid()):
        return False, "Refusing to signal the agent or the shell running it."
    f = _stat(pid)
    info = _proc_basic(pid)
    if not f or not info:
        return False, f"PID {pid} does not exist."
    if int(f[6]) & PF_KTHREAD:
        return False, "Refusing to signal a kernel thread."
    if f[0] == "Z":
        return False, f"PID {pid} is a zombie: it has already exited and only its parent can reap it."
    if info["name"] in PROTECTED_NAMES:
        return False, f"'{info['name']}' is a protected system process."
    return True, "ok"


def send_signal(pid: int, signal_name: str = "SIGTERM", expected_start: int | None = None,
                wait_seconds: float = 3.0) -> dict:
    """Signal one exact process.

    pidfd_open() pins the process; we then confirm its start time matches the one recorded when it
    was looked up. If the PID was reused by a different process in between, nothing is sent.
    """
    pid = int(pid)
    if signal_name not in ALLOWED_SIGNALS:
        return {"ok": False, "error": f"Signal must be one of {list(ALLOWED_SIGNALS)}."}
    allowed, reason = check_kill_safety(pid)
    if not allowed:
        return {"ok": False, "error": reason}
    name = (_proc_basic(pid) or {}).get("name")
    sig = ALLOWED_SIGNALS[signal_name]

    pidfd = None
    try:
        if hasattr(os, "pidfd_open"):
            pidfd = os.pidfd_open(pid)
        if expected_start is not None and _starttime(pid) != expected_start:
            return {"ok": False, "error": f"PID {pid} now belongs to a different process (PID reused). "
                                          "Nothing was sent; look the port up again."}
        if pidfd is not None:
            signal.pidfd_send_signal(pidfd, sig)
            exited = bool(select.select([pidfd], [], [], float(wait_seconds))[0])  # readable on exit
        else:
            os.kill(pid, sig)
            exited = _wait_exit(pid, float(wait_seconds))
    except ProcessLookupError:
        return {"ok": True, "pid": pid, "exited": True, "message": f"PID {pid} had already exited."}
    except PermissionError:
        return {"ok": False, "error": f"Permission denied: PID {pid} belongs to another user. Re-run with sudo."}
    finally:
        if pidfd is not None:
            os.close(pidfd)

    res = {"ok": True, "pid": pid, "name": name, "signal": signal_name, "exited": exited}
    if not exited:
        res["message"] = f"Still running after {wait_seconds}s."
    return res


def _wait_exit(pid: int, timeout: float) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        f = _stat(pid)
        if not f or f[0] == "Z":
            return True
        time.sleep(0.1)
    return False


def _bind_probe(port: int) -> str:
    """Try to bind the port the way a server without SO_REUSEADDR would. Ground truth, then release."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("0.0.0.0", port))
        return "ok"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
    finally:
        s.close()


def verify_port_free(port: int) -> dict:
    """Is the port released? Separates 'no listener' from 'a new server can bind right now'."""
    port = int(port)
    res = find_process_by_port(port)
    tw = res["connections"].get("TIME_WAIT", 0)
    out = {"port": port, "free": not res["services"], "time_wait_connections": tw}
    if res["services"]:
        out["still_listening"] = res["services"]
        if any(s.get("managed_by") for s in res["services"]):
            out["note"] = "Port is held again; a supervisor may have restarted the service."
        return out
    probe = _bind_probe(port)
    out["bind_without_reuseaddr"] = probe
    if probe == "EADDRINUSE" and tw:
        out["note"] = (f"No process holds the port, but {tw} connection(s) in TIME_WAIT block servers that don't "
                       "set SO_REUSEADDR for up to 60 s. Most servers set it and can start now.")
    elif probe == "EACCES":
        out["note"] = "Ports below 1024 need root to bind; the port itself is free."
    return out


# Registry: name -> (function, destructive)
TOOLS = {
    "list_listening_ports": (list_listening_ports, False),
    "find_process_by_port": (find_process_by_port, False),
    "get_process_details": (get_process_details, False),
    "send_signal": (send_signal, True),
    "verify_port_free": (verify_port_free, False),
}

TOOL_SCHEMAS = [
    {"type": "function", "function": {
        "name": "list_listening_ports",
        "description": "List every listening port on this machine, grouped into services. Each service has a "
                       "target_pid (the master to stop) and its worker PIDs. Use this when the user did not give "
                       "a port number.",
        "parameters": {"type": "object", "properties": {
            "protocol": {"type": "string", "enum": ["tcp", "udp", "all"], "description": "Default all."}}}}},
    {"type": "function", "function": {
        "name": "find_process_by_port",
        "description": "Find what is listening on one port. Returns services with target_pid (the master process "
                       "to signal), workers, listening addresses, and managed_by (systemd/docker) if supervised.",
        "parameters": {"type": "object", "properties": {
            "port": {"type": "integer"},
            "protocol": {"type": "string", "enum": ["tcp", "udp", "all"]}}, "required": ["port"]}}},
    {"type": "function", "function": {
        "name": "get_process_details",
        "description": "Details of one PID: user, parent, uptime, CPU time, memory, supervisor, protected flag.",
        "parameters": {"type": "object", "properties": {"pid": {"type": "integer"}}, "required": ["pid"]}}},
    {"type": "function", "function": {
        "name": "send_signal",
        "description": "Stop a process. Signal the service's target_pid, never individual workers. Use SIGTERM "
                       "first. SIGKILL is accepted only after SIGTERM failed on that PID, or with force=true when "
                       "the user explicitly asked to force it. The user is asked to confirm.",
        "parameters": {"type": "object", "properties": {
            "pid": {"type": "integer"},
            "signal_name": {"type": "string", "enum": list(ALLOWED_SIGNALS)},
            "force": {"type": "boolean", "description": "Only if the user explicitly said force / kill -9."}},
            "required": ["pid"]}}},
    {"type": "function", "function": {
        "name": "verify_port_free",
        "description": "Check whether a port is released and whether a new server can bind it now.",
        "parameters": {"type": "object", "properties": {"port": {"type": "integer"}}, "required": ["port"]}}},
]
