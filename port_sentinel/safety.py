"""
Safety layer (Review 2).

The LLM only proposes tool calls. Before a signal is sent, code checks, in order:
  1. the PID was returned by a lookup in this session (no invented PIDs)
  2. SIGKILL only after SIGTERM failed on that PID, or the user's own words asked to force it
  3. hard rules (init, the agent itself, kernel threads, zombies, protected daemons)
  4. the user confirms, seeing exactly what will be stopped
Every decision is appended to an audit log.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Callable

from .tools import _starttime, check_kill_safety, get_process_details

LOG_FILE = os.path.expanduser("~/.port_sentinel_audit.log")
FORCE_WORDS = re.compile(r"\bforce\w*|kill\s+-9|\bsigkill\b|\bhard[- ]kill", re.I)

ConfirmFn = Callable[[str], bool]


def terminal_confirm(message: str) -> bool:
    try:
        return input(f"{message}\nProceed? [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


class Session:
    """What this conversation has actually seen. The source of truth for the guards."""

    def __init__(self, user_prompt: str = ""):
        self.user_prompt = user_prompt
        self.observed: dict[int, int | None] = {}   # pid -> start time when it was looked up
        self.workers_of: dict[int, list[int]] = {}  # target pid -> worker pids
        self.ports_of: dict[int, set[int]] = {}     # pid -> ports it was seen listening on
        self.sigterm_sent: set[int] = set()

    def record(self, result) -> None:
        """Remember every PID that appears in a tool result."""
        if isinstance(result, dict):
            pid = result.get("pid")
            if isinstance(pid, int):
                self.observed.setdefault(pid, result.get("start_time"))
            if isinstance(result.get("target"), dict):
                tgt = result["target"]
                self.observed[tgt["pid"]] = tgt.get("start_time")
                self.workers_of[tgt["pid"]] = result.get("workers", [])
                if isinstance(result.get("port"), int):
                    self.ports_of.setdefault(tgt["pid"], set()).add(result["port"])
            for w in result.get("workers", []) or []:
                if isinstance(w, int):
                    self.observed.setdefault(w, _starttime(w))
            for v in result.values():
                if isinstance(v, (dict, list)):
                    self.record(v)
        elif isinstance(result, list):
            for v in result:
                self.record(v)

    def user_asked_to_force(self) -> bool:
        return bool(FORCE_WORDS.search(self.user_prompt))


def precheck(args: dict, session: Session) -> str | None:
    """Session-level rules. Returns an error string, or None if the call may go to confirmation."""
    pid, sig = args.get("pid"), args.get("signal_name", "SIGTERM")
    if not isinstance(pid, int) or pid not in session.observed:
        return (f"PID {pid} has not been returned by any lookup in this session. "
                "Call find_process_by_port or list_listening_ports first; never guess a PID.")
    if sig == "SIGKILL" and pid not in session.sigterm_sent:
        if not (args.get("force") and session.user_asked_to_force()):
            return "SIGKILL refused: send SIGTERM first. SIGKILL is allowed only if SIGTERM fails or the user asks to force it."
    return None


def describe_action(args: dict, session: Session) -> str:
    pid, sig = args["pid"], args.get("signal_name", "SIGTERM")
    d = get_process_details(pid)
    if "error" in d:
        return f"Send {sig} to PID {pid} ({d['error']})"
    verb = "FORCE-KILL" if sig == "SIGKILL" else "Stop"
    lines = [f"⚠  {verb} PID {pid} '{d['name']}' (user {d['user']}, running {d['running_for_seconds']}s)",
             f"   command: {d['cmdline'][:100]}", f"   signal:  {sig}"]
    workers = session.workers_of.get(pid)
    if workers:
        lines.append(f"   workers: {len(workers)} child process(es) {workers[:6]} will stop with it")
    if d.get("managed_by"):
        lines.append(f"   note:    {d['managed_by']['advice']}")
    return "\n".join(lines)


def gate(args: dict, session: Session, confirm: ConfirmFn, auto_yes: bool = False) -> tuple[bool, str]:
    err = precheck(args, session)
    if err:
        audit(args, "REFUSED", err)
        return False, err
    allowed, reason = check_kill_safety(args["pid"])
    if not allowed:
        audit(args, "BLOCKED", reason)
        return False, f"Blocked by safety policy: {reason}"
    preview = describe_action(args, session)
    ok = auto_yes or confirm(preview)
    audit(args, "APPROVED" if ok else "DECLINED", preview.splitlines()[0])
    return ok, "approved" if ok else "User declined. Do not retry; tell the user nothing was changed."


def audit(args: dict, decision: str, detail: str) -> None:
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{datetime.now().isoformat(timespec='seconds')} {decision:8} send_signal "
                    f"{json.dumps(args)} | {detail}\n")
    except OSError:
        pass
