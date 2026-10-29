"""
Port Sentinel local web app (Review 3 extension).

Runs on 127.0.0.1 only. It exposes the same five tools the agent uses, through a small
JSON API and one page. It does NOT run arbitrary code: every action is a fixed tool call.

  python3 web/server.py            then open http://127.0.0.1:8000

Guards:
  * binds to 127.0.0.1 only (not reachable from other machines)
  * every POST needs a random token that is printed at startup and embedded in the page
    (a web page in another tab cannot read it, so it cannot stop a process on your behalf)
  * the Host header must be 127.0.0.1 or localhost (blocks DNS-rebinding tricks)
  * stops go through the same safety gate as the agent: the PID must come from a lookup
    in this server session, hard rules apply, and the exact target is shown before it is sent
  * the page only offers SIGTERM. SIGKILL is left to the terminal, where the user types it
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from port_sentinel import tools as T                      # noqa: E402
from port_sentinel.agent import run_tool                  # noqa: E402
from port_sentinel.safety import Session, describe_action, precheck  # noqa: E402

HOST = "127.0.0.1"
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}

TOKEN = secrets.token_urlsafe(24)
SESSION = Session("")          # one shared ledger: a PID must be looked up here before it can be stopped


def _json(handler, status, body):
    data = json.dumps(body, indent=2).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def _page() -> bytes:
    with open(os.path.join(HERE, "index.html"), "r", encoding="utf-8") as f:
        return f.read().replace("__TOKEN__", TOKEN).encode()


def _int(value, name):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a whole number")


class Handler(BaseHTTPRequestHandler):
    server_version = "PortSentinel/3"

    def log_message(self, fmt, *args):      # keep the terminal quiet; the audit log has the decisions
        pass

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ALLOWED_HOSTS

    def do_GET(self):
        if not self._host_ok():
            return _json(self, 403, {"error": "Host not allowed"})
        url = urlparse(self.path)
        parts = [p for p in url.path.split("/") if p]
        try:
            if url.path in ("/", "/index.html"):
                data = _page()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return self.wfile.write(data)
            if parts == ["api", "ports"]:
                return _json(self, 200, run_tool("list_listening_ports", {}, SESSION, _no, True))
            if len(parts) == 3 and parts[:2] == ["api", "port"]:
                port = _int(parts[2], "port")
                return _json(self, 200, run_tool("find_process_by_port", {"port": port}, SESSION, _no, True))
            if len(parts) == 3 and parts[:2] == ["api", "free"]:
                port = _int(parts[2], "port")
                return _json(self, 200, run_tool("verify_port_free", {"port": port}, SESSION, _no, True))
            if len(parts) == 3 and parts[:2] == ["api", "info"]:
                pid = _int(parts[2], "pid")
                return _json(self, 200, run_tool("get_process_details", {"pid": pid}, SESSION, _no, True))
            return _json(self, 404, {"error": "Not found"})
        except ValueError as e:
            return _json(self, 400, {"error": str(e)})

    def do_POST(self):
        if not self._host_ok():
            return _json(self, 403, {"error": "Host not allowed"})
        if self.headers.get("X-Token") != TOKEN:
            return _json(self, 403, {"error": "Missing or wrong token. Reload the page from the local server."})
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            pid = _int(body.get("pid"), "pid")
        except (ValueError, json.JSONDecodeError):
            return _json(self, 400, {"error": "Body must be JSON with a whole-number pid"})

        args = {"pid": pid, "signal_name": "SIGTERM", "force": False}
        if self.path == "/api/stop/preview":
            err = precheck(args, SESSION)
            if err:
                return _json(self, 200, {"allowed": False, "reason": err})
            allowed, reason = T.check_kill_safety(pid)
            if not allowed:
                return _json(self, 200, {"allowed": False, "reason": f"Blocked by safety policy: {reason}"})
            return _json(self, 200, {"allowed": True, "preview": describe_action(args, SESSION)})

        if self.path == "/api/stop":
            if body.get("confirmed") is not True:
                return _json(self, 400, {"error": "The stop must be confirmed in the page first"})
            # The page showed the exact preview and the user accepted it, so the gate's own prompt is answered yes.
            result = run_tool("send_signal", args, SESSION, lambda _msg: True, False)
            return _json(self, 200, result)
        return _json(self, 404, {"error": "Not found"})


def _no(_message: str) -> bool:
    return False


def main(port: int = 8000) -> None:
    srv = ThreadingHTTPServer((HOST, port), Handler)
    print(f"Port Sentinel web app running.\n  open: http://{HOST}:{port}\n  stop: Ctrl+C")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        srv.server_close()


if __name__ == "__main__":
    main(int(os.environ.get("PORT", "8000")))
