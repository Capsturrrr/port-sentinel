"""Local web app: guards on the API and one real stop through it."""

import importlib.util
import json
import os
import re
import threading
import time
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

import pytest

from .conftest import free_port, kill_group, start_http

_spec = importlib.util.spec_from_file_location(
    "port_sentinel_web", os.path.join(os.path.dirname(__file__), "..", "web", "server.py"))
W = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(W)


@pytest.fixture
def web():
    port = free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), W.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port
    srv.shutdown()
    srv.server_close()


def call(port, method, path, body=None, host="127.0.0.1", token=None):
    conn = HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": f"{host}:{port}", "Content-Type": "application/json"}
    if token:
        headers["X-Token"] = token
    data = json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=data, headers=headers)
    res = conn.getresponse()
    out = json.loads(res.read() or b"{}")
    conn.close()
    return res.status, out


def test_page_is_served_with_token(web):
    conn = HTTPConnection("127.0.0.1", web, timeout=10)
    conn.request("GET", "/", headers={"Host": f"127.0.0.1:{web}"})
    html = conn.getresponse().read().decode()
    assert f'const TOKEN = "{W.TOKEN}"' in html
    assert "__TOKEN__" not in html


def test_foreign_host_is_rejected(web):
    status, body = call(web, "GET", "/api/ports", host="evil.example")
    assert status == 403


def test_post_without_token_is_rejected(web):
    status, body = call(web, "POST", "/api/stop/preview", {"pid": 1})
    assert status == 403 and "token" in body["error"].lower()


def test_unseen_pid_is_refused(web):
    status, body = call(web, "POST", "/api/stop/preview", {"pid": 999999}, token=W.TOKEN)
    assert status == 200 and body["allowed"] is False
    assert "never guess a PID" in body["reason"]


def test_stop_requires_confirmation(web):
    status, body = call(web, "POST", "/api/stop", {"pid": 999999}, token=W.TOKEN)
    assert status == 400 and "confirmed" in body["error"]


def test_bad_port_is_a_clean_error(web):
    status, body = call(web, "GET", "/api/port/notanumber")
    assert status == 400


def test_full_stop_through_the_web_api(web):
    port = free_port()
    proc = start_http(port, "127.0.0.1")
    try:
        status, found = call(web, "GET", f"/api/port/{port}")
        assert status == 200
        pid = found["services"][0]["target_pid"]
        assert pid == proc.pid

        status, pre = call(web, "POST", "/api/stop/preview", {"pid": pid}, token=W.TOKEN)
        assert pre["allowed"] is True and str(pid) in pre["preview"]

        status, out = call(web, "POST", "/api/stop", {"pid": pid, "confirmed": True}, token=W.TOKEN)
        assert out["ok"] is True and out["exited"] is True
        assert out["auto_verify"][0]["free"] is True
        proc.wait(timeout=5)
    finally:
        kill_group(proc)
