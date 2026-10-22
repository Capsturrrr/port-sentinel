"""
Agent loop with a scripted stand-in for the LLM, so the guards can be tested without an API key.
The scripted model deliberately misbehaves (invented PIDs, early SIGKILL, loops) to prove the
code-level guards hold no matter what the model does.
"""

import json
from types import SimpleNamespace as NS

from port_sentinel import agent, tools

from .conftest import free_port, kill_group, start_http, start_prefork


class Msg:
    def __init__(self, content=None, calls=None):
        self.content, self.tool_calls = content, calls or None

    def model_dump(self, exclude_none=False):
        d = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            d["tool_calls"] = [{"id": c.id, "type": "function",
                                "function": {"name": c.function.name, "arguments": c.function.arguments}}
                               for c in self.tool_calls]
        return {k: v for k, v in d.items() if v is not None} if exclude_none else d


class ScriptedLLM:
    """policy(step, last_tool_result) -> list of (tool, args) or a final string."""

    def __init__(self, policy):
        self.policy, self.step, self.tool_choices = policy, 0, []
        self.chat = NS(completions=NS(create=self.create))

    def create(self, model, messages, tools, tool_choice, temperature):
        self.tool_choices.append(tool_choice)
        if tool_choice == "none":
            return NS(choices=[NS(message=Msg("summary"))])
        self.step += 1
        last = json.loads(messages[-1]["content"]) if messages[-1]["role"] == "tool" else None
        out = self.policy(self.step, last)
        if isinstance(out, str):
            return NS(choices=[NS(message=Msg(out))])
        calls = [NS(id=f"c{self.step}{i}", function=NS(name=n, arguments=json.dumps(a))) for i, (n, a) in enumerate(out)]
        return NS(choices=[NS(message=Msg("", calls))])


def use(monkeypatch, policy):
    llm = ScriptedLLM(policy)
    monkeypatch.setattr(agent, "_client", lambda: (llm, "scripted"))
    return llm


def find_kill_answer(port):
    state = {}

    def policy(step, last):
        if step == 1:
            return [("find_process_by_port", {"port": port})]
        if step == 2:
            state["pid"] = last["services"][0]["target_pid"]
            return [("send_signal", {"pid": state["pid"], "signal_name": "SIGTERM"})]
        if not last.get("ok"):
            return "Nothing was changed."
        return f"free={last['auto_verify'][0]['free']}"
    return policy


def test_find_kill_and_auto_verify(monkeypatch):
    port = free_port()
    p = start_http(port)
    use(monkeypatch, find_kill_answer(port))
    asked, trace = [], []
    out = agent.handle("stop whatever is on the port", confirm=lambda m: asked.append(m) or True, trace=trace)
    p.wait(timeout=5)
    assert out == "free=True" and "http.server" in asked[0]
    assert [t["tool"] for t in trace] == ["find_process_by_port", "send_signal"]


def test_decline_is_respected(monkeypatch):
    port = free_port()
    p = start_http(port)
    try:
        use(monkeypatch, find_kill_answer(port))
        assert agent.handle("stop it", confirm=lambda m: False) == "Nothing was changed."
        assert p.poll() is None
    finally:
        p.kill(); p.wait()


def test_invented_pid_is_refused_before_confirmation(monkeypatch):
    port = free_port()
    p = start_http(port)
    try:
        use(monkeypatch, lambda step, last: [("send_signal", {"pid": p.pid})] if step == 1 else last["error"])
        asked = []
        out = agent.handle("kill the server", confirm=lambda m: asked.append(m) or True)
        assert "has not been returned by any lookup" in out and asked == [] and p.poll() is None
    finally:
        p.kill(); p.wait()


def test_sigkill_needs_sigterm_first(monkeypatch):
    port = free_port()
    p = start_http(port)
    try:
        def policy(step, last):
            if step == 1:
                return [("find_process_by_port", {"port": port})]
            if step == 2:
                return [("send_signal", {"pid": p.pid, "signal_name": "SIGKILL", "force": True})]
            return last.get("error", "done")
        use(monkeypatch, policy)
        out = agent.handle("stop the server on that port", confirm=lambda m: True)   # user never said force
        assert "SIGKILL refused" in out and p.poll() is None
    finally:
        p.kill(); p.wait()


def test_user_force_allows_sigkill(monkeypatch):
    port = free_port()
    p = start_http(port)
    def policy(step, last):
        if step == 1:
            return [("find_process_by_port", {"port": port})]
        if step == 2:
            return [("send_signal", {"pid": p.pid, "signal_name": "SIGKILL", "force": True})]
        return "killed" if last.get("ok") else last["error"]
    use(monkeypatch, policy)
    asked = []
    assert agent.handle(f"force kill whatever is on {port}", confirm=lambda m: asked.append(m) or True) == "killed"
    p.wait(timeout=5)
    assert "FORCE-KILL" in asked[0]


def test_worker_pool_confirmation_names_the_workers(monkeypatch):
    port = free_port()
    p = start_prefork(port, workers=3)
    try:
        use(monkeypatch, find_kill_answer(port))
        asked = []
        out = agent.handle("stop the app server", confirm=lambda m: asked.append(m) or True)
        p.wait(timeout=5)
        assert f"PID {p.pid}" in asked[0] and "3 child process(es)" in asked[0]
        assert out == "free=True"
    finally:
        kill_group(p)


def test_repeated_call_ends_loop_with_summary(monkeypatch):
    llm = use(monkeypatch, lambda step, last: [("list_listening_ports", {})])
    trace = []
    assert agent.handle("what ports are open", trace=trace) == "summary"
    assert len(trace) == 3 and "already made this exact call" in trace[1]["result"]["error"]
    assert llm.tool_choices[-1] == "none"


def test_step_budget_forces_summary(monkeypatch):
    llm = use(monkeypatch, lambda step, last: [("get_process_details", {"pid": 100000 + step})])
    assert agent.handle("look around") == "summary"
    assert llm.step == agent.MAX_STEPS and llm.tool_choices[-1] == "none"


def test_rate_limit_is_retried(monkeypatch):
    calls = {"n": 0}

    class RateLimited(Exception):
        status_code = 429

    def create(**kw):
        calls["n"] += 1
        if calls["n"] < 3:
            raise RateLimited()
        return NS(choices=[NS(message=Msg("ok"))])
    monkeypatch.setattr(agent, "_client", lambda: (NS(chat=NS(completions=NS(create=create))), "m"))
    monkeypatch.setattr(agent.time, "sleep", lambda s: None)
    assert agent.handle("hi") == "ok" and calls["n"] == 3
