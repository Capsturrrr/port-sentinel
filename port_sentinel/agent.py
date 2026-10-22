"""
Port Sentinel - LLM agent loop (Review 2).

handle(prompt) is the entry point the base shell calls after routing. Works with any
OpenAI-compatible endpoint (Gemini, Groq, Ollama, OpenAI) selected by environment variables.

Guards that live in code, not in the prompt:
  * PIDs must come from an earlier lookup; SIGKILL needs a failed SIGTERM or the user's own "force"
  * after a successful stop the port is re-checked automatically
  * a repeated identical tool call is refused; a third repeat ends the loop
  * when the step budget runs out the model must summarise (tool_choice="none")
  * rate limits (HTTP 429) and transient 5xx errors are retried with backoff
"""

from __future__ import annotations

import json
import os
import time

from . import tools as T
from .safety import ConfirmFn, Session, gate, terminal_confirm

PROVIDERS = {
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai/", "gemini-2.5-flash", "GEMINI_API_KEY"),
    "groq":   ("https://api.groq.com/openai/v1", "llama-3.3-70b-versatile", "GROQ_API_KEY"),
    "ollama": ("http://localhost:11434/v1", "qwen2.5:7b", None),
    "openai": ("https://api.openai.com/v1", "gpt-4o-mini", "OPENAI_API_KEY"),
}

SYSTEM_PROMPT = """You are Port Sentinel, an agent inside a Linux natural-language shell.
You find which process is using a network port and stop it, using ONLY the provided tools.

How to work:
1. Facts come from tools. Never state or use a PID, port or process name you did not get from a tool.
2. If the user gave a port number, call find_process_by_port. If not (e.g. "my web port", "the dev server"),
   call list_listening_ports and match their words against what is actually listening
   (web: 80, 443, 8000, 8080, 3000, 5000, 5173; databases: 5432, 3306, 6379, 27017).
   - Exactly one match: proceed. The user's y/N confirmation is the check.
   - Several matches: list them briefly and ask which one. Stop there.
   - None: say nothing matching is listening.
3. Each service has a target_pid (the master) and workers. Signal target_pid only; workers stop with it.
4. If managed_by is systemd or docker, do not signal it. Tell the user the exact stop command from managed_by.advice
   (a supervisor would restart it). Only signal it if the user insists after hearing that.
5. Stop with SIGTERM. Use SIGKILL only if SIGTERM left the process running, or the user said force / kill -9
   (then pass force=true).
6. The system re-checks the port after a successful stop (auto_verify in the result). Report what it says.
7. If a tool returns an error (permission denied, blocked, declined), explain it plainly with the fix it suggests.
   Never retry a declined or blocked action and never try to work around one.
8. Requests not about ports or the processes on them belong to another agent: say so.
9. Never ask the user yes/no before stopping. When you have exactly one match, call send_signal directly; the system asks the user to confirm.

Answer in 1-3 short sentences: what was on the port (port, PID, name), what you did, and the result."""

MAX_STEPS = 8


def _client():
    from openai import OpenAI
    provider = os.getenv("LLM_PROVIDER", "gemini")
    base, model, key_env = PROVIDERS.get(provider, PROVIDERS["gemini"])
    base = os.getenv("LLM_BASE_URL", base)
    model = os.getenv("LLM_MODEL", model)
    key = os.getenv("LLM_API_KEY") or (os.getenv(key_env) if key_env else None) or "none"
    return OpenAI(base_url=base, api_key=key, max_retries=0), model


def _complete(client, model, messages, tool_choice="auto", attempts=5):
    """One chat completion with backoff on 429 / 5xx."""
    delay = 2.0
    for i in range(attempts):
        try:
            return client.chat.completions.create(model=model, messages=messages, tools=T.TOOL_SCHEMAS,
                                                  tool_choice=tool_choice, temperature=0)
        except Exception as e:
            status = getattr(e, "status_code", None)
            if status in (429, 500, 502, 503, 504) and i < attempts - 1:
                time.sleep(delay)
                delay *= 2
                continue
            raise


def run_tool(name: str, args: dict, session: Session, confirm: ConfirmFn, auto_yes: bool) -> dict:
    if name not in T.TOOLS:
        return {"error": f"Unknown tool {name}"}
    fn, destructive = T.TOOLS[name]
    try:
        if not destructive:
            result = fn(**args)
            session.record(result)
            return result

        ok, reason = gate(args, session, confirm, auto_yes)
        if not ok:
            return {"ok": False, "error": reason}
        pid, sig = args["pid"], args.get("signal_name", "SIGTERM")
        result = T.send_signal(pid, sig, expected_start=session.observed.get(pid))
        if result.get("ok") and sig == "SIGTERM" and not result.get("exited"):
            session.sigterm_sent.add(pid)     # SIGTERM was ignored: SIGKILL is now justified
        if result.get("ok") and result.get("exited"):
            ports = session.ports_of.get(pid, set())
            if ports:
                result["auto_verify"] = [T.verify_port_free(p) for p in sorted(ports)]
                session.record(result["auto_verify"])
        return result
    except TypeError as e:
        return {"error": f"Bad arguments: {e}"}
    except Exception as e:                     # a tool error must never crash the shell
        return {"error": f"{type(e).__name__}: {e}"}


def handle(prompt: str, confirm: ConfirmFn = terminal_confirm, auto_yes: bool = False,
           verbose: bool = False, history: list | None = None, trace: list | None = None) -> str:
    """Entry point for the base shell. Returns the final natural-language answer.

    trace, if given, receives one dict per tool call (used by the evaluation harness).
    """
    client, model = _client()
    session = Session(prompt)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, *(history or []),
                {"role": "user", "content": prompt}]
    seen: dict[str, int] = {}

    for _ in range(MAX_STEPS):
        msg = _complete(client, model, messages).choices[0].message
        if not msg.tool_calls:
            return msg.content or "(no answer)"
        messages.append(msg.model_dump(exclude_none=True))   # keep provider-specific fields intact

        stop = False
        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            key = f"{tc.function.name}:{json.dumps(args, sort_keys=True)}"
            seen[key] = seen.get(key, 0) + 1
            if seen[key] == 2:
                result = {"error": "You already made this exact call; use the earlier result or give your final answer."}
            elif seen[key] >= 3:
                result, stop = {"error": "Repeated call refused."}, True
            else:
                result = run_tool(tc.function.name, args, session, confirm, auto_yes)
            if verbose:
                print(f"  → {tc.function.name}({args})\n  ← {json.dumps(result)[:240]}")
            if trace is not None:
                trace.append({"tool": tc.function.name, "args": args, "result": result})
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result)})
        if stop:
            break

    # Out of steps or looping: make the model summarise from what it has.
    messages.append({"role": "user", "content": "Stop calling tools. Summarise what happened for the user."})
    msg = _complete(client, model, messages, tool_choice="none").choices[0].message
    return msg.content or "Stopped without a final answer."
