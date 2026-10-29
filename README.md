# Port Sentinel Agent (#16) — Agentic Shell

[![ci](https://github.com/Capsturrrr/port-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Capsturrrr/port-sentinel/actions/workflows/ci.yml)

Natural-language agent that finds which process is using a port and frees it.

> "What process is hogging port 8080? Stop it."

## How it works

```
user text ─► base shell router ─► port_sentinel.handle(prompt)
                                       │
                         LLM (function calling) ◄─────────────┐
                                       │ proposes a tool call  │ JSON result
                                       ▼                       │
              code guards: seen PID? SIGTERM first? hard rules? user y/N
                                       ▼                       │
       tools.py ─ /proc/net/tcp*, /proc/<pid>/fd, pidfd_send_signal(2), bind(2) probe
```

| Tool | What it does | OS interface |
|---|---|---|
| `list_listening_ports` | Listening ports grouped into services (master + workers) | `/proc/net/{tcp,tcp6,udp,udp6}` |
| `find_process_by_port` | Who listens on port N; TIME_WAIT / CLOSE_WAIT summary | inode → `readlink(/proc/<pid>/fd/*)` |
| `get_process_details` | User, parent, uptime, CPU, RAM, systemd/docker supervisor | `/proc/<pid>/{stat,status,cmdline,cgroup}` |
| `send_signal` ⚠ | Signal one exact process, refuses reused PIDs | `pidfd_open(2)` + `pidfd_send_signal(2)` |
| `verify_port_free` | No listener left? Can a new server bind now? | socket table + `bind(2)` probe |

## Safety (all enforced in code)

1. The PID must have come from a lookup in this session (no invented PIDs).
2. SIGKILL only after SIGTERM failed, or when the user's own words say force / kill -9.
3. Hard rules: PID 1, the agent and its shell, kernel threads (PF_KTHREAD), zombies, protected daemons.
4. The user confirms, seeing the process, its workers and any supervisor warning.
5. The kill is pinned with a pidfd and the process start time is re-checked, so a reused PID is never hit.

Every decision is logged to `~/.port_sentinel_audit.log`.

## Setup and run

```bash
pip install -r requirements.txt
export GEMINI_API_KEY=...            # free key: aistudio.google.com  (never commit it)
python3 main.py -v "what's hogging port 8080? stop it"
python3 main.py --direct port 8080   # tools only, no LLM
```

Other providers: `LLM_PROVIDER=groq GROQ_API_KEY=...` or `LLM_PROVIDER=ollama`.

## Local web app

```bash
python3 web/server.py          # then open http://127.0.0.1:8000 in your browser
```

The page lists ports, finds the process on a port, checks whether a port is free, and stops a
process with SIGTERM after a confirmation that shows the exact target. It runs only on this
computer (bound to 127.0.0.1), and it does not run arbitrary code. SIGKILL is not offered in the
page; use the terminal for that.

## Tests and evaluation

```bash
python3 -m pytest -q                  # 42 tests, real processes on real ports, no API key
python3 eval/run_eval.py --runs 3     # 12 live-LLM scenarios -> eval/results.json
python3 eval/run_eval.py --check-setup
```

## Integration with the base shell

```python
from port_sentinel import handle, AGENT_NAME, AGENT_DESCRIPTION
answer = handle(user_text, confirm=shell_confirm_fn)
```

## Licence

MIT. See [LICENSE](LICENSE).
