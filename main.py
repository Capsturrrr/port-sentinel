#!/usr/bin/env python3
"""
Port Sentinel CLI.

  python3 main.py                         interactive natural-language mode (needs an LLM key)
  python3 main.py "who is on port 8080?"  one-shot
  python3 main.py --direct ports          call tools directly, no LLM (useful for Review 1 demo)
  python3 main.py --direct port 8080
  python3 main.py --direct info 1234
  python3 main.py --direct kill 1234 [SIGKILL]
"""

import json
import sys

from port_sentinel.agent import handle, run_tool
from port_sentinel.safety import Session, terminal_confirm


def direct(argv: list[str]) -> None:
    cmd, rest = argv[0], argv[1:]
    calls = {
        "ports": ("list_listening_ports", {}),
        "port": ("find_process_by_port", {"port": int(rest[0])} if rest else None),
        "info": ("get_process_details", {"pid": int(rest[0])} if rest else None),
        "kill": ("send_signal", {"pid": int(rest[0]), "signal_name": rest[1] if len(rest) > 1 else "SIGTERM"} if rest else None),
        "free": ("verify_port_free", {"port": int(rest[0])} if rest else None),
    }
    if cmd not in calls or calls[cmd][1] is None:
        print(__doc__)
        return
    name, args = calls[cmd]
    # A human typing SIGKILL in direct mode is an explicit request to force.
    session = Session("kill -9" if args.get("signal_name") == "SIGKILL" else "")
    if name == "send_signal":
        args["force"] = args["signal_name"] == "SIGKILL"
        for tool, a in (("list_listening_ports", {}), ("get_process_details", {"pid": args["pid"]})):
            run_tool(tool, a, session, terminal_confirm, False)   # observe the PID (and its workers) first
    print(json.dumps(run_tool(name, args, session, terminal_confirm, False), indent=2))


def main() -> None:
    args = sys.argv[1:]
    verbose = "-v" in args
    args = [a for a in args if a != "-v"]
    if args and args[0] == "--direct":
        direct(args[1:] or ["help"])
        return
    if args:
        print(handle(" ".join(args), verbose=verbose))
        return
    print("Port Sentinel — ask about ports in plain English. Ctrl+D to exit.")
    while True:
        try:
            q = input("\nsentinel> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if q:
            try:
                print(handle(q, verbose=verbose))
            except Exception as e:
                print(f"LLM error: {e}")


if __name__ == "__main__":
    main()
