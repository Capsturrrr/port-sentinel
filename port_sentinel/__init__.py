"""Port Sentinel Agent (#16) for the Agentic Shell."""
from .agent import handle

AGENT_NAME = "port_sentinel"
AGENT_DESCRIPTION = ("Finds which process is using a network port, lists listening ports, "
                     "and stops processes to free a port.")
__all__ = ["handle", "AGENT_NAME", "AGENT_DESCRIPTION"]
