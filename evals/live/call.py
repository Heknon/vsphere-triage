"""Call one vsphere-triage tool on the running eval world and print its result.

    python call.py <run-id> <tool> ['{"arg": "value"}']

A shell tool cuts long output (Claude Code's at 30,000 characters) where an MCP
client would show the whole result, so a longer one is also written next to
this script, under results/, and the printout says where.
"""

import json
import sys
import urllib.request
from pathlib import Path

SHELL_CUT = 25_000

run, tool = sys.argv[1], sys.argv[2]
arguments = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
request = urllib.request.Request(
    "http://127.0.0.1:8765/call",
    data=json.dumps({"run": run, "tool": tool, "arguments": arguments}).encode(),
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(request, timeout=330) as response:
    text = response.read().decode()
if len(text) <= SHELL_CUT:
    print(text)
else:
    saved = Path(__file__).resolve().parent / "results" / f"{run}-{tool}-{len(text)}.json"
    saved.parent.mkdir(exist_ok=True)
    saved.write_text(text)
    print(f"[{len(text)} characters: the whole result is in {saved}; read that file]\n")
    print(text[:SHELL_CUT])
