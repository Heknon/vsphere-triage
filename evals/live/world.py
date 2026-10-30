"""Serve the real tool surface over two simulated vCenters, for a model to drive.

Builds the integration scenario (tests/integration/scenario.py) in Docker, with
its controlled performance counters, and answers `POST /call` with what the
MCP client would receive. Every call is appended to runs/<run>.jsonl, so a run
can be scored on which tools it used and how much it read. Also writes
tools.md: the server instructions and tool list, as the model would see them.

    uv run python evals/live/world.py          # leave running; Ctrl-C stops the vCenters
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "tests" / "integration"))

import scenario  # noqa: E402
from conftest import Plan  # noqa: E402

from vsphere_triage.config import Settings  # noqa: E402
from vsphere_triage.server import INSTRUCTIONS, build_server  # noqa: E402
from vsphere_triage.vcenter import VCenterSession  # noqa: E402

PORT = 8765
RUNS = HERE / "runs"


def tools_markdown(tools: list[Any]) -> str:
    parts = ["# Server instructions\n", INSTRUCTIONS, "\n# Tools\n"]
    for tool in tools:
        schema = tool.input_schema.get("properties", {})
        required = set(tool.input_schema.get("required", []))
        params = ", ".join(  # name?: type, optional ones marked
            f"{name}{'' if name in required else '?'}: {spec.get('type', 'any')}"
            for name, spec in schema.items()
        )
        acts = tool.annotations and tool.annotations.read_only_hint is False
        flag = "  [NOT read-only]" if acts else ""
        parts.append(f"\n## {tool.name}({params}){flag}\n\n{tool.description}\n")
    return "".join(parts)


def main() -> None:
    work = Path(tempfile.mkdtemp(prefix="vcsim-"))
    a, b = scenario.fleet(work)
    plan = Plan(a)

    # A plain function, so it binds to each session; Plan.perf takes that session first.
    def perf(session: VCenterSession, *args: Any, **kwargs: Any) -> Any:
        return plan.perf(session, *args, **kwargs)

    VCenterSession.perf = perf  # type: ignore[method-assign]
    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": (
                f'[{{"name": "vc-a", "host": "127.0.0.1", "port": {a.port}, "aliases": ["vca.lab.example"]}},'
                f' {{"name": "vc-b", "host": "localhost", "port": {b.port}}}]'
            ),
            "VSPHERE_USERNAME": "user",
            "VSPHERE_PASSWORD": "pass",
            "VSPHERE_TLS_VERIFY": "0",
            "VSPHERE_ENV_PARENT_HINTS": "environments,projects",
        }
    )
    server = build_server(settings)
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True).start()
    tools = asyncio.run_coroutine_threadsafe(server.list_tools(), loop).result()
    (HERE / "tools.md").write_text(tools_markdown(tools))
    RUNS.mkdir(exist_ok=True)
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            started = time.monotonic()
            try:
                result = asyncio.run_coroutine_threadsafe(
                    server.call_tool(body["tool"], body.get("arguments") or {}), loop
                ).result(timeout=300)
                if result.structured_content is not None and not result.is_error:
                    text = json.dumps(result.structured_content, indent=2)
                else:
                    text = "\n".join(getattr(part, "text", "") for part in result.content)
                error = bool(result.is_error)
                content = result.structured_content or {}
                # Some results name the VM under "vm", others at the top level.
                vm = content.get("vm") if isinstance(content.get("vm"), dict) else content
            except Exception as failure:  # noqa: BLE001 - the model sees the error, as a client would
                text, error, vm = f"Error: {failure}", True, {}
            with lock, (RUNS / f"{body.get('run', 'adhoc')}.jsonl").open("a") as log:
                log.write(
                    json.dumps(
                        {
                            "tool": body["tool"],
                            "arguments": body.get("arguments"),
                            "error": error,
                            "vm": [
                                vm.get("vcenter") or (body.get("arguments") or {}).get("vcenter"),
                                vm.get("moref") or (body.get("arguments") or {}).get("moref"),
                            ],
                            "characters": len(text),
                            "seconds": round(time.monotonic() - started, 1),
                        }
                    )
                    + "\n"
                )
            payload = text.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_: Any) -> None:
            pass

    print(f"ready on 127.0.0.1:{PORT}: vc-a :{a.port}, vc-b :{b.port}; {len(tools)} tools", flush=True)
    try:
        ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    finally:
        for world in (a, b):
            scenario.stop(world.container)


if __name__ == "__main__":
    main()
