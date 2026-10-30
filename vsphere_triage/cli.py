"""The command line: which transport to serve on. Everything else is configuration."""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import Annotated, Optional

import typer
from mcp.server.transport_security import TransportSecuritySettings

from vsphere_triage.config import Settings
from vsphere_triage.server import build_server


class Transport(StrEnum):
    """How MCP clients reach this server."""

    stdio = "stdio"
    http = "streamable-http"


app = typer.Typer(
    name="vsphere-triage",
    help="Read-only vSphere fleet triage over MCP (optional vROps history).",
    invoke_without_command=True,
    no_args_is_help=False,
    add_completion=False,
    pretty_exceptions_enable=False,
)


@app.callback()
def serve(
    *,
    transport: Annotated[Transport, typer.Option(help="How MCP clients connect.")] = Transport.stdio,
    host: Annotated[str, typer.Option(help="HTTP bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1, max=65535, help="HTTP bind port.")] = 8000,
    path: Annotated[str, typer.Option(help="Streamable HTTP endpoint path.")] = "/mcp",
    allowed_host: Annotated[
        Optional[list[str]],  # noqa: UP045 - read by older Typer too
        typer.Option(help="Allowed HTTP Host header; repeatable."),
    ] = None,
) -> None:
    """Start the server; stdio is the default for a local client."""
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        settings = Settings.from_environment()
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error
    if not settings.vcenters:
        msg = "VSPHERE_VCENTERS is empty: configure at least one vCenter"
        raise typer.BadParameter(msg)
    names = ", ".join(vcenter.name for vcenter in settings.vcenters)
    # Over HTTP anyone who reaches the port is a caller, so the one tool that acts
    # on a guest is left out unless explicitly asked for.
    guest_exec = transport == Transport.stdio or settings.guest_exec_over_http
    mode = "read-only, plus run_in_guest" if guest_exec else "read-only"
    typer.echo(f"vsphere-triage -> {names} ({transport.value}, {mode})", err=True)
    server = build_server(settings, guest_exec=guest_exec)
    if transport == Transport.stdio:
        server.run()
        return
    options: dict = {"host": host, "port": port, "streamable_http_path": path, "stateless_http": True}
    if allowed_host:
        options["transport_security"] = TransportSecuritySettings(
            allowed_hosts=allowed_host,
            allowed_origins=[f"https://{name}" for name in allowed_host]
            + [f"http://{name}" for name in allowed_host],
        )
    server.run("streamable-http", **options)
