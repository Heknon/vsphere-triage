"""The vCenter appliance's own health, through its REST API (`/api/appliance`, vCenter 7.0 U2+).

Errors that hit every client of a vCenter are not always its session count: a
vpxd that restarted, an appliance short of memory or disk, or a service that is
up but unhealthy all drop or refuse connections too, and none of it is in the
SOAP API. The appliance's REST API reports it: the overall, load, memory, swap,
storage and database health, the appliance's uptime, and each vCenter service's
state and health.

Read-only like everything else: every data request is a GET through
`ensure_read_request`. The one exception is the REST session itself — a POST to
`/api/session` to log in and a DELETE of it to log out, the REST counterpart of
the SOAP `Login`/`Logout` on `readonly.ALLOWED_METHODS` — and it is opened and
closed within each call, so this client never holds a session on a vCenter that
may be short of them. `readonly.ensure_session_request` allows exactly those two
and nothing else.

It uses the vCenter's own credentials. The account may not be allowed every
endpoint; each one that is refused is named in `not_read`, and the rest stand.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

import httpx

from vsphere_triage.readonly import ensure_read_request, ensure_session_request
from vsphere_triage.vcenter import ssl_context

if TYPE_CHECKING:
    from vsphere_triage.config import Settings, VCenter

SESSION_PATH = "/api/session"
SESSION_HEADER = "vmware-api-session-id"
# The health areas the appliance reports, each a colour: green, orange, red or gray.
HEALTH_AREAS = ("system", "load", "mem", "swap", "storage", "database-storage", "applmgmt")
UPTIME_PATH = "/api/appliance/system/uptime"
# vMon's services; the first path is the current one, the second its older spelling.
SERVICES_PATHS = ("/api/vcenter/services", "/api/appliance/vmon/service")
# Services whose trouble drops or refuses API connections, named first when unhealthy.
CONNECTION_SERVICES = ("vpxd", "envoy", "rhttpproxy", "vapi-endpoint", "sts", "vmware-vpostgres")
RECENT_RESTART_SECONDS = 24 * 3600
BAD_COLOURS = ("orange", "red")


class ApplianceError(RuntimeError):
    """The appliance API could not be used at all (no session), worded for the reader."""


def _service_rows(raw: Any) -> list[dict[str, Any]]:
    """The vMon service list as rows, from either response shape: a map, or a list of {key, value}."""
    if isinstance(raw, dict):
        items = list(raw.items())
    elif isinstance(raw, list):
        items = [(item.get("key"), item.get("value")) for item in raw if isinstance(item, dict)]
    else:
        return []
    rows = []
    for name, info in items:
        if not isinstance(info, dict):
            continue
        rows.append(
            {
                "service": name,
                "state": info.get("state"),
                "health": info.get("health"),
                "startup_type": info.get("startup_type"),
                "health_messages": [
                    (message.get("default_message") if isinstance(message, dict) else str(message))
                    for message in info.get("health_messages") or []
                ][:3],
            }
        )
    return rows


def judge(health: dict[str, Any], uptime_seconds: float | None, services: list[dict[str, Any]]) -> list[str]:
    """Findings from the appliance's health colours, uptime and services. Pure."""
    findings = []
    bad = {area: colour for area, colour in health.items() if str(colour).lower() in BAD_COLOURS}
    if bad:
        findings.append(
            "appliance health not green: "
            + ", ".join(f"{area} {colour}" for area, colour in bad.items())
            + " — a short appliance (memory, swap, disk, database) slows or drops API connections for "
            "every client"
        )
    if uptime_seconds is not None and uptime_seconds < RECENT_RESTART_SECONDS:
        findings.append(
            f"the appliance came up {uptime_seconds / 3600:.1f} h ago: every session and connection was "
            "dropped then — errors at that time are the restart, not a limit"
        )
    unhealthy = [
        row
        for row in services
        if (
            str(row.get("state")).upper() == "STARTED"
            and str(row.get("health")).upper() not in ("HEALTHY", "NONE")
        )
        or (
            str(row.get("state")).upper() == "STOPPED" and str(row.get("startup_type")).upper() == "AUTOMATIC"
        )
    ]
    unhealthy.sort(key=lambda row: row["service"] not in CONNECTION_SERVICES)
    for row in unhealthy[:8]:
        why = "; ".join(message for message in row["health_messages"] if message)
        findings.append(
            f"service {row['service']} is {row['state']} / {row['health']}"
            + (f" ({why})" if why else "")
            + (
                " — it carries the API connections, so its trouble is every client's"
                if row["service"] in CONNECTION_SERVICES
                else ""
            )
        )
    return findings


class Appliance:
    """A per-call client for one vCenter's appliance REST API: log in, GET, log out."""

    def __init__(
        self, vcenter: VCenter, settings: Settings, transport: httpx.BaseTransport | None = None
    ) -> None:
        """Hold where and how to connect; nothing is opened until `health` runs."""
        self.vcenter = vcenter
        self.settings = settings
        self._transport = transport

    def health(self) -> dict[str, Any]:
        """Read every health area, the uptime and the services, inside one short-lived session."""
        username, password = self.settings.credentials_for(self.vcenter)
        with httpx.Client(
            base_url=f"https://{self.vcenter.host}:{self.vcenter.port}",
            verify=ssl_context(self.settings),
            timeout=self.settings.timeout_seconds,
            transport=self._transport,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            token = self._login(client, username, password)
            try:
                return self._read(client, token)
            finally:
                self._logout(client, token)

    def _login(self, client: httpx.Client, username: str, password: str) -> str:
        request = client.build_request("POST", SESSION_PATH)
        ensure_session_request(request.method, request.url.path)
        response = client.send(request, auth=httpx.BasicAuth(username, password))
        if response.status_code == httpx.codes.NOT_FOUND:
            msg = (
                f"vCenter {self.vcenter.name} has no {SESSION_PATH}: the appliance REST API needs vCenter "
                "7.0 U2 or later (older releases use /rest, which this client does not read)"
            )
            raise ApplianceError(msg)
        if response.status_code not in (httpx.codes.OK, httpx.codes.CREATED):
            msg = f"vCenter {self.vcenter.name}: appliance API login refused (HTTP {response.status_code})"
            raise ApplianceError(msg)
        return str(response.json()).strip('"')

    def _logout(self, client: httpx.Client, token: str) -> None:
        request = client.build_request("DELETE", SESSION_PATH, headers={SESSION_HEADER: token})
        ensure_session_request(request.method, request.url.path)
        # The session times out on its own; a failed logout loses nothing read.
        with contextlib.suppress(httpx.HTTPError):
            client.send(request)

    def _get(self, client: httpx.Client, token: str, path: str) -> tuple[Any, str | None]:
        """One GET: its JSON, or None and why not."""
        request = client.build_request("GET", path, headers={SESSION_HEADER: token})
        ensure_read_request(request.method)
        try:
            response = client.send(request)
        except httpx.HTTPError as error:
            return None, f"{type(error).__name__}: {error}"
        if response.status_code != httpx.codes.OK:
            hint = (
                " (the account may not be allowed this endpoint)"
                if response.status_code in (httpx.codes.UNAUTHORIZED, httpx.codes.FORBIDDEN)
                else ""
            )
            return None, f"HTTP {response.status_code}{hint}"
        try:
            return response.json(), None
        except ValueError:
            return None, "not JSON"

    def _read(self, client: httpx.Client, token: str) -> dict[str, Any]:
        health: dict[str, Any] = {}
        not_read: dict[str, str] = {}
        for area in HEALTH_AREAS:
            value, why = self._get(client, token, f"/api/appliance/health/{area}")
            if why is None:
                health[area] = value
            else:
                not_read[f"health/{area}"] = why
        uptime, why = self._get(client, token, UPTIME_PATH)
        uptime_seconds = float(uptime) if isinstance(uptime, (int, float)) else None
        if why is not None:
            not_read["system/uptime"] = why
        services: list[dict[str, Any]] = []
        reasons = []
        for path in SERVICES_PATHS:
            raw, why = self._get(client, token, path)
            if why is None:
                services = _service_rows(raw)
                break
            reasons.append(f"{path}: {why}")
        if not services and reasons:
            not_read["services"] = "; ".join(reasons)
        findings = judge(health, uptime_seconds, services)
        if not findings:
            findings = (
                ["appliance healthy: every health area read is green, no recent restart, services healthy"]
                if health and not not_read
                else []
            )
        if not_read:
            findings.append(
                f"{len(not_read)} appliance endpoint(s) not read ({', '.join(not_read)}): "
                "not evidence they are healthy"
            )
        return {
            "findings": findings,
            "health": health,
            "uptime_hours": None if uptime_seconds is None else round(uptime_seconds / 3600, 1),
            "services_unhealthy": [
                row
                for row in services
                if str(row.get("health")).upper() not in ("HEALTHY", "NONE")
                or (
                    str(row.get("state")).upper() == "STOPPED"
                    and str(row.get("startup_type")).upper() == "AUTOMATIC"
                )
            ][:20],
            "services_read": len(services),
            "not_read": not_read,
        }
