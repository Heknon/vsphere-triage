"""vROps (Aria Operations / VCF Operations), read-only: history for the long-lived things.

A VM that lived thirty minutes barely registers in vROps. Hosts, clusters and
datastores do, for weeks, and that is what this is for: was this window's CPU
demand or latency unusual for that host at that hour, or is it every night?

Only GET requests are sent, apart from acquiring and releasing the API token,
which is how vROps logs in. Stat keys differ between versions, so none is
assumed: `list_stat_keys` reads what a resource actually has, and the defaults
offered are starting points to check against it.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime, timedelta
from statistics import fmean
from typing import TYPE_CHECKING, Any

import httpx

from vsphere_triage.readonly import ensure_read_request

if TYPE_CHECKING:
    from vsphere_triage.config import Settings

API = "/suite-api/api"
SUGGESTED_STAT_KEYS = {
    "HostSystem": ("cpu|demandPct", "cpu|usage_average", "cpu|capacity_contentionPct", "mem|usage_average"),
    "ClusterComputeResource": ("cpu|demandPct", "cpu|capacity_contentionPct", "mem|usage_average"),
    "Datastore": (
        "datastore|totalLatency_average",
        "datastore|commandsAveraged_average",
        "datastore|demand_oio",
    ),
    "VirtualMachine": ("cpu|readyPct", "cpu|demandPct", "virtualDisk|totalLatency"),
}
KINDS = tuple(SUGGESTED_STAT_KEYS)


class VropsError(RuntimeError):
    """A vROps request failed, worded for the reader."""


def millis(moment: datetime) -> int:
    """A datetime as vROps' epoch milliseconds."""
    return int(moment.timestamp() * 1000)


def from_millis(value: int) -> datetime:
    """VROps' epoch milliseconds as a UTC datetime."""
    return datetime.fromtimestamp(value / 1000, tz=UTC)


class Vrops:
    """A token-authenticated, GET-only client for the vROps Suite API."""

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        """Hold the settings; log in on the first request."""
        if not settings.vrops_url:
            msg = "vROps is not configured (VSPHERE_VROPS_URL)"
            raise VropsError(msg)
        self.settings = settings
        verify: Any = settings.tls_verify and (settings.ca_bundle or True)
        self._client = httpx.AsyncClient(
            base_url=settings.vrops_url,
            verify=verify,
            timeout=settings.timeout_seconds,
            transport=transport,
            headers={"Accept": "application/json"},
        )
        self._token: str | None = None
        self._lock = asyncio.Lock()

    async def _login(self) -> str:
        async with self._lock:
            if self._token:
                return self._token
            body: dict[str, str] = {
                "username": self.settings.vrops_username or "",
                "password": self.settings.vrops_password or "",
            }
            if self.settings.vrops_auth_source:
                body["authSource"] = self.settings.vrops_auth_source
            response = await self._client.post(f"{API}/auth/token/acquire", json=body)
            if response.status_code != 200:  # noqa: PLR2004
                msg = f"vROps login refused (HTTP {response.status_code})"
                raise VropsError(msg)
            self._token = response.json()["token"]
            return self._token

    async def get(self, path: str, params: Any = None) -> Any:
        """GET a Suite API path, logging in again once if the token expired."""
        ensure_read_request("GET")
        for attempt in range(2):
            token = await self._login()
            response = await self._client.get(
                f"{API}{path}", params=params, headers={"Authorization": f"vRealizeOpsToken {token}"}
            )
            if response.status_code == 401 and attempt == 0:  # noqa: PLR2004
                self._token = None
                continue
            if response.status_code != 200:  # noqa: PLR2004
                msg = f"vROps GET {path} failed (HTTP {response.status_code})"
                raise VropsError(msg)
            return response.json()
        msg = "vROps refused the token twice"
        raise VropsError(msg)

    async def find(self, name: str, kind: str | None) -> list[dict[str, Any]]:
        """Resources by name (and kind), with the id every other call takes."""
        params: dict[str, Any] = {"name": name, "pageSize": 20}
        if kind:
            params["resourceKind"] = kind
        data = await self.get("/resources", params)
        return [
            {
                "id": item.get("identifier"),
                "name": (item.get("resourceKey") or {}).get("name"),
                "kind": (item.get("resourceKey") or {}).get("resourceKindKey"),
                "adapter": (item.get("resourceKey") or {}).get("adapterKindKey"),
                "health": item.get("resourceHealth"),
            }
            for item in data.get("resourceList", [])
        ]

    async def stat_keys(self, resource_id: str, contains: str | None) -> list[str]:
        """The stat keys a resource actually has, filtered by a substring."""
        data = await self.get(f"/resources/{resource_id}/statkeys")
        keys = [item.get("key") for item in data.get("stat-key", []) if item.get("key")]
        if contains:
            keys = [key for key in keys if contains.lower() in key.lower()]
        return sorted(keys)

    async def stats(
        self,
        resource_id: str,
        stat_keys: list[str],
        begin: datetime,
        end: datetime,
        *,
        interval_minutes: int,
    ) -> dict[str, list[tuple[datetime, float]]]:
        """Each stat key's samples in the window, averaged per interval."""
        params = [
            *(("statKey", key) for key in stat_keys),
            ("begin", millis(begin)),
            ("end", millis(end)),
            ("rollUpType", "AVG"),
            ("intervalType", "MINUTES"),
            ("intervalQuantifier", interval_minutes),
        ]
        data = await self.get(f"/resources/{resource_id}/stats", params)
        series: dict[str, list[tuple[datetime, float]]] = {}
        for value in data.get("values", []):
            for stat in (value.get("stat-list") or {}).get("stat", []):
                key = (stat.get("statKey") or {}).get("key")
                if key:
                    series[key] = [
                        (from_millis(stamp), float(sample))
                        for stamp, sample in zip(
                            stat.get("timestamps", []), stat.get("data", []), strict=False
                        )
                    ]
        return series

    async def alerts(self, resource_id: str, since: datetime) -> list[dict[str, Any]]:
        """Alerts on a resource that started or updated since a time."""
        data = await self.get("/alerts", {"resourceId": resource_id})
        cutoff = millis(since)
        return [
            {
                "name": alert.get("alertDefinitionName"),
                "level": alert.get("alertLevel"),
                "status": alert.get("status"),
                "impact": alert.get("alertImpact"),
                "started": from_millis(alert["startTimeUTC"]) if alert.get("startTimeUTC") else None,
                "updated": from_millis(alert["updateTimeUTC"]) if alert.get("updateTimeUTC") else None,
            }
            for alert in data.get("alerts", [])
            if max(alert.get("startTimeUTC") or 0, alert.get("updateTimeUTC") or 0) >= cutoff
        ]

    async def compare(
        self,
        resource_id: str,
        stat_keys: list[str],
        begin: datetime,
        end: datetime,
        *,
        baseline_days: int,
        interval_minutes: int,
    ) -> dict[str, Any]:
        """The window against the same clock window on each of the previous days."""
        current = await self.stats(resource_id, stat_keys, begin, end, interval_minutes=interval_minutes)
        baselines = await asyncio.gather(
            *(
                self.stats(
                    resource_id,
                    stat_keys,
                    begin - timedelta(days=day),
                    end - timedelta(days=day),
                    interval_minutes=interval_minutes,
                )
                for day in range(1, baseline_days + 1)
            )
        )
        result: dict[str, Any] = {}
        for key in stat_keys:
            now_values = [value for _, value in current.get(key, [])]
            past = [
                {"days_ago": day, "max": max(values), "mean": round(fmean(values), 2)}
                for day, baseline in enumerate(baselines, start=1)
                if (values := [value for _, value in baseline.get(key, [])])
            ]
            if not now_values:
                result[key] = {"available": False, "reason": "no samples in the window"}
                continue
            peak = max(now_values)
            past_peaks = [entry["max"] for entry in past]
            result[key] = {
                "window_max": round(peak, 2),
                "window_mean": round(fmean(now_values), 2),
                "baseline_days": past,
                "baseline_max_of_maxes": max(past_peaks) if past_peaks else None,
                "days_as_high_or_higher": sum(1 for value in past_peaks if value >= peak),
                "unusual": bool(past_peaks) and peak > max(past_peaks),
            }
        return result

    async def aclose(self) -> None:
        """Release the token and close the client."""
        if self._token:
            with contextlib.suppress(httpx.HTTPError):
                await self._client.post(
                    f"{API}/auth/token/release",
                    headers={"Authorization": f"vRealizeOpsToken {self._token}"},
                )
        await self._client.aclose()
