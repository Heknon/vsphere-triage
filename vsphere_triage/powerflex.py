"""Dell PowerFlex (ScaleIO / VxFlex) backend health, read-only.

A VMFS datastore on PowerFlex can read as "slow" in vSphere while the real cause
is in the backend: a drive or node (SDS) failed and the pool is rebuilding or
rebalancing, saturating the storage network. vSphere cannot see that; PowerFlex
can. This is the optional client for it — the storage counterpart of the vROps
history client — reached only when VSPHERE_POWERFLEX_URL and credentials are set.

Only GET requests are sent, apart from the login/logout that acquire and release
the Gateway API token. Field names vary across PowerFlex versions, so the
summaries read defensively (getattr-style dict access) and say what they could
not find rather than assuming a schema.

The pure parts — classifying a LUN as PowerFlex, decoding a volume id from an
ESXi device id, and summarizing SDS/device/rebuild health — are tested here; the
HTTP is in the client.
"""

from __future__ import annotations

import contextlib
import re
from typing import TYPE_CHECKING, Any

import httpx

from vsphere_triage.readonly import ensure_read_request

if TYPE_CHECKING:
    from vsphere_triage.config import Settings

API = "/api"


class PowerFlexError(RuntimeError):
    """A PowerFlex request failed, worded for the reader."""


def is_powerflex_lun(vendor: str | None, model: str | None) -> bool:
    """Whether a SCSI LUN's vendor/model marks it as a PowerFlex volume."""
    text = f"{vendor or ''} {model or ''}".upper()
    return ("EMC" in text or "DELL" in text) and (
        "SCALEIO" in text or "VXFLEX" in text or "POWERFLEX" in text
    )


def volume_id_from_naa(naa: str | None) -> str | None:
    """A best-effort PowerFlex volume id from an ESXi device id (naa.* / eui.*).

    PowerFlex volume ids are 16 hex digits, and the device id ends with the
    volume id. This returns the trailing 16 hex digits as the candidate — a hint
    to match against the Gateway's volume list, not a guarantee; matching by
    volume name is more reliable where the name is known.
    """
    if not naa:
        return None
    hexrun = re.findall(r"[0-9a-fA-F]{16,}", naa)
    return hexrun[-1][-16:].lower() if hexrun else None


# The read/write bandwidth counters a PowerFlex statistics object may carry, in
# order of preference — the first present one is used (summing would double-count
# user vs primary/secondary). Each is a "Bwc": {numOccured, numSeconds,
# totalWeightInKb}, from which IOPS and KB/s over the sample window are derived.
_READ_BWC = ("userDataReadBwc", "totalReadBwc", "primaryReadBwc")
_WRITE_BWC = ("userDataWriteBwc", "totalWriteBwc", "primaryWriteBwc")


def bwc_rate(bwc: Any) -> dict[str, float]:
    """IOPS and KB/s from a PowerFlex bandwidth counter, or zeros when it is empty."""
    if not isinstance(bwc, dict):
        return {"iops": 0.0, "kb_per_s": 0.0}
    seconds = bwc.get("numSeconds") or 0
    if seconds <= 0:
        return {"iops": 0.0, "kb_per_s": 0.0}
    return {
        "iops": round((bwc.get("numOccured") or 0) / seconds, 2),
        "kb_per_s": round((bwc.get("totalWeightInKb") or 0) / seconds, 2),
    }


def _first_present(stats: dict[str, Any], keys: tuple[str, ...]) -> Any:
    """The first of `keys` present in `stats` as a counter dict, or {}."""
    for key in keys:
        if isinstance(stats.get(key), dict):
            return stats[key]
    return {}


def traffic_of(stats: dict[str, Any]) -> dict[str, float]:
    """Read/write IOPS and throughput from a statistics object (PD, pool, volume, …)."""
    read = bwc_rate(_first_present(stats, _READ_BWC))
    write = bwc_rate(_first_present(stats, _WRITE_BWC))
    return {
        "read_iops": read["iops"],
        "write_iops": write["iops"],
        "read_kb_per_s": read["kb_per_s"],
        "write_kb_per_s": write["kb_per_s"],
        "total_iops": round(read["iops"] + write["iops"], 2),
        "total_kb_per_s": round(read["kb_per_s"] + write["kb_per_s"], 2),
    }


def rank_protection_domains(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Protection domains sorted by traffic, flagging one that carries a hot share.

    `rows`: {name, id, state, traffic} where traffic is from `traffic_of`. A PD
    carrying more than half of the backend's IOPS is called out — the hotspot
    whose datastores and volumes feel load first, the pattern behind "this PD
    gets more traffic than the others".
    """
    ranked = sorted(rows, key=lambda row: row["traffic"]["total_iops"], reverse=True)
    total = round(sum(row["traffic"]["total_iops"] for row in ranked), 2)
    findings = []
    if ranked and total > 0 and len(ranked) > 1:
        top = ranked[0]
        share = top["traffic"]["total_iops"] / total
        if share > 0.5:  # noqa: PLR2004 - more than half of all backend IOPS on one PD is "hot"
            findings.append(
                f"{top['name']} carries {share:.0%} of backend IOPS ({top['traffic']['total_iops']} IOPS) — "
                "a hot protection domain; the datastores and volumes on it feel load first. Map a slow "
                "datastore to its volume (powerflex_find_volume) and check it is on this PD"
            )
    return {
        "ranked": ranked,
        "total_iops": total,
        "findings": findings or ["traffic is spread across protection domains; none dominates"],
    }


def summarize_health(
    sds: list[dict[str, Any]], devices: list[dict[str, Any]], system_stats: dict[str, Any]
) -> dict[str, Any]:
    """SDS/device state and rebuild/rebalance activity, reduced to a verdict and findings.

    Defensive about field names: an SDS is "down" when any state-ish field is
    present and not a healthy value; rebuild/rebalance is "active" when any
    pending-capacity field is above zero.
    """
    healthy_sds = {"normal", "connected", "joined"}
    sds_down = [
        node
        for node in sds
        if not all(
            str(node.get(key, "normal")).lower() in healthy_sds
            for key in ("sdsState", "mdmConnectionState", "membershipState")
        )
    ]
    devices_bad = [
        device
        for device in devices
        if str(device.get("deviceState", "Normal")).lower() not in ("normal", "")
        or str(device.get("errorState", "None")).lower() not in ("none", "")
    ]
    pending_keys = (
        "rebuildPendingCapacityInKb",
        "rebalancePendingCapacityInKb",
        "degradedHealthyCapacityInKb",
        "pendingMovingInBckRebuildJobs",
        "pendingMovingInRebalanceJobs",
    )
    pending = {key: system_stats.get(key) for key in pending_keys if _positive(system_stats.get(key))}
    rebuild_active = any("rebuild" in key.lower() or "degraded" in key.lower() for key in pending)
    rebalance_active = any("rebalance" in key.lower() for key in pending)
    findings = []
    if sds_down:
        findings.append(f"{len(sds_down)} SDS node(s) not healthy — the backend is degraded")
    if devices_bad:
        findings.append(f"{len(devices_bad)} device(s) in an error/abnormal state")
    if rebuild_active:
        findings.append(
            "a rebuild is in progress (degraded/rebuild capacity pending) — the usual cause of backend "
            "latency after a drive or node failure; datastores on this pool stay slow until it finishes"
        )
    if rebalance_active:
        findings.append("a rebalance is in progress — can add backend load while it runs")
    healthy = not (sds_down or devices_bad or rebuild_active)
    return {
        "healthy": healthy,
        "sds_total": len(sds),
        "sds_down": [node.get("name") or node.get("id") for node in sds_down],
        "devices_bad_total": len(devices_bad),
        "rebuild_active": rebuild_active,
        "rebalance_active": rebalance_active,
        "pending_capacity": pending,
        "findings": findings or ["PowerFlex backend healthy: SDS up, no device errors, no rebuild/rebalance"],
    }


def _positive(value: Any) -> bool:
    """Whether a stat value is a number greater than zero (jobs can be a dict of counts)."""
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return value > 0
    if isinstance(value, dict):
        return any(_positive(inner) for inner in value.values())
    return False


class PowerFlex:
    """A token-authenticated, GET-only client for the PowerFlex Gateway REST API."""

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        """Hold the settings; log in on the first request."""
        self.settings = settings
        self._token: str | None = None
        self._client = httpx.AsyncClient(
            base_url=settings.powerflex_url or "",
            timeout=settings.timeout_seconds,
            transport=transport,
            verify=settings.tls_verify,
        )

    async def _login(self) -> str:
        if self._token is None:
            ensure_read_request("GET")
            auth = httpx.BasicAuth(
                self.settings.powerflex_username or "", self.settings.powerflex_password or ""
            )
            response = await self._client.get(f"{API}/login", auth=auth)
            if response.status_code != httpx.codes.OK:
                msg = f"PowerFlex login failed: HTTP {response.status_code}"
                raise PowerFlexError(msg)
            self._token = response.text.strip().strip('"')
        return self._token

    async def _get(self, path: str) -> Any:
        token = await self._login()
        ensure_read_request("GET")
        auth = httpx.BasicAuth(self.settings.powerflex_username or "", token)
        response = await self._client.get(f"{API}{path}", auth=auth)
        if response.status_code != httpx.codes.OK:
            msg = f"PowerFlex GET {path} failed: HTTP {response.status_code}"
            raise PowerFlexError(msg)
        return response.json()

    async def systems(self) -> list[dict[str, Any]]:
        """Every PowerFlex system (MDM cluster) the Gateway fronts."""
        return await self._get("/types/System/instances")

    async def sds(self) -> list[dict[str, Any]]:
        """Every SDS (storage server) and its state."""
        return await self._get("/types/Sds/instances")

    async def devices(self) -> list[dict[str, Any]]:
        """Every backing device and its error state."""
        return await self._get("/types/Device/instances")

    async def system_statistics(self, system_id: str) -> dict[str, Any]:
        """One system's statistics, where the rebuild/rebalance pending capacity lives."""
        return await self._get(f"/instances/System::{system_id}/relationships/Statistics")

    async def protection_domains(self) -> list[dict[str, Any]]:
        """Every protection domain (the traffic/fault boundary) and its state."""
        return await self._get("/types/ProtectionDomain/instances")

    async def protection_domain_statistics(self, domain_id: str) -> dict[str, Any]:
        """One protection domain's statistics, including its read/write bandwidth counters."""
        return await self._get(f"/instances/ProtectionDomain::{domain_id}/relationships/Statistics")

    async def volumes(self) -> list[dict[str, Any]]:
        """Every volume (id, name, size), for mapping a datastore to its backend volume."""
        return await self._get("/types/Volume/instances")

    async def aclose(self) -> None:
        """Release the token and close the client."""
        if self._token is not None:
            with contextlib.suppress(Exception):
                auth = httpx.BasicAuth(self.settings.powerflex_username or "", self._token)
                await self._client.get(f"{API}/logout", auth=auth)
            self._token = None
        await self._client.aclose()
