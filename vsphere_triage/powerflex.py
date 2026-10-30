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

import asyncio
import contextlib
import re
from typing import TYPE_CHECKING, Any

import httpx

from vsphere_triage.readonly import ensure_read_request
from vsphere_triage.vcenter import ssl_context

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


# A PD is "hot" when it carries more than half of all backend IOPS *and* at least
# 1.5 times its even share: with two PDs a 51/49 split is noise, not a hotspot.
HOT_SHARE = 0.5
HOT_OVER_EVEN = 1.5


def hot_share(share: float, domains: int) -> bool:
    """Whether a PD's share of backend IOPS makes it the hot one among `domains`."""
    return domains > 1 and share > HOT_SHARE and share >= HOT_OVER_EVEN / domains


def rank_protection_domains(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Protection domains sorted by traffic, flagging one that carries a hot share.

    `rows`: {name, id, state, traffic} where traffic is from `traffic_of`. A PD
    carrying more than half of the backend's IOPS, and well over its even share,
    is called out — the hotspot whose datastores and volumes feel load first, the
    pattern behind "this PD gets more traffic than the others".
    """
    ranked = sorted(rows, key=lambda row: row["traffic"]["total_iops"], reverse=True)
    total = round(sum(row["traffic"]["total_iops"] for row in ranked), 2)
    findings = []
    if ranked and total > 0 and len(ranked) > 1:
        top = ranked[0]
        share = top["traffic"]["total_iops"] / total
        if hot_share(share, len(ranked)):
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


# Statistics that mean a rebuild, lost redundancy, a rebalance, or data with no
# copy left. Names as Dell's own SDKs and 3.6 samples report them (goscaleio,
# ansible-powerflex), plus older spellings kept for earlier releases; a key a
# release does not report simply never matches.
_REBUILD_KEYS = (
    # Data down to one copy: degraded whether or not a rebuild is running (no
    # spare capacity, or a rebuild that has not started or has stalled).
    "semiProtectedCapacityInKb",
    "semiProtectedVacInKb",
    "degradedHealthyCapacityInKb",
    "degradedHealthyVacInKb",
    "degradedFailedCapacityInKb",
    "degradedFailedVacInKb",
    # A rebuild in progress or queued.
    "fwdRebuildCapacityInKb",
    "bckRebuildCapacityInKb",
    "normRebuildCapacityInKb",
    "pendingFwdRebuildCapacityInKb",
    "pendingBckRebuildCapacityInKb",
    "activeFwdRebuildCapacityInKb",
    "activeBckRebuildCapacityInKb",
    "activeMovingInFwdRebuildJobs",
    "activeMovingInBckRebuildJobs",
    "pendingMovingInFwdRebuildJobs",
    "pendingMovingInBckRebuildJobs",
    "pendingNormRebuildCapacityInKb",
    "activeNormRebuildCapacityInKb",
    "activeMovingInNormRebuildJobs",
    "pendingMovingInNormRebuildJobs",
    "rebuildPendingCapacityInKb",
)
# The subset that means redundancy is lost, which holds with or without a rebuild.
_DEGRADED_KEYS = _REBUILD_KEYS[:6]
_REBALANCE_KEYS = (
    "rebalanceCapacityInKb",
    "pendingRebalanceCapacityInKb",
    "activeRebalanceCapacityInKb",
    "activeMovingInRebalanceJobs",
    "pendingMovingInRebalanceJobs",
    "rebalancePendingCapacityInKb",
)
# Data with no copy left, or not reachable: unavailable, the worst state a pool can be in.
_FAILED_KEYS = ("failedCapacityInKb", "failedVacInKb", "inaccessibleCapacityInKb")
_PD_DEGRADED_KEYS = (*_REBUILD_KEYS, *_REBALANCE_KEYS, *_FAILED_KEYS)


def map_backend_impact(
    pds: list[dict[str, Any]],
    pd_stats: dict[str, dict[str, Any]],
    pools: list[dict[str, Any]],
    volumes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Which PowerFlex volumes sit on a *troubled* protection domain, and why.

    A PD is troubled if it is rebuilding/rebalancing or has degraded capacity, or
    if it is the hot PD (more than half the backend IOPS). Returns {volume_id ->
    PD name} for every volume on a troubled PD, so the caller can map those
    volumes back to vSphere datastores. Pure.
    """
    pd_name = {pd["id"]: (pd.get("name") or pd["id"]) for pd in pds if pd.get("id")}
    rows = [
        {"id": pd["id"], "name": pd_name[pd["id"]], "traffic": traffic_of(pd_stats.get(pd["id"]) or {})}
        for pd in pds
        if pd.get("id")
    ]
    ranked = rank_protection_domains(rows)
    total = ranked["total_iops"]
    top = ranked["ranked"][0] if ranked["ranked"] else None
    hot_id = (
        top["id"]
        if top and total > 0 and hot_share(top["traffic"]["total_iops"] / total, len(ranked["ranked"]))
        else None
    )
    troubled: dict[str, list[str]] = {}
    for pd in pds:
        pd_id = pd.get("id")
        if not pd_id:
            continue
        reasons = []
        if any(_positive((pd_stats.get(pd_id) or {}).get(key)) for key in _PD_DEGRADED_KEYS):
            reasons.append("rebuild/rebalance or degraded capacity")
        if pd_id == hot_id:
            reasons.append("hot: more than half of backend IOPS, well over its even share")
        if reasons:
            troubled[pd_id] = reasons
    pool_pd = {pool.get("id"): pool.get("protectionDomainId") for pool in pools}
    volume_to_pd: dict[str, str] = {}
    for volume in volumes:
        pd_id = pool_pd.get(volume.get("storagePoolId"))
        if pd_id in troubled:
            identifier = str(volume.get("id", "")).lower()
            if identifier:
                volume_to_pd[identifier] = pd_name.get(pd_id, pd_id)
    return {
        "troubled_protection_domains": {pd_name.get(k, k): v for k, v in troubled.items()},
        "volume_to_pd": volume_to_pd,
    }


def datastore_key(vcenter: str, moref: str) -> str:
    """A datastore across the fleet: `datastore-12` on two vCenters is two datastores."""
    return f"{vcenter}:{moref}"


def affected_vms(
    volume_to_pd: dict[str, str],
    datastores: list[dict[str, Any]],
    vms_by_datastore: dict[str, list[dict[str, Any]]],
    *,
    limit: int = 50,
) -> dict[str, Any]:
    """Join troubled-volume ids to datastores to the VMs on them, split by suffering.

    `datastores`: {vcenter, moref, name, powerflex_volume_ids}. `vms_by_datastore`:
    `datastore_key(vcenter, moref)` -> [{name, moref, vcenter, state, suffering}],
    keyed by vCenter too because morefs repeat across vCenters. Pure.
    """
    affected = []
    total_suffering = 0
    for datastore in datastores:
        hit = next((vid for vid in datastore.get("powerflex_volume_ids", []) if vid in volume_to_pd), None)
        if hit is None:
            continue
        vms = vms_by_datastore.get(datastore_key(datastore["vcenter"], datastore["moref"]), [])
        suffering = [vm for vm in vms if vm.get("suffering")]
        total_suffering += len(suffering)
        affected.append(
            {
                "vcenter": datastore["vcenter"],
                "datastore": datastore["name"],
                "moref": datastore["moref"],
                "powerflex_volume_id": hit,
                "protection_domain": volume_to_pd[hit],
                "vms_total": len(vms),
                "suffering_total": len(suffering),
                "suffering_vms": suffering[:limit],
            }
        )
    affected.sort(key=lambda item: item["suffering_total"], reverse=True)
    if affected and total_suffering:
        findings = [
            (
                f"{total_suffering} VM(s) suffering on {len(affected)} datastore(s) backed by a troubled "
                "protection domain — the backend trouble is reaching the VMs"
            )
        ]
    elif affected:
        findings = [
            (
                f"{len(affected)} datastore(s) are backed by a troubled protection domain, but none of their "
                "VMs is abnormal right now"
            )
        ]
    else:
        findings = ["no datastore in these vCenters maps to a troubled protection domain"]
    return {"affected_datastores": affected, "suffering_total": total_suffering, "findings": findings}


def summarize_health(
    sds: list[dict[str, Any]], devices: list[dict[str, Any]], system_stats: dict[str, Any]
) -> dict[str, Any]:
    """SDS/device state and rebuild/rebalance activity, reduced to a verdict and findings.

    Defensive about field names: an SDS is "down" when any state-ish field is
    present and not a healthy value; rebuild/rebalance is "active" when any
    pending-capacity field is above zero.
    """
    healthy_sds = {"normal", "connected", "joined"}
    # A field that is absent or null is not reported, not unhealthy.
    sds_down = [
        node
        for node in sds
        if any(
            node.get(key) is not None and str(node[key]).lower() not in healthy_sds
            for key in ("sdsState", "mdmConnectionState", "membershipState")
        )
    ]
    devices_bad = [
        device
        for device in devices
        if str(device.get("deviceState", "Normal")).lower() not in ("normal", "")
        or str(device.get("errorState", "None")).lower() not in ("none", "")
    ]
    pending = {key: system_stats.get(key) for key in _PD_DEGRADED_KEYS if _positive(system_stats.get(key))}
    degraded = any(key in _DEGRADED_KEYS for key in pending)
    rebuild_active = any(key in _REBUILD_KEYS and key not in _DEGRADED_KEYS for key in pending)
    rebalance_active = any(key in _REBALANCE_KEYS for key in pending)
    data_unavailable = any(key in _FAILED_KEYS for key in pending)
    findings = []
    if data_unavailable:
        findings.append(
            "capacity is failed or inaccessible ("
            + ", ".join(key for key in _FAILED_KEYS if key in pending)
            + ") — data with no reachable copy is unavailable, so VMs on those volumes can block on I/O"
        )
    if sds_down:
        findings.append(f"{len(sds_down)} SDS node(s) not healthy — the backend is degraded")
    if devices_bad:
        findings.append(f"{len(devices_bad)} device(s) in an error/abnormal state")
    if degraded:
        findings.append(
            "data is down to one copy (semi-protected/degraded capacity)"
            + (
                " and a rebuild is reported"
                if rebuild_active
                else " and no rebuild is running — no spare capacity, or a rebuild that has not started or "
                "has stalled"
            )
            + "; one more failure loses data"
        )
    if rebuild_active:
        findings.append(
            "a rebuild is in progress (degraded/rebuild capacity pending) — the usual cause of backend "
            "latency after a drive or node failure; datastores on this pool stay slow until it finishes"
        )
    if rebalance_active:
        findings.append("a rebalance is in progress — can add backend load while it runs")
    # Nothing read is not healthy: no SDS, no devices and no statistics (a schema
    # or permission mismatch) leave the verdict unknown, never "healthy".
    unread = [
        label
        for label, value in (("SDS list", sds), ("devices", devices), ("system statistics", system_stats))
        if not value
    ]
    trouble = bool(sds_down or devices_bad or degraded or rebuild_active or data_unavailable)
    healthy: bool | None = False if trouble else (None if unread else True)
    if not trouble and unread:
        findings.append(
            "could not judge the backend: "
            + ", ".join(unread)
            + " came back empty — not evidence it is healthy"
        )
    return {
        "healthy": healthy,
        "not_read": unread,
        "data_unavailable": data_unavailable,
        "sds_total": len(sds),
        "sds_down": [node.get("name") or node.get("id") for node in sds_down],
        "devices_bad_total": len(devices_bad),
        "degraded": degraded,
        "rebuild_active": rebuild_active,
        "rebalance_active": rebalance_active,
        "pending_capacity": pending,
        "findings": findings or ["PowerFlex backend healthy: SDS up, no device errors, no rebuild/rebalance"],
    }


def merge_statistics(per_system: list[dict[str, Any]]) -> dict[str, Any]:
    """Several systems' statistics as one, keeping the worst (largest) value of each key.

    A plain dict update would let the last system's numbers win, so a rebuilding
    system beside a healthy one would read as healthy.
    """
    merged: dict[str, Any] = {}
    for stats in per_system:
        for key, value in stats.items():
            if key not in merged:
                merged[key] = value
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                current = merged[key]
                if isinstance(current, (int, float)) and not isinstance(current, bool):
                    merged[key] = max(current, value)
            elif isinstance(value, dict) and isinstance(merged[key], dict):
                merged[key] = merge_statistics([merged[key], value])
    return merged


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
        self._login_lock = asyncio.Lock()
        self._client = httpx.AsyncClient(
            base_url=settings.powerflex_url or "",
            timeout=settings.timeout_seconds,
            transport=transport,
            # The same trust as vCenter: VSPHERE_CA_BUNDLE for an internal CA, so a
            # privately signed Gateway does not force verification off everywhere.
            verify=ssl_context(settings),
        )

    async def _login(self, stale: str | None = None) -> str:
        """The Gateway token, logging in when there is none or `stale` was refused.

        Under a lock, so concurrent first calls log in once, and a refused token
        is replaced once rather than by every caller that saw it refused.
        """
        async with self._login_lock:
            if self._token is None or self._token == stale:
                auth = httpx.BasicAuth(
                    self.settings.powerflex_username or "", self.settings.powerflex_password or ""
                )
                response = await self._send("/login", auth)
                if response.status_code != httpx.codes.OK:
                    hint = (
                        " (PowerFlex 4.x uses /rest/auth/login, not supported by this GET-only client)"
                        if response.status_code in (httpx.codes.NOT_FOUND, httpx.codes.METHOD_NOT_ALLOWED)
                        else ""
                    )
                    msg = f"PowerFlex login failed: HTTP {response.status_code}{hint}"
                    raise PowerFlexError(msg)
                self._token = response.text.strip().strip('"')
            return self._token

    async def _send(self, path: str, auth: httpx.Auth) -> httpx.Response:
        """Every request this client makes: a GET, checked by the read-only guard."""
        request = self._client.build_request("GET", f"{API}{path}")
        ensure_read_request(request.method)
        return await self._client.send(request, auth=auth)

    async def _get(self, path: str) -> Any:
        for attempt in range(2):
            token = await self._login()
            response = await self._send(path, httpx.BasicAuth(self.settings.powerflex_username or "", token))
            if response.status_code == httpx.codes.UNAUTHORIZED and attempt == 0:
                # The token expired (idle or past its lifetime): log in again, once.
                await self._login(stale=token)
                continue
            if response.status_code != httpx.codes.OK:
                msg = f"PowerFlex GET {path} failed: HTTP {response.status_code}"
                raise PowerFlexError(msg)
            return response.json()
        msg = "PowerFlex refused a fresh token too"
        raise PowerFlexError(msg)

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

    async def storage_pools(self) -> list[dict[str, Any]]:
        """Every storage pool and the protection domain it belongs to (pool -> PD)."""
        return await self._get("/types/StoragePool/instances")

    async def volumes(self) -> list[dict[str, Any]]:
        """Every volume (id, name, size), for mapping a datastore to its backend volume."""
        return await self._get("/types/Volume/instances")

    async def aclose(self) -> None:
        """Release the token and close the client."""
        if self._token is not None:
            with contextlib.suppress(Exception):
                await self._send(
                    "/logout", httpx.BasicAuth(self.settings.powerflex_username or "", self._token)
                )
            self._token = None
        await self._client.aclose()
