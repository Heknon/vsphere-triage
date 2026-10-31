"""Host and vCenter logs read through the DiagnosticManager: one host, every host, or vCenter itself.

Some failures leave no task or event, only a log line. A guest file transfer is
the main one: vCenter hands out a URL that names the ESXi host, the client
downloads from the host directly, and a dropped or refused transfer shows only
in that host's `hostd` log. Reading one host at a time cannot say whether the
failures cluster on a few hosts (their certificates, their hostd load) or spread
over all of them (the network, the client). The sweep reads the end of the same
log on every connected host and counts the matching lines per host.

vCenter's own logs (vpxd) come from the same DiagnosticManager, asked without a
host. Its keys carry the file name (`vpxd:vpxd-214.log`), so a bare `vpxd` is
resolved to the key vCenter offers.

Reads only: `QueryDescriptions` and `BrowseDiagnosticLog`, both on the list.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from pyVmomi import vim, vmodl

from vsphere_triage.inventory import read_hosts
from vsphere_triage.vmlog import caller_pattern, grep, parse_lines

if TYPE_CHECKING:
    from collections.abc import Sequence

    from vsphere_triage.vcenter import VCenterPool, VCenterSession

# What a guest file transfer, a TLS failure or a dropped connection writes in hostd.
GUEST_TRANSFER_PATTERN = (
    r"guestFile|FileTransfer|InitiateFileTransfer|GuestOps|SSL|TLS|handshake|"
    r"connection (reset|refused|closed|timed out)|broken pipe|EOF|too many|"
    r"Max(imum)? .*(connections|sessions)"
)
# Hosts read per vCenter in one sweep: two DiagnosticManager calls each.
MAX_HOSTS = 200
# A sweep's findings call matches concentrated when this few hosts hold this share.
CONCENTRATED_HOSTS = 3
CONCENTRATED_SHARE = 0.8


def resolve_log_key(offered: Sequence[str], wanted: str) -> str | None:
    """The DiagnosticManager key for a log asked for by its key or by its name before the colon.

    vCenter offers `vpxd:vpxd-214.log`; a caller says `vpxd`. Pure.
    """
    text = wanted.strip()
    if text in offered:
        return text
    lowered = text.lower()
    for key in offered:
        if key.lower() == lowered or key.lower().split(":", 1)[0] == lowered:
            return key
    return None


def read_vcenter_log(session: VCenterSession, log: str, lines: int) -> dict[str, Any]:
    """The last `lines` of one of vCenter's own logs (vpxd by default), or why not."""
    manager = session.content.diagnosticManager
    try:
        offered = [item.key for item in manager.QueryDescriptions() or []]
    except vim.fault.NotAuthenticated:
        raise
    except (vmodl.MethodFault, vmodl.RuntimeFault) as fault:
        return {
            "available": False,
            "reason": f"{type(fault).__name__}: {getattr(fault, 'msg', '') or fault}",
            "keys_offered": [],
        }
    key = resolve_log_key(offered, log)
    if key is None:
        return {
            "available": False,
            "reason": f"vCenter offers no log {log!r}",
            "keys_offered": offered,
        }
    read = session.host_log(None, key, lines)
    return {"key": key} | read


def _host_matches(
    session: VCenterSession, host: Any, *, log: str, pattern: str, lines: int, keep: int
) -> dict[str, Any]:
    """One host's log, cut to the lines matching `pattern`. Blocking."""
    read = session.host_log(session.reference("HostSystem", host.moref), log, lines)
    row: dict[str, Any] = {
        "vcenter": session.vcenter.name,
        "host": host.name,
        "moref": host.moref,
        "cluster": host.cluster,
    }
    if not read.get("available"):
        return row | {"read": False, "reason": read.get("reason"), "keys_offered": read.get("keys_offered")}
    parsed = parse_lines("\n".join(read["lines"]), first_number=read["line_start"])
    kept, total = grep(parsed, pattern, limit=keep)
    return row | {
        "read": True,
        "lines_read": len(parsed),
        "matched": total,
        "newest_matches": [line.as_dict() for line in kept],
    }


def sweep_vcenter(
    session: VCenterSession,
    *,
    log: str,
    pattern: str,
    lines: int,
    keep: int,
    hosts: Sequence[str] = (),
) -> dict[str, Any]:
    """Every connected host's log on one vCenter, matched against `pattern`. Blocking."""
    wanted = {name.strip().lower() for name in hosts if name.strip()}
    facts = sorted(read_hosts(session).values(), key=lambda host: host.name)
    if wanted:
        facts = [host for host in facts if host.name.lower() in wanted or host.moref.lower() in wanted]
    skipped = [
        {"host": host.name, "connection_state": host.connection_state}
        for host in facts
        if host.connection_state not in (None, "connected")
    ]
    connected = [host for host in facts if host.connection_state in (None, "connected")]
    rows = []
    for host in connected[:MAX_HOSTS]:
        try:
            rows.append(_host_matches(session, host, log=log, pattern=pattern, lines=lines, keep=keep))
        except vim.fault.NotAuthenticated:
            raise  # the session expired: let the pool re-login and retry the sweep
        except Exception as error:  # noqa: BLE001 - a host that will not answer is a gap, said so
            rows.append(
                {
                    "vcenter": session.vcenter.name,
                    "host": host.name,
                    "moref": host.moref,
                    "read": False,
                    "reason": f"{type(error).__name__}: {error}",
                }
            )
    return {
        "rows": rows,
        "not_connected": skipped,
        "cut": max(0, len(connected) - MAX_HOSTS),
        "unmatched_filter": sorted(
            name for name in wanted if not any(name in (h.name.lower(), h.moref.lower()) for h in facts)
        ),
    }


def summarize_sweep(rows: list[dict[str, Any]], *, pattern: str) -> dict[str, Any]:
    """Which hosts' logs carry the matching lines, and whether they cluster. Pure."""
    read = [row for row in rows if row.get("read")]
    unread = [row for row in rows if not row.get("read")]
    hit = sorted((row for row in read if row.get("matched")), key=lambda row: row["matched"], reverse=True)
    total = sum(row["matched"] for row in hit)
    findings: list[str] = []
    pattern_note = (
        "the default guest-transfer/TLS pattern" if pattern == GUEST_TRANSFER_PATTERN else "pattern"
    )
    if not read:
        findings.append(
            "no host log could be read, so nothing can be said about where the failures are — not "
            "evidence there are none" + (f" (first reason: {unread[0].get('reason')})" if unread else "")
        )
    elif not hit:
        findings.append(
            f"none of the {len(read)} host logs read has a line matching {pattern_note} in the part read; "
            "the failures may be older than that, or not on the host side"
        )
    else:
        findings.append(
            f"{len(hit)} of {len(read)} hosts have {total} matching line(s); most on {hit[0]['host']}"
        )
        top = hit[:CONCENTRATED_HOSTS]
        share = sum(row["matched"] for row in top) / total
        if len(read) > CONCENTRATED_HOSTS and share >= CONCENTRATED_SHARE:
            names = ", ".join(row["host"] for row in top)
            findings.append(
                f"concentrated: {share:.0%} of the matches are on {names} — look at those hosts "
                "(their certificate, hostd load, their network path), not at vCenter or the client"
            )
        elif len(hit) >= max(2, len(read) // 2):
            findings.append(
                "spread over most hosts: a cause every host shares — the network between the client and "
                "the hosts, the client itself, or how it uses the transfer URLs"
            )
    if unread:
        findings.append(f"{len(unread)} host log(s) not read; see `unread` for why")
    return {
        "findings": findings,
        "hosts_read": len(read),
        "hosts_with_matches": len(hit),
        "matched_total": total,
        "hosts": hit[:25],
        "unread": [{key: row.get(key) for key in ("vcenter", "host", "reason")} for row in unread[:25]],
    }


async def search_host_logs(
    pool: VCenterPool,
    names: Sequence[str],
    *,
    log: str,
    pattern: str | None,
    lines: int,
    keep: int,
    hosts: Sequence[str] = (),
) -> dict[str, Any]:
    """The same log on every connected host across the vCenters, counted per host."""
    chosen = pattern or GUEST_TRANSFER_PATTERN
    caller_pattern(chosen)  # a bad pattern is refused before any host is read

    def work(session: VCenterSession) -> dict[str, Any]:
        return sweep_vcenter(session, log=log, pattern=chosen, lines=lines, keep=keep, hosts=hosts)

    results = await asyncio.gather(*(pool.sweep(name, work) for name in names), return_exceptions=True)
    rows: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    not_connected: list[dict[str, Any]] = []
    cut: dict[str, int] = {}
    unmatched: set[str] = {name.strip().lower() for name in hosts if name.strip()}
    for name, result in zip(names, results, strict=True):
        if isinstance(result, BaseException):
            errors[name] = str(result)
            continue
        rows.extend(result["rows"])
        not_connected.extend({"vcenter": name} | row for row in result["not_connected"])
        if result["cut"]:
            cut[name] = result["cut"]
        unmatched &= set(result["unmatched_filter"])
    summary = summarize_sweep(rows, pattern=chosen)
    for name, error in errors.items():
        summary["findings"].append(f"vCenter {name} not read: {error}")
    for name, count in cut.items():
        summary["findings"].append(
            f"vCenter {name}: {count} connected host(s) past the first {MAX_HOSTS} were not read; "
            "name them in `hosts` to read them"
        )
    if not_connected:
        summary["findings"].append(f"{len(not_connected)} host(s) not connected, so not read")
    if hosts and unmatched:
        summary["findings"].append(f"no host matched: {', '.join(sorted(unmatched))}")
    summary["pattern"] = chosen
    return summary | {
        "log": log,
        "lines_per_host": lines,
        "not_connected": not_connected[:25],
        "errors": errors,
    }
