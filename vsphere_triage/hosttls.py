"""Whether this server can reach each ESXi host on 443, and whether its certificate holds up.

A guest file transfer (the output of `run_in_guest`, or any client's
`InitiateFileTransferFromGuest` / `ToGuest`) is two steps: a SOAP call to
vCenter that returns a URL, and an HTTPS request to that URL — which names the
ESXi host, not vCenter. So "guestFile" SSL EOFs, resets and timeouts are about
the path from the client to the host and the host's own TLS endpoint, and a
vCenter with sessions to spare can still see every transfer fail.

This opens a TCP connection to each host, then a TLS handshake, and reports
which step failed and why: the name does not resolve, nothing answers (a
firewall dropping it), the connection is refused or reset, or the certificate
is not trusted, expired, or does not cover the name in the URL. No vSphere
method and no HTTP request is sent: only a handshake, then the socket is closed.

It tests from where this server runs. A client somewhere else has its own path,
so a host this server reaches can still be out of that client's reach.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from vsphere_triage.inventory import read_hosts
from vsphere_triage.vcenter import ssl_context

if TYPE_CHECKING:
    from collections.abc import Sequence

    from vsphere_triage.config import Settings
    from vsphere_triage.vcenter import VCenterPool

PORT = 443
CONCURRENT_PROBES = 16
MAX_PROBE_SECONDS = 10.0
SLOW_HANDSHAKE_SECONDS = 2.0
EXPIRES_SOON_DAYS = 30
# Hosts named per line of a finding.
SHOWN = 8

# The outcomes a probe can have, worst first in a summary.
UNRESOLVED = "name_does_not_resolve"
NO_ANSWER = "no_answer"
REFUSED = "refused"
RESET = "reset_during_handshake"
UNTRUSTED = "certificate_not_trusted"
NAME_MISMATCH = "certificate_name_mismatch"
EXPIRED = "certificate_expired"
TLS_FAILED = "tls_failed"
OK = "ok"

MEANING = {
    UNRESOLVED: "the host's name does not resolve from this server, so a transfer URL naming it cannot work",
    NO_ANSWER: "nothing answered on the port in time: a firewall dropping the traffic, or the host is down",
    REFUSED: "the host refused the connection: nothing listening, or a firewall rejecting it",
    RESET: "the connection was reset or closed during the TLS handshake — the same SSL EOF clients see",
    UNTRUSTED: "the host's certificate is not signed by a CA this server trusts (VSPHERE_CA_BUNDLE)",
    NAME_MISMATCH: "the host's certificate does not cover the name vCenter puts in the transfer URL",
    EXPIRED: "the host's certificate has expired",
    TLS_FAILED: "the TLS handshake failed for another reason; see `error`",
    OK: "reachable, and the handshake completed",
}
ORDER = [UNRESOLVED, NO_ANSWER, REFUSED, RESET, EXPIRED, NAME_MISMATCH, UNTRUSTED, TLS_FAILED, OK]


# Exception types in the order they are tested: a subclass before its base.
_OUTCOME_BY_TYPE: tuple[tuple[tuple[type[BaseException], ...], str], ...] = (
    ((ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError), RESET),
    ((ssl.SSLError,), TLS_FAILED),
    ((TimeoutError,), NO_ANSWER),
    ((ConnectionRefusedError,), REFUSED),
    ((asyncio.IncompleteReadError, EOFError), RESET),
)


def _verification_outcome(error: ssl.SSLCertVerificationError) -> str:
    message = (getattr(error, "verify_message", "") or str(error)).lower()
    if "hostname" in message or "ip address mismatch" in message:
        return NAME_MISMATCH
    if "expired" in message:
        return EXPIRED
    return UNTRUSTED


def outcome_of(error: BaseException | None) -> str:
    """Which outcome an exception from the connect or the handshake means. Pure."""
    if error is None:
        return OK
    if isinstance(error, ssl.SSLCertVerificationError):
        return _verification_outcome(error)
    for kinds, outcome in _OUTCOME_BY_TYPE:
        if isinstance(error, kinds):
            return outcome
    return TLS_FAILED


def certificate_facts(der: bytes | None, *, now: datetime | None = None) -> dict[str, Any]:
    """The subject, names and expiry of a DER certificate, when `cryptography` is installed."""
    if not der:
        return {}
    try:
        from cryptography import x509  # noqa: PLC0415 - optional: details only when it is there
        from cryptography.x509.oid import NameOID  # noqa: PLC0415
    except ImportError:
        return {"note": "install `cryptography` to see the certificate's names and expiry"}
    try:
        certificate = x509.load_der_x509_certificate(der)
    except ValueError:
        return {"note": "the certificate could not be decoded"}
    names: list[str] = []
    with contextlib.suppress(x509.ExtensionNotFound):
        alternative = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [*alternative.get_values_for_type(x509.DNSName)]
        names += [str(address) for address in alternative.get_values_for_type(x509.IPAddress)]
    common = [
        attribute.value for attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    ]
    issuer = [attribute.value for attribute in certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)]
    expires = certificate.not_valid_after_utc
    moment = now or datetime.now(UTC)
    return {
        "subject_cn": common[0] if common else None,
        "issuer_cn": issuer[0] if issuer else None,
        "names": names,
        "expires": expires,
        "days_left": round((expires - moment).total_seconds() / 86400, 1),
    }


async def probe(host: str, settings: Settings, *, port: int = PORT) -> dict[str, Any]:
    """One host: resolve, connect, handshake. Every failure is a result, never raised."""
    deadline = min(MAX_PROBE_SECONDS, settings.timeout_seconds)
    result: dict[str, Any] = {"host": host, "port": port}
    loop = asyncio.get_running_loop()
    try:
        addresses = await asyncio.wait_for(loop.getaddrinfo(host, port), timeout=deadline)
    except (OSError, TimeoutError) as error:
        return result | {"outcome": UNRESOLVED, "error": f"{type(error).__name__}: {error}"}
    result["address"] = addresses[0][4][0] if addresses else None
    started = time.monotonic()
    writer: asyncio.StreamWriter | None = None
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=deadline)
        result["connect_seconds"] = round(time.monotonic() - started, 3)
        handshake = time.monotonic()
        await asyncio.wait_for(
            writer.start_tls(ssl_context(settings), server_hostname=host), timeout=deadline
        )
        result["handshake_seconds"] = round(time.monotonic() - handshake, 3)
        tls = writer.get_extra_info("ssl_object")
        if tls is not None:
            result["tls_version"] = tls.version()
            result["certificate"] = certificate_facts(tls.getpeercert(binary_form=True))
        result["outcome"] = OK
    except (OSError, TimeoutError, ssl.SSLError, EOFError) as error:
        result["outcome"] = outcome_of(error)
        result["error"] = f"{type(error).__name__}: {getattr(error, 'verify_message', None) or error}"
        if result["outcome"] in (UNTRUSTED, NAME_MISMATCH, EXPIRED):
            result["certificate"] = await _unverified_certificate(host, port, deadline)
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
    if not settings.tls_verify and result["outcome"] == OK:
        result["note"] = "VSPHERE_TLS_VERIFY is off: the certificate was not judged, only the handshake"
    return result


async def _unverified_certificate(host: str, port: int, deadline: float) -> dict[str, Any]:
    """The certificate a host presents, read without trusting it, to say why it was refused."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host), timeout=deadline
        )
        tls = writer.get_extra_info("ssl_object")
        return certificate_facts(tls.getpeercert(binary_form=True)) if tls is not None else {}
    except (OSError, TimeoutError, ssl.SSLError):
        return {}
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=2)


def summarize(rows: list[dict[str, Any]], *, verify: bool) -> dict[str, Any]:
    """Hosts grouped by outcome, worst first, with what each outcome means for a transfer. Pure."""
    by_outcome: dict[str, list[str]] = {}
    for row in rows:
        by_outcome.setdefault(row["outcome"], []).append(f"{row['vcenter']}:{row['name']}")
    failing = [row for row in rows if row["outcome"] != OK]
    findings: list[str] = []
    if not rows:
        findings.append("no connected host to probe")
    elif not failing:
        findings.append(
            f"all {len(rows)} hosts reachable on {PORT} with a good handshake from this server: the "
            "host side of a transfer URL works from here"
        )
    elif len(failing) == len(rows) and len(by_outcome) == 1:
        outcome = failing[0]["outcome"]
        findings.append(
            f"every host ({len(rows)}) fails the same way — {outcome}: {MEANING[outcome]}. From this server "
            "no guest file transfer can complete, however healthy vCenter is"
        )
    else:
        findings.append(f"{len(failing)} of {len(rows)} hosts fail on {PORT} from this server")
        for outcome in ORDER:
            if outcome != OK and outcome in by_outcome:
                hosts = by_outcome[outcome]
                shown = ", ".join(hosts[:SHOWN]) + (
                    f" (+{len(hosts) - SHOWN} more)" if len(hosts) > SHOWN else ""
                )
                findings.append(f"{outcome} ({len(hosts)}): {shown} — {MEANING[outcome]}")
    slow = [row for row in rows if (row.get("handshake_seconds") or 0) >= SLOW_HANDSHAKE_SECONDS]
    if slow:
        findings.append(
            f"{len(slow)} host(s) took {SLOW_HANDSHAKE_SECONDS:g}s or more to finish the handshake — a busy "
            "hostd/reverse proxy on the host, or a slow path: "
            + ", ".join(f"{row['name']} ({row['handshake_seconds']}s)" for row in slow[:SHOWN])
        )
    expiring = [
        row
        for row in rows
        if isinstance((row.get("certificate") or {}).get("days_left"), (int, float))
        and row["certificate"]["days_left"] < EXPIRES_SOON_DAYS
    ]
    if expiring:
        findings.append(
            f"{len(expiring)} host certificate(s) expire within {EXPIRES_SOON_DAYS} days: "
            + ", ".join(f"{row['name']} ({row['certificate']['days_left']} d)" for row in expiring[:SHOWN])
        )
    if not verify:
        findings.append("VSPHERE_TLS_VERIFY is off, so certificates were not judged — only reachability")
    rank = {outcome: index for index, outcome in enumerate(ORDER)}
    ordered = sorted(rows, key=lambda row: (rank[row["outcome"]], -(row.get("handshake_seconds") or 0)))
    return {
        "findings": findings,
        "hosts_probed": len(rows),
        "failing": len(failing),
        "by_outcome": {outcome: len(hosts) for outcome, hosts in by_outcome.items()},
        "hosts": ordered[:50],
        "meaning": {outcome: MEANING[outcome] for outcome in by_outcome},
    }


async def check_host_tls(
    pool: VCenterPool, settings: Settings, names: Sequence[str], *, hosts: Sequence[str] = ()
) -> dict[str, Any]:
    """Probe every connected host (or the named ones) across the vCenters on 443."""
    wanted = {name.strip().lower() for name in hosts if name.strip()}
    results = await asyncio.gather(*(pool.run(name, read_hosts) for name in names), return_exceptions=True)
    targets: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    not_connected: list[str] = []
    for name, result in zip(names, results, strict=True):
        if isinstance(result, BaseException):
            errors[name] = str(result)
            continue
        for facts in result.values():
            if wanted and facts.name.lower() not in wanted and facts.moref.lower() not in wanted:
                continue
            if facts.connection_state not in (None, "connected"):
                not_connected.append(f"{name}:{facts.name}")
                continue
            targets.append({"vcenter": name, "name": facts.name, "moref": facts.moref})
    gate = asyncio.Semaphore(CONCURRENT_PROBES)

    async def one(target: dict[str, Any]) -> dict[str, Any]:
        async with gate:
            return target | await probe(target["name"], settings)

    rows = list(await asyncio.gather(*(one(target) for target in targets)))
    summary = summarize(rows, verify=settings.tls_verify)
    for name, error in errors.items():
        summary["findings"].append(f"vCenter {name} not read: {error}")
    if not_connected:
        summary["findings"].append(f"{len(not_connected)} host(s) not connected to vCenter, not probed")
    if wanted and not targets and not not_connected:
        summary["findings"].append(f"no host matched {', '.join(sorted(wanted))}")
    return summary | {
        "not_connected": not_connected[:25],
        "errors": errors,
        "note": (
            "probed from where this server runs, by the host's name in vCenter (normally the name a "
            "guest file-transfer URL carries); a client elsewhere has its own network path"
        ),
    }
