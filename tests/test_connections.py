"""Connection failures past the session count: the cap, vCenter's logs and appliance, the host path."""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import json
import ssl
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from pyVmomi import vim

from vsphere_triage import appliance, hostlogs, hosttls
from vsphere_triage.config import Settings, VCenter
from vsphere_triage.inventory import HostFacts
from vsphere_triage.readonly import ReadOnlyViolationError, ensure_session_request
from vsphere_triage.vcenter import SESSION_LIMIT_KEY, VCenterSession, against_limit

if TYPE_CHECKING:
    from pathlib import Path

# -- the session cap ---------------------------------------------------------------------------


def test_a_count_at_the_configured_cap_is_called_at_the_limit() -> None:
    result = against_limit(500, 500)

    assert result["session_limit"] == 500
    assert result["percent_of_limit"] == 100.0
    assert "refuses new logins" in result["limit_finding"]


def test_a_count_near_the_cap_is_called_close() -> None:
    assert "close to" in against_limit(420, 500)["limit_finding"]


def test_a_count_well_under_the_cap_has_no_finding() -> None:
    result = against_limit(500, 2000)

    assert result["percent_of_limit"] == 25.0
    assert "limit_finding" not in result


def test_an_unset_cap_says_the_default_applies_and_is_not_readable() -> None:
    result = against_limit(500, None)

    assert result["session_limit"] is None
    assert SESSION_LIMIT_KEY in result["session_limit_note"]
    assert "not readable" in result["session_limit_note"]


class _Option:
    def __init__(self, key: str, value: Any) -> None:
        self.key = key
        self.value = value


class _OptionManager:
    """Answers QueryOptions like vCenter: a key, a prefix ending in '.', or '' for all."""

    def __init__(self, options: dict[str, Any], *, prefixes: bool = True) -> None:
        self.options = options
        self.prefixes = prefixes

    def QueryOptions(self, name: str = "") -> list[_Option]:  # noqa: N802 - pyVmomi's name
        if name == "":
            return [_Option(key, value) for key, value in self.options.items()]
        if name.endswith("."):
            if not self.prefixes:
                raise vim.fault.InvalidName
            return [_Option(key, value) for key, value in self.options.items() if key.startswith(name)]
        if name not in self.options:
            raise vim.fault.InvalidName
        return [_Option(name, self.options[name])]


class _Entry:
    def __init__(self, key: str, user: str = "svc") -> None:
        self.key = key
        self.userName = user
        self.ipAddress = "10.0.0.9"
        self.userAgent = "leaky/1.0"
        self.loginTime = None
        self.lastActiveTime = None


class _Sessions:
    def __init__(self, count: int) -> None:
        self.sessionList = [_Entry(f"s{index}") for index in range(count)]
        self.currentSession = self.sessionList[0]


def _session(options: dict[str, Any], sessions: int, *, prefixes: bool = True) -> VCenterSession:
    session = VCenterSession(VCenter(name="vc-a", host="a"), Settings())
    session._content = type(
        "Content",
        (),
        {"sessionManager": _Sessions(sessions), "setting": _OptionManager(options, prefixes=prefixes)},
    )()
    return session


def test_the_session_count_is_read_against_the_configured_cap() -> None:
    session = _session({SESSION_LIMIT_KEY: "12"}, 12)

    counted = session.session_count()

    assert counted["total"] == 12
    assert counted["session_limit"] == 12
    assert "at its session limit" in counted["limit_finding"]


def test_the_session_breakdown_leads_with_the_cap_and_lists_connection_settings() -> None:
    options = {
        SESSION_LIMIT_KEY: "10",
        "config.vmacore.soap.sessionTimeout": "30",
        "config.vmacore.http.maxConnections": "256",
        "config.vmacore.ssl.protocols": "tls1.2",
        "config.vpxd.stats.maxQueryMetrics": "64",
    }
    session = _session(options, 9, prefixes=False)
    session._service = type("Service", (), {"CurrentTime": lambda _self: dt.datetime.now(dt.UTC)})()

    result = session.sessions()

    assert result["session_limit"] == 10
    assert result["findings"][0].startswith("9 sessions open against a configured cap of 10")
    # Read by prefix (filtered from the full list here): what was set, not guessed names.
    assert result["connection_settings"] == {
        "config.vmacore.http.maxConnections": "256",
        SESSION_LIMIT_KEY: "10",
        "config.vmacore.soap.sessionTimeout": "30",
    }


def test_an_unset_or_unreadable_cap_is_none() -> None:
    assert _session({}, 3).session_limit() is None
    assert _session({SESSION_LIMIT_KEY: "lots"}, 3).session_limit() is None


# -- the REST session exception ----------------------------------------------------------------


def test_only_a_rest_login_and_logout_may_be_other_than_a_read() -> None:
    ensure_session_request("GET", "/api/appliance/health/system")
    ensure_session_request("POST", "/api/session")
    ensure_session_request("DELETE", "/api/session/")
    for method, path in (("POST", "/api/vcenter/vm"), ("PUT", "/api/session"), ("PATCH", "/api/session")):
        with pytest.raises(ReadOnlyViolationError):
            ensure_session_request(method, path)


# -- the appliance -----------------------------------------------------------------------------


def _appliance(
    answers: dict[str, Any], *, login: int = 201
) -> tuple[appliance.Appliance, list[tuple[str, str]]]:
    sent: list[tuple[str, str]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        sent.append((request.method, request.url.path))
        if request.url.path == "/api/session":
            if request.method == "POST":
                assert request.headers["authorization"].startswith("Basic ")
                return httpx.Response(login, json="token-1") if login < 300 else httpx.Response(login)
            return httpx.Response(204)
        assert request.headers.get("vmware-api-session-id") == "token-1"
        answer = answers.get(request.url.path)
        if isinstance(answer, int):
            return httpx.Response(answer)
        if answer is None:
            return httpx.Response(404)
        return httpx.Response(200, content=json.dumps(answer))

    settings = Settings(username="u", password="p")
    client = appliance.Appliance(
        VCenter(name="vc-a", host="vca"), settings, transport=httpx.MockTransport(handle)
    )
    return client, sent


GREEN = {f"/api/appliance/health/{area}": "green" for area in appliance.HEALTH_AREAS}


def test_a_healthy_appliance_says_so_and_sends_only_reads_inside_one_session() -> None:
    answers = GREEN | {
        appliance.UPTIME_PATH: 9 * 86400.0,
        "/api/vcenter/services": {
            "vpxd": {"state": "STARTED", "health": "HEALTHY", "startup_type": "AUTOMATIC"}
        },
    }
    client, sent = _appliance(answers)

    result = client.health()

    assert result["findings"][0].startswith("appliance healthy")
    assert result["uptime_hours"] == 216.0
    assert sent[0] == ("POST", "/api/session")
    assert sent[-1] == ("DELETE", "/api/session")
    assert {method for method, _ in sent[1:-1]} == {"GET"}


def test_a_short_appliance_a_recent_restart_and_a_degraded_vpxd_are_findings() -> None:
    answers = GREEN | {
        "/api/appliance/health/mem": "red",
        "/api/appliance/health/swap": "orange",
        appliance.UPTIME_PATH: 2 * 3600.0,
        "/api/vcenter/services": {
            "vpxd": {
                "state": "STARTED",
                "health": "DEGRADED",
                "startup_type": "AUTOMATIC",
                "health_messages": [{"default_message": "vpxd is low on memory"}],
            },
            "vsan-health": {"state": "STOPPED", "startup_type": "MANUAL"},
            "envoy": {"state": "STOPPED", "startup_type": "AUTOMATIC"},
        },
    }
    client, _ = _appliance(answers)

    findings = " | ".join(client.health()["findings"])

    assert "mem red" in findings
    assert "swap orange" in findings
    assert "came up 2.0 h ago" in findings
    assert "vpxd is STARTED / DEGRADED (vpxd is low on memory)" in findings
    assert "envoy is STOPPED" in findings
    assert "vsan-health" not in findings


def test_endpoints_the_account_may_not_read_are_named_not_called_healthy() -> None:
    answers = dict.fromkeys(GREEN, 403) | {appliance.UPTIME_PATH: 9 * 86400.0}
    client, sent = _appliance(answers)

    result = client.health()

    assert "health/system" in result["not_read"]
    assert "may not be allowed" in result["not_read"]["health/system"]
    assert not any(finding.startswith("appliance healthy") for finding in result["findings"])
    assert sent[-1] == ("DELETE", "/api/session")


def test_an_older_vcenter_without_the_rest_api_is_said_in_words() -> None:
    client, sent = _appliance({}, login=404)

    with pytest.raises(appliance.ApplianceError, match=r"7\.0 U2"):
        client.health()
    assert sent == [("POST", "/api/session")]


def test_the_older_vmon_service_list_shape_is_read_too() -> None:
    rows = appliance._service_rows([{"key": "vpxd", "value": {"state": "STARTED", "health": "HEALTHY"}}])

    assert rows[0]["service"] == "vpxd"
    assert rows[0]["health"] == "HEALTHY"


# -- vCenter's own log, and the host-log sweep --------------------------------------------------


def test_a_bare_log_name_resolves_to_the_key_vcenter_offers() -> None:
    offered = ["vpxd:vpxd-214.log", "vpxd-alert:vpxd-alert-214.log", "vpxd-profiler:vpxd-profiler-214.log"]

    assert hostlogs.resolve_log_key(offered, "vpxd") == "vpxd:vpxd-214.log"
    assert hostlogs.resolve_log_key(offered, "VPXD-ALERT") == "vpxd-alert:vpxd-alert-214.log"
    assert hostlogs.resolve_log_key(offered, "vpxd:vpxd-214.log") == "vpxd:vpxd-214.log"
    assert hostlogs.resolve_log_key(offered, "hostd") is None


class _Description:
    def __init__(self, key: str) -> None:
        self.key = key


class _Diagnostics:
    def __init__(self, logs: dict[tuple[str | None, str], list[str]]) -> None:
        self.logs = logs

    def QueryDescriptions(self, host: Any = None) -> list[_Description]:  # noqa: N802 - pyVmomi's name
        moref = getattr(host, "_moId", None)
        return [_Description(key) for owner, key in self.logs if owner == moref]

    def BrowseDiagnosticLog(  # noqa: N802 - pyVmomi's name
        self, host: Any = None, key: str = "", start: int | None = None, lines: int | None = None
    ) -> Any:
        moref = getattr(host, "_moId", None)
        if (moref, key) not in self.logs:
            raise vim.fault.CannotAccessFile
        text = self.logs[(moref, key)]
        first = start or 1
        chosen = text[first - 1 : first - 1 + (lines or len(text))] if start else []
        return type("Header", (), {"lineStart": first, "lineEnd": len(text), "lineText": chosen})()


def _log_session(logs: dict[tuple[str | None, str], list[str]]) -> VCenterSession:
    session = VCenterSession(VCenter(name="vc-a", host="a"), Settings())
    session._content = type("Content", (), {"diagnosticManager": _Diagnostics(logs)})()
    session._stub = object()  # reference() binds to it; the fake ignores it
    return session


def test_vcenters_own_log_is_read_by_its_bare_name() -> None:
    lines = [f"2026-10-31T10:00:{second:02d}.000Z info vpxd[1] line {second}" for second in range(30)]
    session = _log_session({(None, "vpxd:vpxd-9.log"): lines})

    read = hostlogs.read_vcenter_log(session, "vpxd", 10)

    assert read["key"] == "vpxd:vpxd-9.log"
    assert read["available"] is True
    assert read["lines"][-1].endswith("line 29")
    assert len(read["lines"]) == 10


def test_a_log_vcenter_does_not_offer_lists_the_ones_it_does() -> None:
    session = _log_session({(None, "vpxd:vpxd-9.log"): ["x"]})

    read = hostlogs.read_vcenter_log(session, "rhttpproxy", 10)

    assert read["available"] is False
    assert read["keys_offered"] == ["vpxd:vpxd-9.log"]


def _hosts(*names: str, down: tuple[str, ...] = ()) -> dict[str, HostFacts]:
    return {
        f"host-{index}": HostFacts(
            moref=f"host-{index}",
            name=name,
            cluster="C1",
            connection_state="disconnected" if name in down else "connected",
            maintenance=False,
            core_mhz=None,
            cores=None,
            cpu_usage_mhz=None,
        )
        for index, name in enumerate(names)
    }


def test_the_sweep_counts_matches_per_host_and_calls_a_cluster_concentrated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bad = [
        f"2026-10-31T10:00:{n:02d}Z error hostd[1] SSL handshake failed for /guestFile?id={n}"
        for n in range(9)
    ]
    fine = ["2026-10-31T10:00:00Z info hostd[1] all quiet"]
    names = ("esx-01", "esx-02", "esx-03", "esx-04", "esx-05", "esx-06")
    logs: dict[tuple[str | None, str], list[str]] = {
        (f"host-{index}", "hostd"): (bad if name == "esx-02" else fine) for index, name in enumerate(names)
    }
    logs[("host-4", "hostd")] = [*fine, bad[0]]
    session = _log_session(logs)
    monkeypatch.setattr(hostlogs, "read_hosts", lambda _s: _hosts(*names, "esx-07", down=("esx-07",)))

    swept = hostlogs.sweep_vcenter(
        session, log="hostd", pattern=hostlogs.GUEST_TRANSFER_PATTERN, lines=100, keep=3
    )
    summary = hostlogs.summarize_sweep(swept["rows"], pattern=hostlogs.GUEST_TRANSFER_PATTERN)

    assert swept["not_connected"] == [{"host": "esx-07", "connection_state": "disconnected"}]
    assert summary["hosts_read"] == 6
    assert summary["hosts_with_matches"] == 2
    assert summary["hosts"][0]["host"] == "esx-02"
    assert summary["hosts"][0]["matched"] == 9
    assert len(summary["hosts"][0]["newest_matches"]) == 3
    assert any(finding.startswith("concentrated: 100%") for finding in summary["findings"])


def test_matches_on_most_hosts_are_called_spread() -> None:
    rows = [{"vcenter": "vc-a", "host": f"esx-{n}", "read": True, "matched": 2} for n in range(6)]

    findings = hostlogs.summarize_sweep(rows, pattern="x")["findings"]

    assert any(finding.startswith("spread over most hosts") for finding in findings)


def test_a_sweep_that_read_nothing_says_it_is_not_evidence() -> None:
    rows = [{"vcenter": "vc-a", "host": "esx-1", "read": False, "reason": "MethodNotFound"}]

    findings = hostlogs.summarize_sweep(rows, pattern="x")["findings"]

    assert "not evidence there are none" in findings[0]
    assert "MethodNotFound" in findings[0]


# -- the host TLS path --------------------------------------------------------------------------


def test_each_connection_failure_is_named_for_what_it_means() -> None:
    mismatch = ssl.SSLCertVerificationError(1, "x")
    mismatch.verify_message = "Hostname mismatch, certificate is not valid for 'esx-01'."
    expired = ssl.SSLCertVerificationError(1, "x")
    expired.verify_message = "certificate has expired"
    untrusted = ssl.SSLCertVerificationError(1, "x")
    untrusted.verify_message = "self-signed certificate"

    assert hosttls.outcome_of(None) == hosttls.OK
    assert hosttls.outcome_of(mismatch) == hosttls.NAME_MISMATCH
    assert hosttls.outcome_of(expired) == hosttls.EXPIRED
    assert hosttls.outcome_of(untrusted) == hosttls.UNTRUSTED
    assert hosttls.outcome_of(ssl.SSLEOFError()) == hosttls.RESET
    assert hosttls.outcome_of(ConnectionResetError()) == hosttls.RESET
    assert hosttls.outcome_of(TimeoutError()) == hosttls.NO_ANSWER
    assert hosttls.outcome_of(ConnectionRefusedError()) == hosttls.REFUSED


def test_every_host_failing_the_same_way_says_no_transfer_can_complete() -> None:
    rows = [{"vcenter": "vc-a", "name": f"esx-{n}", "outcome": hosttls.UNRESOLVED} for n in range(3)]

    summary = hosttls.summarize(rows, verify=True)

    assert summary["failing"] == 3
    assert "every host (3) fails the same way" in summary["findings"][0]
    assert "no guest file transfer can complete" in summary["findings"][0]


def test_mixed_outcomes_are_listed_worst_first() -> None:
    rows = [
        {"vcenter": "vc-a", "name": "esx-1", "outcome": hosttls.OK, "handshake_seconds": 3.5},
        {"vcenter": "vc-a", "name": "esx-2", "outcome": hosttls.NAME_MISMATCH},
        {"vcenter": "vc-a", "name": "esx-3", "outcome": hosttls.REFUSED},
    ]

    summary = hosttls.summarize(rows, verify=True)

    assert summary["findings"][0] == "2 of 3 hosts fail on 443 from this server"
    assert summary["findings"][1].startswith("refused (1): vc-a:esx-3")
    assert summary["findings"][2].startswith("certificate_name_mismatch (1): vc-a:esx-2")
    assert "esx-1 (3.5s)" in summary["findings"][3]
    assert [row["name"] for row in summary["hosts"]] == ["esx-3", "esx-2", "esx-1"]


def _self_signed(tmp_path: Path, name: str) -> tuple[Path, Path]:
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    from cryptography.x509.oid import NameOID  # noqa: PLC0415

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=10))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert = tmp_path / "cert.pem"
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private = tmp_path / "key.pem"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return cert, private


def test_a_real_handshake_is_judged_by_the_servers_trust(tmp_path: Path) -> None:
    cert, private = _self_signed(tmp_path, "esx-test")

    async def run() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, private)
        server = await asyncio.start_server(lambda _r, w: w.close(), "127.0.0.1", 0, ssl=context)
        port = server.sockets[0].getsockname()[1]
        async with server:
            trusting = Settings(ca_bundle=str(cert))
            untrusting = Settings()
            off = Settings(tls_verify=False)
            ok = await hosttls.probe("127.0.0.1", trusting, port=port)
            refused_by_trust = await hosttls.probe("127.0.0.1", untrusting, port=port)
            unverified = await hosttls.probe("127.0.0.1", off, port=port)
        closed = await hosttls.probe("127.0.0.1", trusting, port=port)
        return ok, refused_by_trust, unverified, closed

    ok, untrusted, unverified, closed = asyncio.run(run())

    assert ok["outcome"] == hosttls.OK
    assert ok["certificate"]["subject_cn"] == "esx-test"
    assert ok["certificate"]["days_left"] == pytest.approx(10, abs=0.1)
    assert untrusted["outcome"] == hosttls.UNTRUSTED
    # Refused, but the certificate is still shown, read without trusting it, to say why.
    assert untrusted["certificate"]["names"] == ["esx-test", "127.0.0.1"]
    assert unverified["outcome"] == hosttls.OK
    assert "not judged" in unverified["note"]
    assert closed["outcome"] == hosttls.REFUSED


def test_a_name_that_does_not_resolve_is_its_own_outcome() -> None:
    result = asyncio.run(hosttls.probe("esx-01.does-not-exist.invalid", Settings(timeout_seconds=5)))

    assert result["outcome"] == hosttls.UNRESOLVED
