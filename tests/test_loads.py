"""Mass Tools errors: creation waves, guest-operations readiness, and the per-host line-up."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vsphere_triage import loadmap, taskhistory
from vsphere_triage.checks import GUEST_OPS_NOT_READY, classify
from vsphere_triage.config import Thresholds
from vsphere_triage.inventory import VmFacts

T0 = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)


def _tasks(operation: str, count: int, *, every_seconds: int) -> list[dict]:
    return [
        {"operation": operation, "time": T0 + timedelta(seconds=n * every_seconds), "state": "success"}
        for n in range(count)
    ]


# -- clone and power-on waves -------------------------------------------------------------------


def test_a_burst_of_clones_and_power_ons_is_called_a_wave_with_its_busiest_ten_minutes() -> None:
    rows = [
        *_tasks("VirtualMachine.clone", 12, every_seconds=30),
        *_tasks("VirtualMachine.powerOn", 25, every_seconds=20),
        *_tasks("VirtualMachine.clone", 2, every_seconds=3600),
    ]

    peaks, findings = taskhistory.creation_waves(rows)

    assert peaks["clone"]["count"] == 13  # the 12 in the burst, and the first of the two later ones
    assert peaks["clone"]["start"] == T0
    assert peaks["power_on"]["count"] == 25
    assert findings[0].startswith("clone/deploy wave: 13 clone/deploy tasks in the 10 minutes from 09:00Z")
    assert findings[1].startswith("power-on wave: 25 power-on tasks")


def test_a_trickle_of_clones_is_not_a_wave() -> None:
    peaks, findings = taskhistory.creation_waves(_tasks("VirtualMachine.clone", 9, every_seconds=600))

    assert peaks["clone"]["count"] == 1
    assert findings == []


def test_recent_tasks_carries_the_busiest_window_and_the_wave() -> None:
    rows = _tasks("VirtualMachine.clone", 10, every_seconds=10)

    summary = taskhistory.summarize_tasks(rows, now=T0 + timedelta(hours=1), window_minutes=120)

    assert summary["busiest"]["clone"]["count"] == 10
    assert any(finding.startswith("clone/deploy wave") for finding in summary["findings"])
    assert "power_on" not in summary["busiest"]


# -- guest operations readiness ---------------------------------------------------------------


def _vm(**kwargs: object) -> VmFacts:
    base = {
        "vcenter": "vc-a",
        "moref": "vm-1",
        "name": "web-01",
        "power_state": "poweredOn",
        "tools_running": "guestToolsRunning",
        "heartbeat": "green",
        "power_on_time": T0,
        "read_at": T0 + timedelta(minutes=30),
    }
    return VmFacts(**(base | kwargs))  # ty: ignore[invalid-argument-type]


def test_tools_up_but_not_ready_for_guest_operations_is_flagged() -> None:
    verdict = classify(_vm(guest_ops_ready=False), Thresholds())

    assert GUEST_OPS_NOT_READY in verdict.flags
    assert verdict.values["guest_operations_ready"] is False
    # A detail flag: it does not make an otherwise healthy VM count as abnormal.
    assert not verdict.abnormal


def test_readiness_unknown_or_true_is_not_flagged() -> None:
    assert GUEST_OPS_NOT_READY not in classify(_vm(guest_ops_ready=None), Thresholds()).flags
    assert GUEST_OPS_NOT_READY not in classify(_vm(guest_ops_ready=True), Thresholds()).flags


# -- the per-host line-up ---------------------------------------------------------------------


def _row(
    host: str, *, trouble: int, hot: bool | None, power_ons: int = 0, hits: int | None = None, vms: int = 10
) -> dict:
    return {
        "vcenter": "vc-a",
        "host": host,
        "vms": vms,
        "tools_trouble": trouble,
        "overcommitted": hot,
        "powered_on_in_window": power_ons,
        "log_hits": hits,
    }


def test_tools_trouble_on_overcommitted_hosts_with_the_transfer_failures_there_is_one_load() -> None:
    rows = [
        _row("esx-1", trouble=6, hot=True, power_ons=8, hits=40),
        _row("esx-2", trouble=3, hot=True, power_ons=5, hits=12),
        _row("esx-3", trouble=1, hot=False, hits=2),
        _row("esx-4", trouble=0, hot=False, hits=0),
    ]

    findings = loadmap.correlate(rows, logs_read=True)

    assert findings[0].startswith("10 VM(s) in Tools trouble on 3 of 4 hosts; most on esx-1 (6)")
    assert findings[1].startswith("Tools trouble follows host load: 9 of 10 (90%) on overcommitted host(s)")
    assert "which hold 50% of the VMs" in findings[1]
    assert findings[2].startswith("Tools trouble follows the creation burst: 9 of 10")
    assert findings[3].startswith("guest-transfer failures land on the same hosts: 54 of 54")


def test_transfer_failures_on_quiet_hosts_point_away_from_the_load() -> None:
    rows = [
        _row("esx-1", trouble=5, hot=True, hits=1),
        _row("esx-2", trouble=0, hot=False, hits=20),
        _row("esx-3", trouble=0, hot=False, hits=19),
    ]

    findings = loadmap.correlate(rows, logs_read=True)

    assert any(finding.startswith("Tools trouble follows host load: 5 of 5") for finding in findings)

    assert any(
        finding.startswith("guest-transfer failures are not where the Tools trouble is: 39 of 40")
        for finding in findings
    )


def test_trouble_spread_over_quiet_hosts_says_cpu_is_not_the_common_factor() -> None:
    rows = [_row("esx-1", trouble=1, hot=True), _row("esx-2", trouble=4, hot=False)]

    findings = loadmap.correlate(rows, logs_read=False)

    assert any("host CPU is not the common factor" in finding for finding in findings)
    assert not any("guest-transfer" in finding for finding in findings)
    # No host took a burst of power-ons, so the burst is not judged at all.
    assert not any("creation burst" in finding for finding in findings)


def test_unread_counters_are_said_not_called_quiet() -> None:
    findings = loadmap.correlate([_row("esx-1", trouble=2, hot=None)], logs_read=False)

    assert any("could not be judged" in finding for finding in findings)
    assert not any("follows host load" in finding for finding in findings)


def test_a_burst_that_reached_every_host_is_not_called_the_pattern() -> None:
    # Every host took new VMs: most of the trouble is on a burst host whatever caused it.
    rows = [
        _row("esx-1", trouble=2, hot=True, power_ons=4),
        _row("esx-2", trouble=3, hot=False, power_ons=6),
        _row("esx-3", trouble=2, hot=False, power_ons=5),
    ]

    findings = loadmap.correlate(rows, logs_read=False)

    assert not any("follows the creation burst" in finding for finding in findings)
    assert any(finding.startswith("the creation burst reached nearly every host") for finding in findings)


def test_trouble_on_a_host_group_no_more_than_its_share_of_vms_does_not_follow_it() -> None:
    # The overcommitted hosts hold 70% of the VMs and 70% of the trouble: no concentration.
    rows = [
        _row("esx-1", trouble=7, hot=True, vms=70),
        _row("esx-2", trouble=3, hot=False, vms=30),
    ]

    findings = loadmap.correlate(rows, logs_read=False)

    assert not any("follows host load" in finding for finding in findings)
    assert any("host CPU is not the common factor" in finding for finding in findings)


def test_a_burst_the_trouble_does_not_follow_is_said() -> None:
    rows = [
        _row("esx-1", trouble=1, hot=False, power_ons=6),
        _row("esx-2", trouble=4, hot=False),
        _row("esx-3", trouble=0, hot=False),
    ]

    findings = loadmap.correlate(rows, logs_read=False)

    assert any(
        finding.startswith("the Tools trouble does not concentrate on the hosts that took")
        for finding in findings
    )
