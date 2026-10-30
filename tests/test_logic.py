"""The pure parts: verdicts, log reading, stop codes, screenshots, grouping, conclusions."""

from __future__ import annotations

import asyncio
import io
import json
import re
import ssl
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import TYPE_CHECKING

import httpx
import pytest
from PIL import Image
from pyVmomi import vim, vmodl

from vsphere_triage import (
    ages,
    capabilities,
    checks,
    clusterevents,
    connhistory,
    console,
    contention,
    crashdump,
    diagnose,
    emscheck,
    formatting,
    guestexec,
    hostsensors,
    linuxboot,
    powerflex,
    resources,
    scan,
    snapshots,
    storagehealth,
    taskhistory,
    timecheck,
    vmlog,
    winboot,
)
from vsphere_triage.config import Settings, Thresholds, VCenter
from vsphere_triage.inventory import (
    FolderFacts,
    HostFacts,
    Inventory,
    Question,
    VmFacts,
    datastore_backing_naas,
    describe_devices,
    find_environment,
    os_family,
    set_effective_boot,
    snapshot_usage,
)
from vsphere_triage.readonly import ALLOWED_METHODS, ReadOnlyStub, ReadOnlyViolationError, ensure_read_request
from vsphere_triage.vcenter import PerfSeries, VCenterSession, ssl_context
from vsphere_triage.vrops import Vrops

if TYPE_CHECKING:
    import pathlib

NOW = datetime(2026, 10, 29, 2, 30, tzinfo=UTC)
LIMITS = Thresholds()


def vm(**fields: object) -> VmFacts:
    base: dict[str, object] = {
        "vcenter": "vc-a",
        "moref": "vm-1",
        "name": "web-01",
        "power_state": "poweredOn",
        "connection_state": "connected",
        "uptime_minutes": 25.0,
        "tools_running": "guestToolsNotRunning",
        "heartbeat": "gray",
        "cpu_mhz": 30.0,
        "num_cpu": 2,
        "host_core_mhz": 2000.0,
        "host": "esx-1",
    }
    base.update(fields)
    return VmFacts(**base)  # type: ignore[arg-type]


# -- configuration ----------------------------------------------------------------


def test_a_vcenter_answers_to_its_name_host_short_host_and_aliases() -> None:
    vcenter = VCenter(name="vc-04", host="vc04.lab.example", aliases=("Datacenter-4",))

    # Exact name, host and alias (any case), and a bare first label.
    assert all(vcenter.answers_to(name) for name in ("vc-04", "VC04.lab.example", "vc04", "datacenter-4"))
    # A different FQDN that only shares the first label must NOT match, or two
    # vCenters like vcsa.site1 and vcsa.site2 would be confused.
    assert not vcenter.answers_to("vc04.other")
    assert not vcenter.answers_to("vc-05")


def test_two_vcenters_sharing_a_first_label_stay_distinct_by_fqdn() -> None:
    a = VCenter(name="site1", host="vcsa.site1.corp")
    b = VCenter(name="site2", host="vcsa.site2.corp")

    assert a.answers_to("vcsa.site1.corp")
    assert not a.answers_to("vcsa.site2.corp")
    assert not b.answers_to("vcsa.site1.corp")


def test_settings_read_vcenters_and_thresholds_from_json() -> None:
    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": (
                '[{"name": "vc-a", "host": "a.example"}, {"name": "vc-b", "host": "b.example", "port": 8443}]'
            ),
            "VSPHERE_USERNAME": "reader",
            "VSPHERE_PASSWORD": "secret",
            "VSPHERE_THRESHOLDS": '{"booted_not_up_minutes": 15}',
            "VSPHERE_ENV_PARENT_HINTS": "environments, projects",
        }
    )

    assert [vcenter.port for vcenter in settings.vcenters] == [443, 8443]
    assert settings.thresholds.booted_not_up_minutes == 15
    assert settings.thresholds.hung_cpu_mhz == 100
    assert settings.env_parent_hints == ("environments", "projects")
    assert settings.vcenter("b").name == "vc-b"
    assert "secret" not in repr(settings)


def test_settings_refuse_a_vcenter_without_credentials_by_variable_name() -> None:
    with pytest.raises(ValueError, match="VSPHERE_"):
        Settings.from_environment({"VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]'})


def test_an_empty_ca_bundle_falls_back_to_the_system_trust_store() -> None:
    # A blank plugin field injects VSPHERE_CA_BUNDLE="", and
    # ssl.create_default_context(cafile="") raises. An empty bundle must mean
    # "use the system trust store", so building the context must not raise.
    base = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a.example"}]',
            "VSPHERE_USERNAME": "reader",
            "VSPHERE_PASSWORD": "secret",
        }
    )
    empty_bundle = base.model_copy(update={"ca_bundle": ""})
    assert ssl_context(empty_bundle).verify_mode == ssl.CERT_REQUIRED


def test_an_unknown_vcenter_lists_the_known_ones() -> None:
    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
        }
    )

    with pytest.raises(LookupError, match="configured: vc-a"):
        settings.vcenter("vc-z")


# -- verdicts ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fields", "state"),
    [
        ({"connection_state": "orphaned"}, checks.INACCESSIBLE),
        ({"question": Question("1", "moved or copied?", ["Cancel"])}, checks.BLOCKED_ON_QUESTION),
        ({"power_state": "poweredOff"}, checks.OFF),
        ({"tools_running": "guestToolsRunning", "heartbeat": "green"}, checks.HEALTHY),
        ({"tools_running": "guestToolsRunning", "heartbeat": "gray"}, checks.HEALTHY),
        ({"tools_running": "guestToolsRunning", "heartbeat": "red"}, checks.LOST_HEARTBEAT),
        ({"uptime_minutes": None}, checks.NO_BOOT_TIME),
        ({"uptime_minutes": 4.0}, checks.BOOTING),
        ({"cpu_mhz": 30.0}, checks.HUNG),
        ({"cpu_mhz": 3600.0}, checks.BUSY_NOT_UP),
        ({"cpu_mhz": 900.0}, checks.BOOTED_NOT_UP),
        ({"cpu_mhz": 900.0, "host_core_mhz": None}, checks.BOOTED_NOT_UP),
    ],
)
def test_each_state_is_judged_on_its_own_values(fields: dict[str, object], state: str) -> None:
    verdict = checks.classify(vm(**fields), LIMITS)

    assert verdict.state == state
    assert verdict.values["uptime_minutes"] == fields.get("uptime_minutes", 25.0)


def test_a_question_outranks_everything_but_reachability() -> None:
    verdict = checks.classify(vm(question=Question("1", "q", []), power_state="poweredOff"), LIMITS)

    assert verdict.state == checks.BLOCKED_ON_QUESTION


def test_resets_in_the_window_flag_a_boot_loop() -> None:
    verdict = checks.classify(vm(uptime_minutes=1.0), LIMITS, resets_in_window=3)

    assert verdict.state == checks.BOOTING
    assert verdict.flags == [checks.BOOT_LOOP]
    assert verdict.abnormal


def test_ready_time_is_a_percent_per_vcpu() -> None:
    # 6,000 ms ready in a 20 s sample on 2 vCPUs: 15% each.
    assert checks.ready_percent(6000, 20, 2) == pytest.approx(15.0)


def _host(**kw: object) -> HostFacts:
    base = {
        "moref": "host-1",
        "name": "esx-1",
        "cluster": "c",
        "connection_state": "connected",
        "maintenance": False,
        "core_mhz": 2000.0,
        "cores": 2,
        "cpu_usage_mhz": None,
    }
    return HostFacts(**(base | kw))  # type: ignore[arg-type]


def _series(counter: str, value: float) -> PerfSeries:
    return PerfSeries(counter=counter, unit="megaHertz", interval_seconds=20, samples={"": [(NOW, value)]})


def test_host_cpu_demand_over_capacity_is_overcommit() -> None:
    result = contention.host_cpu_from_series(
        _host(), {"cpu.demand.average": _series("cpu.demand.average", 4800)}, LIMITS
    )

    assert result["basis"] == "demand"
    assert result["peak_percent_of_capacity"] == 120.0
    assert result["overcommitted"] is True


def test_host_usage_only_cannot_prove_overcommit() -> None:
    result = contention.host_cpu_from_series(
        _host(), {"cpu.usagemhz.average": _series("cpu.usagemhz.average", 3960)}, LIMITS
    )

    assert result["basis"] == "usage"
    assert result["peak_percent_of_capacity"] == 99.0
    assert result["overcommitted"] is None  # unknown from usage alone
    assert result["near_capacity"] is True


def test_no_host_series_reports_current_not_a_window_peak() -> None:
    result = contention.host_cpu_from_series(_host(cpu_usage_mhz=3960.0), {}, LIMITS)

    assert result["basis"] == "current"
    assert result["peak_percent_of_capacity"] is None
    assert result["current_percent_of_capacity"] == 99.0
    assert result["overcommitted"] is None


# -- inventory concepts --------------------------------------------------------------


def folder(moref: str, name: str, parent: str | None, path: str, parent_name: str | None) -> FolderFacts:
    return FolderFacts(moref, name, parent, path, parent_name, "DC0")


def test_an_environment_is_found_by_exact_name_before_containing_it() -> None:
    folders = {
        "g1": folder("g1", "env-1001", "p", "/DC0/vm/environments/env-1001", "environments"),
        "g2": folder("g2", "env-10011", "p", "/DC0/vm/environments/env-10011", "environments"),
        "g3": folder("g3", "old-env-1001-copy", "q", "/DC0/vm/archive/old-env-1001-copy", "archive"),
    }

    assert [match.moref for match in find_environment(folders, "ENV-1001")] == ["g1"]
    # Without an exact match, every folder containing the id comes back, for the reader to choose.
    assert {match.moref for match in find_environment(folders, "env-100")} == {"g1", "g2", "g3"}


def test_hinted_parents_come_first_but_nothing_is_dropped() -> None:
    folders = {
        "g1": folder("g1", "env-7", "a", "/DC0/vm/a/b/env-7", "elsewhere"),
        "g2": folder("g2", "env-7", "p", "/DC0/vm/projects/env-7/x/y", "projects"),
    }

    assert [match.moref for match in find_environment(folders, "env-7", ["projects"])] == ["g2", "g1"]
    assert [match.moref for match in find_environment(folders, "env-7")] == ["g1", "g2"]


@pytest.mark.parametrize(
    ("guest_id", "full_name", "family", "expected"),
    [
        ("windows9_64Guest", None, None, "windows"),
        ("winVistaGuest", None, None, "windows"),
        (None, "Microsoft Windows Server 2019", None, "windows"),
        ("otherGuest", None, "windowsGuest", "windows"),
        ("rhel8_64Guest", None, None, "linux"),
        ("otherGuest", None, None, "unknown"),
    ],
)
def test_os_family_from_any_of_three_fields(
    guest_id: str | None, full_name: str | None, family: str | None, expected: str
) -> None:
    assert os_family(guest_id, full_name, family) == expected


# -- vmware.log --------------------------------------------------------------------------

NEW = """\
2026-10-29T02:05:00.100Z In(05) vmx - Transitioned vmx/execState/val to poweredOn
2026-10-29T02:05:02.000Z In(05) vcpu-0 - EFI ROM: boot order: Windows Boot Manager
2026-10-29T02:05:20.000Z In(05) vmx - HBACommon: First write on scsi0:0.fileName='x.vmdk'
2026-10-29T02:06:40.000Z Wa(03) vmx - SCSI0: RESET BUS
  a continuation line
2026-10-29T02:07:00.000Z In(05) vmx - VMXNET3 user: Ethernet0 Driver Info: version = 1
"""
OLD = """\
2016-01-01T00:00:00.000Z| vmx| I125: Transitioned vmx/execState/val to poweredOn
2016-01-01T00:00:30.000Z| vcpu-0| W115: Guest-initiated reset
2016-01-01T00:01:00.000Z| vmx| I125: ToolsSetVersion: Tools version 10346
"""


def test_both_log_formats_parse() -> None:
    new = vmlog.parse_lines(NEW)
    old = vmlog.parse_lines(OLD)

    assert new[3].level == "warning"
    assert new[3].thread == "vmx"
    assert new[4].time is None
    assert old[1].level == "warning"
    assert old[1].message == "Guest-initiated reset"


def test_the_timeline_says_how_far_the_boot_got_and_what_happened() -> None:
    timeline = vmlog.boot_timeline(vmlog.parse_lines(NEW))

    assert timeline["last_stage"] == "guest_drivers"
    assert timeline["not_reached"] == ["tools"]
    assert timeline["annotations"]["storage"]["count"] == 1
    assert timeline["seconds_from_last_stage_to_end_of_log"] == 0


def test_the_timeline_starts_at_the_last_reset() -> None:
    timeline = vmlog.boot_timeline(vmlog.parse_lines(OLD))

    assert timeline["boot_started"] == datetime(2016, 1, 1, 0, 0, 30, tzinfo=UTC)
    assert timeline["last_stage"] == "tools"


def test_a_log_with_no_boot_says_so() -> None:
    timeline = vmlog.boot_timeline(vmlog.parse_lines("2026-10-29T02:05:00.100Z In(05) vmx - nothing here\n"))

    assert timeline["boot_found"] is False


def test_grep_keeps_the_newest_and_counts_all() -> None:
    lines = vmlog.parse_lines(NEW)

    kept, total = vmlog.grep(lines, None, limit=2)
    since, _ = vmlog.grep(lines, ".*", since=datetime(2026, 10, 29, 2, 6, tzinfo=UTC), limit=10)

    assert total == 5
    assert [line.number for line in kept] == [4, 6]
    assert [line.number for line in since] == [4, 5, 6]


def test_stop_codes_by_number_and_by_name() -> None:
    text = "*** STOP: 0x00000101 (0x0, ...)\nlater: Stop code: CRITICAL_PROCESS_DIED\nBugCheck 0x7b"

    codes = vmlog.stop_codes(text)

    assert [code["code"] for code in codes] == ["0x00000101", "0x0000007B", "0x000000EF"]
    assert codes[0]["points_at"].startswith("CPU")
    assert codes[1]["points_at"].startswith("storage")


def test_serial_output_without_ems_or_errors_is_plain() -> None:
    result = vmlog.read_serial("hello\nworld\n", tail_lines=1)

    assert result == {
        "bytes": 12,
        "lines": 2,
        "empty": False,
        "ems_output_seen": False,
        "windows_stop_codes": [],
        "stop_codes_scoped_to_current_boot": False,
        "linux_findings": [],
        "linux_findings_scoped_to_current_boot": False,
        "linux_findings_earlier_boots": [],
        "tail": ["world"],
    }


def test_a_stop_code_before_the_last_ems_boot_is_not_this_boot() -> None:
    text = (
        "Computer is booting, SAC started and initialized.\n"
        "*** STOP: 0x0000007B INACCESSIBLE_BOOT_DEVICE\n"
        "Computer is booting, SAC started and initialized.\n"  # the reboot we care about
        "SAC>\n"
    )

    result = vmlog.read_serial(text, tail_lines=2)

    assert result["windows_stop_codes"] == []  # the 0x7B was before the last boot
    assert result["stop_codes_scoped_to_current_boot"] is True


def test_a_stop_code_after_the_last_ems_boot_is_reported() -> None:
    text = (
        "Computer is booting, SAC started and initialized.\n*** STOP: 0x0000007A KERNEL_DATA_INPAGE_ERROR\n"
    )

    result = vmlog.read_serial(text, tail_lines=2)

    assert [code["code"] for code in result["windows_stop_codes"]] == ["0x0000007A"]


# -- the console --------------------------------------------------------------------------


def image(colour: tuple[int, int, int]) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (200, 150), colour).save(buffer, format="PNG")
    return buffer.getvalue()


def test_black_and_frozen_screens_are_said_in_words() -> None:
    result = console.read_captures(
        [image((0, 0, 0)), image((0, 0, 0))], black_fraction=0.98, frozen_difference=0.5
    )

    assert result["black"] is True
    assert result["frozen"] is True
    assert result["text"] is None
    assert any("not read" in finding for finding in result["findings"])


def test_a_changing_screen_is_not_frozen() -> None:
    result = console.read_captures(
        [image((0, 0, 0)), image((90, 90, 90))], black_fraction=0.98, frozen_difference=0.5
    )

    assert result["frozen"] is False


@pytest.mark.parametrize("colour", [(0, 0, 170), (0, 120, 215)])
def test_both_generations_of_blue_screen_are_recognised(colour: tuple[int, int, int]) -> None:
    assert console.analyse(image(colour))["blue_screen_colour_fraction"] == 1.0


@pytest.mark.parametrize(
    ("text", "state"),
    [
        ("Your PC ran into a problem and needs to restart. Stop code: CRITICAL PROCESS DIED", "blue_screen"),
        ("Working on updates  30% complete. Don't turn off your computer", "windows_updating"),
        ("Preparing Automatic Repair", "automatic_repair"),
        ("Starting Windows", "windows_starting"),
        ("Press Ctrl+Alt+Delete to sign in.", "windows_logon"),
        ("Kernel panic - not syncing: VFS", "linux_panic"),
        ("Getting devices ready 45%", "device_setup"),
    ],
)
def test_ocr_text_names_the_screen(text: str, state: str) -> None:
    assert console.screen_state(text)[0]["state"] == state


# -- grouping a scan ------------------------------------------------------------------------


def scan_of(vms: list[VmFacts]) -> scan.Scan:
    by_vcenter: dict[str, list[VmFacts]] = {}
    for item in vms:
        by_vcenter.setdefault(item.vcenter, []).append(item)
    return scan.Scan(
        id="s1",
        started=NOW,
        vcenters={
            name: scan.VCenterScan(
                inventory=Inventory(name, NOW, members, {}, {}, {}, base_disks_read=True),
                verdicts={item.moref: checks.classify(item, LIMITS) for item in members},
                hosts={},
                storage=None,
            )
            for name, members in by_vcenter.items()
        },
        errors={},
    )


def test_the_strongest_group_is_the_one_that_concentrates_the_stuck_vms() -> None:
    fleet = [
        vm(
            moref=f"vm-{index}",
            host=f"esx-{index % 4}",
            base_disk="[ds] base-a.vmdk" if index < 4 else "[ds] base-b.vmdk",
            datastores=["ds-1"],
            tools_running="guestToolsNotRunning" if index < 3 else "guestToolsRunning",
            heartbeat="green",
        )
        for index in range(20)
    ]

    result = scan.summary(scan_of(fleet), limit=10)

    assert result["strongest_groups"][0]["dimension"] == "base_disk"
    assert result["strongest_groups"][0]["value"] == "vc-a:[ds] base-a.vmdk"
    assert result["strongest_groups"][0]["abnormal"] == 3
    assert result["strongest_groups"][0]["population"] == 4
    # A datastore every VM is on says nothing and is left out.
    assert "datastore" not in result["groups"]


def test_a_scan_for_other_states_does_not_call_them_abnormal() -> None:
    fleet = [
        vm(
            moref=f"vm-{index}",
            host=f"esx-{index % 4}",
            base_disk="[ds] base-a.vmdk" if index < 4 else "[ds] base-b.vmdk",
            tools_running="guestToolsRunning" if index < 3 else "guestToolsNotRunning",
            heartbeat="green",
        )
        for index in range(20)
    ]

    result = scan.summary(scan_of(fleet), states=["healthy"], limit=10)

    assert result["findings"][0].startswith("3 healthy of 20")
    assert all("abnormal" not in finding for finding in result["findings"][:2])
    assert result["findings"][1].endswith("are healthy (5x the fleet rate)")
    # Past the limit, the rest are still named, one line each.
    narrow = scan.summary(scan_of(fleet), limit=2)
    assert len(narrow["abnormal_vms"]) == 2
    assert len(narrow["more_abnormal_vms"]) == narrow["abnormal_vms_truncated"] == 15
    assert narrow["more_abnormal_vms"][0].startswith("vc-a/vm-")
    # The rows carry their meaning once, above them, and no unset values.
    row = result["abnormal_vms"][0]["verdict"]
    assert "meaning" not in row
    assert None not in row["values"].values()


def test_a_scan_too_large_for_its_rows_still_fits_and_names_the_rest(monkeypatch: pytest.MonkeyPatch) -> None:
    from vsphere_triage.server import build_server  # noqa: PLC0415

    fleet = [
        vm(
            moref=f"vm-{index}",
            name=f"vm-{index:04d}-with-a-long-name",
            host=f"esx-{index % 9}",
            base_disk="[ds] base-a.vmdk" if index < 550 else "[ds] base-b.vmdk",
            **({} if index < 600 else {"tools_running": "guestToolsRunning", "heartbeat": "green"}),
        )
        for index in range(700)
    ]
    fleet[0].notes = ["x" * 2000]  # rows that are each heavy

    async def run_scan(*_: object, **__: object) -> scan.Scan:
        return scan_of(fleet)

    monkeypatch.setattr(scan, "run_scan", run_scan)
    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
        }
    )

    result = asyncio.run(build_server(settings).call_tool("scan", {"limit": 500})).structured_content

    assert "truncated" not in result  # the rows gave way, not the groups and findings
    assert formatting.size(result) <= formatting.MAX_RESPONSE_CHARACTERS
    assert result["strongest_groups"]
    assert result["more_abnormal_vms"][0].startswith("vc-a/vm-")
    assert len(result["abnormal_vms"]) + len(result["more_abnormal_vms"]) > 30


def test_a_scan_for_some_abnormal_states_still_calls_them_abnormal() -> None:
    fleet = [vm(moref=f"vm-{index}", host=f"esx-{index % 4}") for index in range(8)]

    result = scan.summary(scan_of(fleet), states=["hung", "busy_not_up", "booted_not_up"], limit=10)

    assert " abnormal of " in result["findings"][0]


def test_a_brief_line_carries_the_flags_that_make_a_vm_abnormal() -> None:
    row = {"vcenter": "vc-a", "moref": "vm-42", "name": "loop-01", "folder": "env-1003"}

    line = scan.brief(row | {"verdict": {"state": "healthy", "flags": ["boot_loop"]}})

    assert line == "vc-a/vm-42 loop-01 in env-1003: healthy (boot_loop)"


def test_the_same_host_name_on_two_vcenters_is_two_hosts() -> None:
    fleet = [
        vm(vcenter="vc-a", moref="vm-1", host="DC0_H0"),
        vm(vcenter="vc-a", moref="vm-2", host="DC0_H0"),
        vm(vcenter="vc-b", moref="vm-1", host="DC0_H0", tools_running="guestToolsRunning", heartbeat="green"),
        vm(vcenter="vc-b", moref="vm-2", host="DC0_H0", tools_running="guestToolsRunning", heartbeat="green"),
    ]

    hosts = {row["value"]: row for row in scan.groups(scan_of(fleet))["host"]}

    assert hosts["vc-a:DC0_H0"]["population"] == 2
    assert "vc-b:DC0_H0" not in hosts


def test_representatives_span_the_boot_times() -> None:
    members = [vm(moref=f"vm-{index}", boot_time=NOW - timedelta(minutes=index)) for index in range(7)]

    picked = scan.representatives(members)

    assert [item.moref for item in picked] == ["vm-6", "vm-3", "vm-0"]


# -- conclusions ------------------------------------------------------------------------------


def conclude(**parts: dict) -> dict:
    defaults: dict[str, dict] = {
        "cpu": {"findings": [], "starved": False},
        "disk": {"findings": [], "slow": False, "datastores": []},
        "environment": {"signals": []},
        "logs": {"available": False},
        "serial": {"available": False},
        "console": {"available": False},
        "host_log": {"available": False},
    }
    defaults.update(parts)
    machine = vm(cpu_mhz=3600.0)
    return diagnose.conclude(checks.classify(machine, LIMITS), vm=machine, **defaults)


def test_cpu_evidence_from_three_places_is_high_confidence() -> None:
    result = conclude(
        cpu={"findings": ["ready 30%", "host at 120%"], "starved": True},
        environment={"signals": [{"kind": "only_abnormal_on", "dimension": "host", "values": ["esx-1"]}]},
    )

    assert result["causes"][0]["cause"] == diagnose.CPU
    assert result["causes"][0]["confidence"] == "high"
    assert "booting slowly" in result["headline"]


def test_healthy_neighbours_on_the_same_datastore_argue_against_it() -> None:
    result = conclude(
        disk={"findings": ["datastore ds-1 write latency peaked at 60 ms"], "slow": True, "datastores": []},
        environment={
            "signals": [{"kind": "shared_with_healthy", "dimension": "datastore", "values": ["ds-1"]}]
        },
    )

    storage = next(cause for cause in result["causes"] if cause["cause"] == diagnose.STORAGE)
    assert storage["against"] == ["healthy VMs in its environment are on the same datastore ds-1"]
    assert storage["confidence"] != "high"


def test_a_stop_code_on_the_serial_console_names_the_crash_and_its_layer() -> None:
    serial = {
        "available": True,
        "files": [
            {
                "windows_stop_codes": [
                    {
                        "code": "0x0000007A",
                        "name": "KERNEL_DATA_INPAGE_ERROR",
                        "points_at": "storage: paging I/O failed",
                    }
                ],
                "linux_findings": [],
            }
        ],
    }

    result = conclude(serial=serial)

    assert [cause["cause"] for cause in result["causes"]][:2] == [diagnose.WINDOWS_CRASH, diagnose.STORAGE]


def test_a_boot_loop_is_the_cause_not_a_hang_of_its_last_boot() -> None:
    # The last boot stopping after firmware is one turn of the loop, not a separate hang.
    machine = vm(uptime_minutes=2.0, cpu_mhz=30.0)
    verdict = checks.classify(machine, LIMITS, resets_in_window=4)
    logs = {"timeline": {"boot_found": True, "last_stage": "firmware", "annotations": {}}}

    result = diagnose.conclude(
        verdict,
        vm=machine,
        cpu={"findings": [], "starved": False},
        disk={"findings": [], "slow": False, "datastores": []},
        environment={"signals": []},
        logs=logs,
        serial={"available": False},
        console={"available": False},
        host_log={"available": False},
    )

    assert result["causes"][0]["cause"] == diagnose.BOOT_LOOP_CAUSE
    assert "4 resets" in result["causes"][0]["for"][0]
    assert any("who resets it" in step for step in diagnose.next_checks(result, machine))


def test_a_device_the_healthy_neighbours_share_argues_against_itself() -> None:
    nic = "network adapter 'ethernet-0' is not connected (no link; PXE/DHCP would fail)"
    machine = vm(cpu_mhz=10.0, uptime_minutes=40.0)
    machine.device_blocks = [nic]

    result = _conclude_on(machine, environment={"signals": [], "healthy_device_blocks": [nic]})

    hardware = next(entry for entry in result["argued_against"] if entry["cause"] == diagnose.HARDWARE)
    assert hardware["against"] == [f"a healthy VM in its environment has the same: {nic}"]
    assert diagnose.HARDWARE not in [entry["cause"] for entry in result["causes"]]


def test_a_device_only_this_vm_has_still_counts_beside_one_its_neighbours_share() -> None:
    nic = "network adapter 'ethernet-0' is not connected (no link; PXE/DHCP would fail)"
    iso = "CD-ROM 'cdrom-0' has an ISO mounted and connected at power-on"
    machine = vm(cpu_mhz=10.0, uptime_minutes=40.0)
    machine.device_blocks = [nic, iso]

    result = _conclude_on(machine, environment={"signals": [], "healthy_device_blocks": [nic]})

    hardware = next(entry for entry in result["causes"] if entry["cause"] == diagnose.HARDWARE)
    assert hardware["for"] == [iso]
    assert hardware["against"] == [f"a healthy VM in its environment has the same: {nic}"]


def test_a_boot_loop_whose_boots_look_hung_is_still_a_boot_loop() -> None:
    # Low CPU past the boot window is HUNG; a black, still console and a log that
    # stops at firmware would each add to an early hang on their own.
    machine = vm(cpu_mhz=10.0, uptime_minutes=40.0)
    verdict = checks.classify(machine, LIMITS, resets_in_window=4)
    console = {"available": True, "frozen": True, "black": True, "screen_states": [], "stop_codes": []}
    logs = {"timeline": {"boot_found": True, "last_stage": "firmware", "annotations": {}}}

    result = diagnose.conclude(
        verdict,
        vm=machine,
        cpu={"findings": [], "starved": False},
        disk={"findings": [], "slow": False, "datastores": []},
        environment={"signals": []},
        logs=logs,
        serial={"available": False},
        console=console,
        host_log={"available": False},
    )

    assert verdict.state == checks.HUNG
    assert result["causes"][0]["cause"] == diagnose.BOOT_LOOP_CAUSE
    assert diagnose.EARLY_HANG not in [entry["cause"] for entry in result["causes"]]
    assert any(text.startswith("each boot stops early") for text in result["causes"][0]["for"])


def test_a_busy_linux_guest_is_never_windows_still_working() -> None:
    busy = vm(cpu_mhz=3600.0, uptime_minutes=40.0, os_family="linux", guest_os="Red Hat Enterprise Linux 8")

    result = _conclude_on(busy)

    assert diagnose.STILL_WORKING not in [
        entry["cause"] for entry in [*result["causes"], *result["argued_against"]]
    ]


def test_nothing_read_is_listed_as_not_checked() -> None:
    result = conclude(cpu={"available": False, "reason": "x"})

    assert "CPU counters" in result["not_checked"]
    assert "console screen" in result["not_checked"]


def test_the_check_window_starts_before_the_boot() -> None:
    boot = NOW - timedelta(minutes=20)

    assert diagnose.window(NOW, boot) == (boot - timedelta(minutes=2), NOW)
    old = NOW - timedelta(hours=5)
    assert diagnose.window(NOW, old) == (old - timedelta(minutes=5), old + timedelta(minutes=30))


# -- counters ---------------------------------------------------------------------------------


def test_datastore_instances_try_the_volume_id_then_the_name() -> None:
    assert contention.datastore_instances({"url": "ds:///vmfs/volumes/5f1a-22/", "name": "pflex-07"}) == [
        "5f1a-22",
        "pflex-07",
    ]
    assert contention.datastore_instances({"url": "/sim/x/DC0-LocalDS_0", "name": "LocalDS_0"}) == [
        "LocalDS_0",
        "DC0-LocalDS_0",
    ]


def test_a_series_is_summarised_with_its_peak() -> None:
    samples = [(NOW + timedelta(seconds=20 * index), value) for index, value in enumerate([1.0, 9.0, 4.0])]

    summary = contention.summarize(samples)

    assert summary is not None
    assert (summary["max"], summary["mean"], summary["last"]) == (9.0, 4.67, 4.0)
    assert summary["peak_at"] == NOW + timedelta(seconds=20)
    assert summary["steady"] is False


def test_a_flat_series_is_steady_not_peaking_at_its_first_sample() -> None:
    samples = [(NOW + timedelta(seconds=20 * index), 180.0) for index in range(4)]

    summary = contention.summarize(samples)

    assert summary is not None
    assert summary["steady"] is True


# -- read-only --------------------------------------------------------------------------------


class Inner:
    version = "vim.version.v8_0_2_0"
    cookie = 'vmware_soap_session="abc"; Path=/'

    def __init__(self) -> None:
        self.sent: list[str] = []

    def InvokeMethod(self, _mo: object, info: object, _args: object, _outer: object) -> tuple[int, str]:  # noqa: N802
        self.sent.append(info.wsdlName)  # type: ignore[attr-defined]
        return 200, "ok"


class Info:
    def __init__(self, name: str) -> None:
        self.wsdlName = name


def test_a_write_is_refused_before_anything_is_sent() -> None:
    inner = Inner()
    stub = ReadOnlyStub(inner)

    for name in (
        "PowerOffVM_Task",
        "AnswerVM",
        "CreateScreenshot_Task",
        "ReconfigVM_Task",
        "Destroy_Task",
        "CreateFolder",
    ):
        with pytest.raises(ReadOnlyViolationError):
            stub.InvokeMethod(None, Info(name), ())
    assert stub.InvokeMethod(None, Info("RetrievePropertiesEx"), ()) == "ok"
    assert inner.sent == ["RetrievePropertiesEx"]
    assert stub.seen == {"RetrievePropertiesEx"}


def test_nothing_on_the_read_list_writes() -> None:
    writes = (
        "Power",
        "Reset",
        "Reboot",
        "Shutdown",
        "Answer",
        "Reconfig",
        "Create",
        "Destroy",
        "Delete",
        "Move",
        "Relocate",
        "Migrate",
        "Clone",
        "Register",
        "Upload",
        "Rename",
        "Remove",
        "Mount",
        "Revert",
        "Snapshot",
        "Consolidate",
        "Screenshot",
        "Put",
        "Update",
    )
    # Session-scoped views and collectors: created and destroyed within this session, changing nothing.
    allowed_sessions = {"CreateContainerView", "DestroyView", "CreateCollectorForTasks", "DestroyCollector"}

    for name in ALLOWED_METHODS - allowed_sessions:
        assert not any(word in name for word in writes), name


@pytest.mark.parametrize("method", ["PUT", "POST", "DELETE", "PATCH"])
def test_http_writes_are_refused(method: str) -> None:
    with pytest.raises(ReadOnlyViolationError):
        ensure_read_request(method)
    ensure_read_request("get")


# -- results ------------------------------------------------------------------------------------


def test_results_are_json_with_utc_times_and_no_private_keys() -> None:
    result = formatting.bounded({"when": datetime(2026, 1, 1, 3, tzinfo=UTC), "_ref": object(), "n": 1.23456})

    assert result == {"when": "2026-01-01T03:00:00Z", "n": 1.235}


def test_a_large_result_is_cut_and_says_so() -> None:
    result = formatting.bounded({"findings": ["a"], "rows": [{"text": "x" * 500} for _ in range(2000)]})

    assert "truncated" in result
    assert formatting.size(result) <= formatting.MAX_RESPONSE_CHARACTERS
    assert result["findings"] == ["a"]


# -- vROps ----------------------------------------------------------------------------------------


def test_vrops_logs_in_once_and_compares_a_window_with_previous_days() -> None:
    requests: list[httpx.Request] = []
    begin = datetime(2026, 10, 29, 2, 0, tzinfo=UTC)

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/auth/token/acquire"):
            return httpx.Response(200, json={"token": "t-1"})
        if request.url.path.endswith("/stats"):
            start = int(request.url.params["begin"])
            days_ago = round((begin.timestamp() * 1000 - start) / 86_400_000)
            peak = 135.0 if days_ago == 0 else 90.0 + days_ago
            return httpx.Response(
                200,
                json={
                    "values": [
                        {
                            "stat-list": {
                                "stat": [
                                    {
                                        "statKey": {"key": "cpu|demandPct"},
                                        "timestamps": [start, start + 300_000],
                                        "data": [50.0, peak],
                                    }
                                ]
                            }
                        }
                    ]
                },
            )
        return httpx.Response(404)

    settings = Settings.from_environment(
        {
            "VSPHERE_VROPS_URL": "https://vrops.example/",
            "VSPHERE_VROPS_USERNAME": "reader",
            "VSPHERE_VROPS_PASSWORD": "secret",
        }
    )
    client = Vrops(settings, transport=httpx.MockTransport(respond))

    result = asyncio.run(
        client.compare(
            "host-1",
            ["cpu|demandPct"],
            begin,
            begin + timedelta(minutes=30),
            baseline_days=3,
            interval_minutes=5,
        )
    )

    assert result["cpu|demandPct"]["window_max"] == 135.0
    assert result["cpu|demandPct"]["unusual"] is True
    assert result["cpu|demandPct"]["baseline_max_of_maxes"] == 93.0
    assert sum(1 for request in requests if request.url.path.endswith("acquire")) == 1
    assert all(
        request.headers["Authorization"] == "vRealizeOpsToken t-1"
        for request in requests
        if request.method == "GET"
    )


# -- the signals beyond "stuck" ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("fields", "state"),
    [
        ({"paused": True}, checks.PAUSED),
        ({"power_state": "suspended"}, checks.SUSPENDED),
        ({"tools_status": "toolsNotInstalled", "cpu_mhz": 3000.0}, checks.NO_TOOLS),
        ({"tools_status": "toolsNotRunning"}, checks.HUNG),
        ({"tools_running": "guestToolsExecutingScripts", "cpu_mhz": 900.0}, checks.BOOTED_NOT_UP),
    ],
)
def test_the_newer_states(fields: dict[str, object], state: str) -> None:
    assert checks.classify(vm(**fields), LIMITS).state == state


def test_a_vm_without_tools_is_not_abnormal_but_is_explained() -> None:
    verdict = checks.classify(vm(tools_status="toolsNotInstalled", cpu_mhz=2000.0), LIMITS)

    assert not verdict.abnormal
    assert "toolsNotInstalled" in verdict.reasons[0]
    assert "50%" in verdict.reasons[0]


@pytest.mark.parametrize(
    ("fields", "flag", "attention"),
    [
        ({"tools_running": "guestToolsRunning", "heartbeat": "yellow"}, checks.HEARTBEAT_INTERMITTENT, True),
        # Context flags: reported, but a VM with only these is not abnormal.
        ({"swapped_mb": 10}, checks.MEMORY_RECLAIMED, False),
        ({"ballooned_mb": 10}, checks.MEMORY_RECLAIMED, False),
        ({"host_memory_percent": 97.0}, checks.HOST_MEMORY_PRESSURE, False),
        ({"alarms": [{"alarm": "VM CPU", "status": "red"}]}, checks.VCENTER_ALARM, False),
        ({"host_connection_state": "notResponding"}, checks.HOST_NOT_CONNECTED, True),
        ({"created": NOW - timedelta(hours=30), "read_at": NOW}, checks.LONG_RUNNING, False),
        ({"host_maintenance": True}, checks.HOST_IN_MAINTENANCE, False),
        ({"tools_version_status": "guestToolsTooOld"}, checks.TOOLS_OUTDATED, False),
    ],
)
def test_each_flag_and_whether_it_matters_alone(
    fields: dict[str, object], flag: str, attention: bool
) -> None:
    healthy = {"tools_running": "guestToolsRunning", "heartbeat": "green"}

    verdict = checks.classify(vm(**(healthy | fields)), LIMITS)

    assert flag in verdict.flags
    assert verdict.abnormal is attention
    assert verdict.as_dict()["flags_meaning"][flag]


def test_a_yellow_alarm_alone_is_not_flagged() -> None:
    verdict = checks.classify(vm(alarms=[{"alarm": "x", "status": "yellow"}]), LIMITS)

    assert checks.VCENTER_ALARM not in verdict.flags


def test_age_is_measured_by_vcenters_clock_and_unknown_without_a_create_date() -> None:
    assert vm(created=NOW - timedelta(hours=6), read_at=NOW).age_hours == pytest.approx(6.0)
    assert vm(created=None, read_at=NOW).age_hours is None


@pytest.mark.parametrize(
    ("path", "terms", "inside"),
    [
        ("/DC0/vm/projects/env-1", ["projects"], True),
        ("/DC0/vm/projects/team-x/env-1", ["projects/"], True),
        ("/DC0/vm/projects/team-x/env-1", ["/projects/team-x/"], True),
        ("/DC0/vm/projects/team-y/env-1", ["projects/team-x"], False),
        ("/DC0/vm/environments/env-1", ["Environments"], True),
        ("/DC0/vm/my-projects-old/env-1", ["projects"], False),
        ("/DC0/vm/env-1", [], True),
        (None, ["projects"], False),
    ],
)
def test_under_matches_whole_segments(path: str | None, terms: list[str], inside: bool) -> None:
    assert ages.under_any(path, terms) is inside


def test_a_property_vcenter_rejects_is_dropped_not_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
        }
    )
    session = VCenterSession(settings.vcenters[0], settings)
    asked: list[list[str]] = []

    def once(_kind: object, paths: list[str], *, root: object, objects: object) -> list[dict]:
        asked.append(list(paths))
        if "runtime.paused" in paths:
            raise vmodl.query.InvalidProperty(name="runtime.paused")
        return [{"moref": "vm-1", "name": "x"}]

    monkeypatch.setattr(session, "_retrieve_once", once)

    rows = session.retrieve(object, ["name", "runtime.paused"])

    assert asked == [["name", "runtime.paused"], ["name"]]
    assert rows == [{"moref": "vm-1", "name": "x", "_missing": ["runtime.paused"]}]


# -- reboot time (a warm reboot does not move runtime.bootTime) --------------------------------


def test_a_power_on_days_ago_with_a_recent_reboot_event_is_booting_not_hung() -> None:
    machine = vm(
        moref="vm-7",
        power_on_time=NOW - timedelta(days=3),
        boot_time=NOW - timedelta(days=3),
        uptime_minutes=3 * 24 * 60,
        read_at=NOW,
        tools_running="guestToolsNotRunning",
        cpu_mhz=1500.0,
    )
    # Without the reboot event: looks stuck for days.
    assert checks.classify(machine, LIMITS).state in (checks.HUNG, checks.BUSY_NOT_UP, checks.BOOTED_NOT_UP)

    set_effective_boot(machine, NOW, reboots={"vm-7": NOW - timedelta(minutes=3)})

    assert machine.boot_source == "reboot_event"
    assert machine.uptime_minutes == pytest.approx(3.0)
    assert checks.classify(machine, LIMITS).state == checks.BOOTING


def test_a_reported_reboot_time_wins_over_an_older_event() -> None:
    machine = vm(moref="vm-7", power_on_time=NOW - timedelta(days=1), read_at=NOW)

    set_effective_boot(
        machine,
        NOW,
        reboots={"vm-7": NOW - timedelta(hours=2)},
        rebooted_at=NOW - timedelta(minutes=12),
    )

    assert machine.boot_source == "reported_reboot"
    assert machine.uptime_minutes == pytest.approx(12.0)


def test_uptime_from_power_on_with_tools_down_carries_a_caution() -> None:
    machine = vm(
        moref="vm-7",
        power_on_time=NOW - timedelta(hours=5),
        read_at=NOW,
        tools_running="guestToolsNotRunning",
    )

    set_effective_boot(machine, NOW, reboots={})

    assert machine.boot_source == "power_on"
    assert any("in-guest reboot" in note for note in machine.notes)


def test_latest_reboot_picks_the_most_recent_event_per_vm() -> None:
    def event(moref: str, when: datetime, kind: str) -> object:
        vm_arg = type("M", (), {"_moId": moref})()
        # The class name is what the code reads, so give each the real event type name.
        return type(kind, (), {"vm": type("A", (), {"vm": vm_arg})(), "createdTime": when})()

    events = [
        event("vm-1", NOW - timedelta(minutes=30), "VmResettingEvent"),
        event("vm-1", NOW - timedelta(minutes=5), "VmResettingEvent"),
        event("vm-2", NOW - timedelta(minutes=10), "VmGuestRebootEvent"),
        event("vm-3", NOW, "VmPoweredOnEvent"),  # not a reboot
    ]

    latest = checks.latest_reboot_by_vm(events)

    assert latest["vm-1"] == NOW - timedelta(minutes=5)
    assert latest["vm-2"] == NOW - timedelta(minutes=10)
    assert "vm-3" not in latest


# -- session re-login and concurrency ---------------------------------------------------------


def test_reconnect_is_a_no_op_when_another_caller_already_relogged(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
        }
    )
    session = VCenterSession(settings.vcenters[0], settings)
    logins = {"n": 0}

    def fake_login() -> None:
        logins["n"] += 1
        session._content = object()
        session.generation += 1

    monkeypatch.setattr(session, "_login", fake_login)

    session.connect()  # first login
    assert session.generation == 1
    seen = session.generation

    # Two callers both saw generation 1 and try to reconnect; only the first does.
    session.reconnect(seen)
    session.reconnect(seen)  # generation moved to 2, so this is a no-op

    assert logins["n"] == 2  # connect + one reconnect, not two reconnects
    assert session.generation == 2


def test_connect_logs_in_once_under_contention(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
        }
    )
    session = VCenterSession(settings.vcenters[0], settings)
    logins = {"n": 0}

    def fake_login() -> None:
        logins["n"] += 1
        session._content = object()
        session.generation += 1

    monkeypatch.setattr(session, "_login", fake_login)
    session.connect()
    session.connect()  # already connected

    assert logins["n"] == 1


# -- virtual hardware --------------------------------------------------------------------------


class _Connectable:
    def __init__(self, connected: bool, *, start: bool = True, status: str = "ok") -> None:
        self.connected = connected
        self.startConnected = start
        self.status = status


def _dev(
    cls_name: str, label: str, connectable: _Connectable | None = None, backing: object = None
) -> object:
    device = getattr(vim.vm.device, cls_name)()
    device.deviceInfo = vim.Description(label=label, summary="")
    if connectable is not None:
        device.connectable = vim.vm.device.VirtualDevice.ConnectInfo(
            connected=connectable.connected,
            startConnected=connectable.startConnected,
            status=connectable.status,
        )
    if backing is not None:
        device.backing = backing
    return device


def test_hardware_classifies_devices_and_flags_a_down_boot_nic() -> None:
    iso = vim.vm.device.VirtualCdrom.IsoBackingInfo(fileName="[ds] images/win.iso")
    devices = [
        _dev("ParaVirtualSCSIController", "pvscsi-0"),
        _dev("VirtualE1000", "ethernet-0", _Connectable(connected=False, start=True)),
        _dev("VirtualCdrom", "cdrom-0", _Connectable(connected=True), backing=iso),
        _dev("VirtualHdAudioCard", "sound-0"),
    ]

    described, findings, blocking = describe_devices(devices, powered_on=True)

    categories = {entry["label"]: entry["category"] for entry in described}
    assert categories == {
        "pvscsi-0": "controller",
        "ethernet-0": "ethernet",
        "cdrom-0": "cdrom",
        "sound-0": "sound",
    }
    assert any("ethernet-0" in finding and "not connected" in finding for finding in blocking)
    assert any("ISO" in finding for finding in findings)
    assert not any("ISO" in finding for finding in blocking)  # a mounted ISO is a note, not blocking


def test_hardware_ignores_connection_state_when_powered_off() -> None:
    devices = [_dev("VirtualE1000", "ethernet-0", _Connectable(connected=False, start=True))]

    _, findings, blocking = describe_devices(devices, powered_on=False)

    assert findings == []
    assert blocking == []


# -- snapshots -------------------------------------------------------------------------------


class _Tree:
    def __init__(self, name: str, created: datetime, moref: str, children: list | None = None) -> None:
        self.name = name
        self.createTime = created
        self.snapshot = type("S", (), {"_moId": moref})()
        self.childSnapshotList = children or []
        self.quiesced = False
        self.state = "poweredOn"


class _Info:
    def __init__(self, roots: list) -> None:
        self.rootSnapshotList = roots


class _File:
    def __init__(self, key: int, ftype: str, size: int) -> None:
        self.key = key
        self.type = ftype
        self.size = size


class _Unit:
    def __init__(self, *file_keys: int) -> None:
        self.fileKey = list(file_keys)


class _Disk:
    def __init__(self, key: int, chain: list) -> None:
        self.key = key
        self.chain = chain


class _LayoutEx:
    def __init__(self, files: list, disks: list) -> None:
        self.file = files
        self.disk = disks


def test_snapshot_usage_sums_delta_and_memory_state() -> None:
    gb = 1024**3
    layoutex = _LayoutEx(
        files=[
            _File(1, "config", 1000),
            _File(2, "diskExtent", 40 * gb),  # base disk — not counted
            _File(3, "diskExtent", 30 * gb),  # snapshot delta — counted
            _File(4, "diskExtent", 20 * gb),  # a second snapshot delta — counted
            _File(5, "snapshotData", 1 * gb),  # .vmsn state — counted
            _File(6, "snapshotMemory", 7 * gb),  # .vmem memory — counted
        ],
        disks=[_Disk(200, [_Unit(2), _Unit(3), _Unit(4)])],  # base + two deltas: chain depth 2
    )
    info = _Info(
        [
            _Tree(
                "snap1",
                NOW - timedelta(days=5),
                "snapshot-1",
                [_Tree("snap2", NOW - timedelta(hours=2), "snapshot-2")],
            )
        ]
    )

    usage = snapshot_usage(info, layoutex, NOW)

    assert usage["count"] == 2
    assert usage["max_chain_depth"] == 2
    assert usage["delta_bytes"] == 50 * gb  # 30 + 20, base excluded
    assert usage["state_bytes"] == 8 * gb
    assert usage["total_bytes"] == 58 * gb
    assert usage["oldest_name"] == "snap1"
    assert usage["oldest_age_hours"] == pytest.approx(5 * 24, abs=0.1)
    assert usage["has_memory_snapshot"] is True


def test_snapshot_usage_is_none_without_snapshots() -> None:
    assert snapshot_usage(None, None, NOW) is None
    assert snapshot_usage(_Info([]), None, NOW) is None


# -- host time health (NTP and clock skew) -------------------------------------------------


def _host_time(**fields: object) -> dict:
    base: dict[str, object] = {
        "vcenter": "vc-a",
        "moref": "host-1",
        "name": "esx-1",
        "connection_state": "connected",
        "ntp_servers": ["10.0.0.1"],
        "service_key": "ntpd",
        "service_running": True,
        "service_policy": "automatic",
        "skew_seconds": 1.0,
        "skew_error": None,
    }
    base.update(fields)
    return base


def test_a_well_configured_host_with_a_tight_clock_is_healthy() -> None:
    verdict = timecheck.classify_host_time(_host_time(), LIMITS)

    assert verdict["healthy"] is True
    assert verdict["findings"] == []


def test_a_host_without_ntp_or_with_its_service_down_is_flagged() -> None:
    no_ntp = timecheck.classify_host_time(_host_time(ntp_servers=[]), LIMITS)
    stopped = timecheck.classify_host_time(_host_time(service_running=False, service_policy="off"), LIMITS)

    assert no_ntp["healthy"] is False
    assert any("no NTP servers" in finding for finding in no_ntp["findings"])
    assert stopped["healthy"] is False
    assert any("not running" in finding for finding in stopped["findings"])
    assert any("policy is 'off'" in finding for finding in stopped["findings"])


def test_a_clock_past_the_skew_threshold_is_flagged_and_auth_breakage_noted() -> None:
    small = timecheck.classify_host_time(_host_time(skew_seconds=10.0), LIMITS)
    big = timecheck.classify_host_time(_host_time(skew_seconds=-412.0), LIMITS)

    assert small["healthy"] is True  # under the 60 s threshold
    assert big["healthy"] is False
    assert any("Kerberos/AD" in finding for finding in big["findings"])
    assert big["skew_seconds"] == -412.0


def test_a_disconnected_host_is_not_judged() -> None:
    verdict = timecheck.classify_host_time(_host_time(connection_state="notResponding"), LIMITS)

    assert verdict["checked"] is False
    assert verdict["healthy"] is None


# -- CPU and memory limits -----------------------------------------------------------------


def test_a_cpu_limit_flags_the_vm_without_making_it_abnormal_on_its_own() -> None:
    healthy = checks.classify(
        vm(tools_running="guestToolsRunning", heartbeat="green", cpu_mhz=200.0, cpu_limit_mhz=500),
        LIMITS,
    )

    assert healthy.state == checks.HEALTHY
    assert checks.CPU_LIMITED in healthy.flags
    assert not healthy.abnormal  # a detail flag, not an attention flag
    assert healthy.values["cpu_limit_mhz"] == 500


def test_a_memory_limit_below_configured_ram_flags_memory_limited() -> None:
    capped = checks.classify(vm(memory_mb=8192, memory_limit_mb=2048), LIMITS)
    uncapped = checks.classify(vm(memory_mb=8192, memory_limit_mb=8192), LIMITS)

    assert checks.MEMORY_LIMITED in capped.flags
    assert checks.MEMORY_LIMITED not in uncapped.flags  # a limit at or above RAM caps nothing


def test_a_vm_that_is_up_but_capped_names_its_limits_and_says_it_is_up() -> None:
    def capped(cpu_mhz: float) -> VmFacts:
        return vm(
            tools_running="guestToolsRunning",
            heartbeat="green",
            cpu_mhz=cpu_mhz,
            cpu_limit_mhz=600,
            memory_mb=8192,
            memory_limit_mb=2048,
        )

    at_limit = _conclude_on(capped(590.0))
    under_limit = _conclude_on(capped(200.0))

    causes = [cause["cause"] for cause in at_limit["causes"]]
    assert causes[:2] == [diagnose.CPU_LIMIT_CAUSE, diagnose.MEMORY_LIMIT_CAUSE]
    assert "at the limit" in at_limit["causes"][0]["for"][0]
    assert "VM up (Tools running)" in at_limit["headline"]
    limit = next(cause for cause in under_limit["causes"] if cause["cause"] == diagnose.CPU_LIMIT_CAUSE)
    assert "not holding it back" in limit["for"][0]
    assert limit["score"] < at_limit["causes"][0]["score"]


def test_a_cpu_limit_on_a_stuck_vm_is_weighed_as_throttled_not_host_starvation() -> None:
    machine = vm(cpu_mhz=3600.0, cpu_limit_mhz=600)
    result = diagnose.conclude(
        checks.classify(machine, LIMITS),
        vm=machine,
        cpu={"findings": [], "starved": False},
        disk={"findings": [], "slow": False, "datastores": []},
        environment={"signals": []},
        logs={"available": False},
        serial={"available": False},
        console={"available": False},
        host_log={"available": False},
    )

    assert any(cause["cause"] == diagnose.CPU_LIMIT_CAUSE for cause in result["causes"])


# -- datastore health (fill, over-provisioning, APD/PDL) -----------------------------------


def _store(**fields: object) -> dict:
    gb = 1024**3
    base: dict[str, object] = {
        "vcenter": "vc-a",
        "moref": "datastore-1",
        "name": "LocalDS_0",
        "type": "VMFS",
        "capacity_bytes": 1000 * gb,
        "free_bytes": 500 * gb,
        "uncommitted_bytes": 0,
        "accessible": True,
        "mounts": [
            {"host_moref": "host-1", "mounted": True, "accessible": True, "inaccessible_reason": None}
        ],
    }
    base.update(fields)
    return base


def test_a_half_empty_datastore_is_healthy() -> None:
    verdict = storagehealth.classify_datastore(_store(), LIMITS)

    assert verdict["healthy"] is True
    assert verdict["free_percent"] == 50.0


def test_a_nearly_full_datastore_is_flagged() -> None:
    gb = 1024**3
    verdict = storagehealth.classify_datastore(_store(free_bytes=20 * gb), LIMITS)

    assert verdict["healthy"] is False
    assert verdict["free_percent"] == 2.0
    assert any("nearly full" in finding for finding in verdict["findings"])


def test_thin_disks_past_capacity_are_over_provisioned() -> None:
    gb = 1024**3
    # committed 500 GB + 2000 GB uncommitted = 2500 GB provisioned on a 1000 GB store (2.5x).
    verdict = storagehealth.classify_datastore(_store(uncommitted_bytes=2000 * gb), LIMITS)

    assert verdict["overprovision_ratio"] == 2.5
    assert any("over-provisioned" in finding for finding in verdict["findings"])


def test_a_mounted_but_unreachable_host_is_apd_pdl() -> None:
    verdict = storagehealth.classify_datastore(
        _store(
            mounts=[
                {
                    "host_moref": "host-9",
                    "mounted": True,
                    "accessible": False,
                    "inaccessible_reason": "AllPathsDown_Timeout",
                }
            ]
        ),
        LIMITS,
    )

    assert verdict["healthy"] is False
    assert verdict["hosts_unreachable"] == [{"host_moref": "host-9", "reason": "AllPathsDown_Timeout"}]
    assert any("all-paths-down" in finding for finding in verdict["findings"])


# -- template (base-disk) rollups ----------------------------------------------------------


def test_snapshots_roll_up_by_template_base_disk() -> None:
    gb = 1024**3
    rows = [
        {
            "vcenter": "vc-a",
            "base_disk": "[DS] Cool/Cool.vmdk",
            "name": "vm-b",
            "total_bytes": 30 * gb,
            "oldest_age_hours": 40.0,
        },
        {
            "vcenter": "vc-a",
            "base_disk": "[DS] Cool/Cool.vmdk",
            "name": "vm-a",
            "total_bytes": 50 * gb,
            "oldest_age_hours": 10.0,
        },
        {
            "vcenter": "vc-a",
            "base_disk": "[DS] Other/Other.vmdk",
            "name": "vm-c",
            "total_bytes": 5 * gb,
            "oldest_age_hours": 1.0,
        },
        {
            "vcenter": "vc-a",
            "base_disk": None,
            "name": "full-clone",
            "total_bytes": 90 * gb,
            "oldest_age_hours": 2.0,
        },
    ]

    rolled = snapshots._by_template(rows)

    assert [entry["base_disk"] for entry in rolled] == ["[DS] Cool/Cool.vmdk", "[DS] Other/Other.vmdk"]
    cool = rolled[0]
    assert cool["clones"] == 2
    assert cool["total_gb"] == 80.0  # 50 + 30
    assert cool["oldest_age_hours"] == 40.0  # the worst across the clones
    assert cool["names"] == ["vm-a", "vm-b"]  # differently-named clones, named together
    # a full clone / template with no parent base disk is not grouped under a template
    assert all(entry["base_disk"] for entry in rolled)


def test_resource_limits_roll_up_by_template_base_disk() -> None:
    rows = [
        {
            "vcenter": "vc-a",
            "base_disk": "[DS] Cool/Cool.vmdk",
            "name": "a",
            "cpu_limit_mhz": 600,
            "memory_limit_mb": None,
            "memory_mb": 4096,
        },
        {
            "vcenter": "vc-a",
            "base_disk": "[DS] Cool/Cool.vmdk",
            "name": "b",
            "cpu_limit_mhz": 600,
            "memory_limit_mb": 2048,
            "memory_mb": 4096,
        },
        {
            "vcenter": "vc-b",
            "base_disk": "[DS] Cool/Cool.vmdk",
            "name": "c",
            "cpu_limit_mhz": 600,
            "memory_limit_mb": None,
            "memory_mb": 4096,
        },
        {
            "vcenter": "vc-a",
            "base_disk": None,
            "name": "loner",
            "cpu_limit_mhz": 400,
            "memory_limit_mb": None,
            "memory_mb": 4096,
        },
    ]

    rolled = resources._by_template(rows)

    assert rolled[0]["base_disk"] == "[DS] Cool/Cool.vmdk"
    assert rolled[0]["clones"] == 2
    assert rolled[0]["cpu_limited"] == 2
    assert rolled[0]["memory_limited"] == 1
    # The same path on another vCenter is another template.
    assert [(entry["vcenter"], entry["clones"]) for entry in rolled] == [("vc-a", 2), ("vc-b", 1)]


# -- guest run-command: command shaping (the one non-read-only tool) -----------------------


def test_the_windows_shell_wraps_the_command_and_captures_output() -> None:
    program, arguments = guestexec.guest_program_spec("ipconfig /all", r"C:\Temp\o.txt", windows=True)

    assert program.endswith("cmd.exe")
    assert arguments == r'/c (ipconfig /all) > "C:\Temp\o.txt" 2>&1'


def test_the_linux_shell_wraps_the_command_and_captures_output() -> None:
    program, arguments = guestexec.guest_program_spec("systemctl status", "/tmp/o.txt", windows=False)  # noqa: S108

    assert program == "/bin/sh"
    assert arguments.startswith("-c \"exec > '/tmp/o.txt' 2>&1; command -v base64")
    assert "systemctl" not in arguments


def test_a_linux_command_survives_the_shell_tools_starts_it_through(tmp_path: pathlib.Path) -> None:
    import shutil  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    if shutil.which("sh") is None or shutil.which("base64") is None:
        pytest.skip("needs sh and base64")
    out = tmp_path / "o.txt"
    command = "echo 'a b c' | awk '{print $2}'; echo \"`echo tick`\" \\done"
    program, arguments = guestexec.guest_program_spec(command, str(out), windows=False)

    # open-vm-tools runs `"<program>" <arguments>` through /bin/sh -c.
    subprocess.run(["/bin/sh", "-c", f'"{program}" {arguments}'], check=True)

    assert out.read_text().splitlines() == ["b", "tick done"]


@pytest.mark.parametrize("shell", ["sh", "bash"])
def test_a_linux_command_that_reads_stdin_does_not_swallow_the_rest(
    tmp_path: pathlib.Path, shell: str
) -> None:
    import shutil  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    if shutil.which(shell) is None or shutil.which("base64") is None:
        pytest.skip(f"needs {shell} and base64")
    out = tmp_path / "o.txt"
    program, arguments = guestexec.guest_program_spec(
        "read x; echo got=$x\necho second", str(out), windows=False
    )

    done = subprocess.run([shell, "-c", f'"{program}" {arguments}'], check=False)

    assert out.read_text().splitlines() == ["got=", "second"]
    assert done.returncode == 0


def test_the_guest_temp_path_is_os_specific() -> None:
    assert guestexec.guest_temp_path("abc", windows=True).startswith(r"C:\Windows\Temp")
    assert guestexec.guest_temp_path("abc", windows=False) == "/tmp/vsphere-triage-abc.txt"  # noqa: S108


def test_a_star_host_in_the_transfer_url_is_resolved_to_the_vcenter() -> None:
    resolved = guestexec.rewrite_transfer_url("https://*:443/guestFile?id=5&token=x", "esx-7.lab")
    unchanged = guestexec.rewrite_transfer_url("https://host-9.lab/guestFile?id=5", "esx-7.lab")

    assert resolved == "https://esx-7.lab:443/guestFile?id=5&token=x"
    assert unchanged == "https://host-9.lab/guestFile?id=5"


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("echo one; echo two", "one\ntwo\n"),
        ("false || echo fallback", "fallback\n"),
        ("echo out; echo err >&2", "out\nerr\n"),
    ],
)
def test_the_linux_wrapping_captures_every_part_of_a_compound_command(
    command: str, expected: str, tmp_path: object
) -> None:
    import shlex  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    out = f"{tmp_path}/o.txt"
    program, arguments = guestexec.guest_program_spec(command, out, windows=False)
    # As open-vm-tools starts it: the program line through /bin/sh -c.
    leaked = subprocess.run(
        ["/bin/sh", "-c", f"{shlex.quote(program)} {arguments}"], capture_output=True, text=True, check=False
    )

    assert leaked.stdout == ""
    with open(out, encoding="utf-8") as handle:  # noqa: PTH123
        assert handle.read() == expected


def _pool_with_fake_session(monkeypatch: pytest.MonkeyPatch) -> tuple[object, VCenterSession]:
    from vsphere_triage.vcenter import VCenterPool  # noqa: PLC0415

    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
        }
    )
    pool = VCenterPool(settings)
    session = pool.session("vc-a")

    def fake_login() -> None:
        session._content = object()
        session.generation += 1

    monkeypatch.setattr(session, "_login", fake_login)
    return pool, session


def test_work_that_must_not_repeat_is_not_rerun_after_a_session_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vsphere_triage.vcenter import VSphereError  # noqa: PLC0415

    pool, session = _pool_with_fake_session(monkeypatch)
    runs = {"n": 0}

    def work(_session: VCenterSession) -> str:
        runs["n"] += 1
        raise vim.fault.NotAuthenticated

    with pytest.raises(VSphereError, match="may or may not have run"):
        asyncio.run(pool.run("vc-a", work, retry=False))  # ty: ignore[unresolved-attribute]

    assert runs["n"] == 1
    assert session.generation == 2  # re-opened for the next call


def test_reads_are_still_retried_once_after_a_session_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    pool, _session = _pool_with_fake_session(monkeypatch)
    runs = {"n": 0}

    def work(_session: VCenterSession) -> str:
        runs["n"] += 1
        if runs["n"] == 1:
            raise vim.fault.NotAuthenticated
        return "read"

    assert asyncio.run(pool.run("vc-a", work)) == "read"  # ty: ignore[unresolved-attribute]
    assert runs["n"] == 2


def test_guest_exec_can_be_left_out_of_the_server() -> None:
    from vsphere_triage.server import build_server  # noqa: PLC0415

    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
        }
    )
    every = asyncio.run(build_server(settings).list_tools())
    kept = asyncio.run(build_server(settings, guest_exec=False).list_tools())
    acting = {tool.name for tool in every if tool.annotations and tool.annotations.read_only_hint is False}

    assert "run_in_guest" in acting
    assert "hard_reset" in acting
    # Exactly the tools that act on a VM are left out; every read-only tool stays.
    assert {tool.name for tool in every} - {tool.name for tool in kept} == acting
    assert all(tool.annotations is None or tool.annotations.read_only_hint is not False for tool in kept)


# -- conclusions that used to point the wrong way ----------------------------------------------


def _conclude_on(machine: VmFacts, **parts: dict) -> dict:
    defaults: dict[str, dict] = {
        "cpu": {"findings": [], "starved": False},
        "disk": {"findings": [], "slow": False, "datastores": []},
        "environment": {"signals": []},
        "logs": {"available": False},
        "serial": {"available": False},
        "console": {"available": False},
        "host_log": {"available": False},
    }
    defaults.update(parts)
    return diagnose.conclude(checks.classify(machine, LIMITS), vm=machine, **defaults)


def test_a_hung_vm_frozen_on_starting_windows_is_not_still_working() -> None:
    hung = vm(cpu_mhz=10.0, uptime_minutes=40.0)
    console_read = {
        "available": True,
        "frozen": True,
        "black": False,
        "screen_states": [{"state": "windows_starting", "meaning": "Starting Windows"}],
        "stop_codes": [],
    }

    result = _conclude_on(hung, console=console_read)

    assert checks.classify(hung, LIMITS).state == checks.HUNG
    assert result["causes"][0]["cause"] == diagnose.EARLY_HANG
    still = [entry for entry in result["causes"] if entry["cause"] == diagnose.STILL_WORKING]
    assert not still  # argued down to zero or below


def test_an_unknown_host_capacity_is_not_evidence_against_cpu() -> None:
    host = contention.host_cpu_from_series(
        _host(core_mhz=None), {"cpu.demand.average": _series("cpu.demand.average", 99999)}, LIMITS
    )

    assert host["overcommitted"] is None
    result = conclude(cpu={"findings": [], "starved": False, "host": host})
    ranked = [*result["causes"], *result["argued_against"]]
    cpu = [entry for entry in ranked if entry["cause"] == diagnose.CPU]
    assert not cpu or not any("None%" in text for text in cpu[0]["against"])


def test_a_full_datastore_is_its_own_cause_not_latency() -> None:
    disk = {
        "findings": ["datastore ds-1 is nearly full (2.0% free)"],
        "capacity_findings": ["datastore ds-1 is nearly full (2.0% free)"],
        "slow": False,
        "datastores": [],
    }

    result = conclude(disk=disk)

    names = [entry["cause"] for entry in result["causes"]]
    assert diagnose.DATASTORE_CAPACITY in names
    assert diagnose.STORAGE not in names


def test_counters_read_but_empty_for_the_window_are_a_gap() -> None:
    result = conclude(
        cpu={"findings": [], "starved": False, "window_read": False},
        disk={"findings": [], "slow": False, "datastores": [], "window_read": False},
    )

    gaps = " ".join(result["not_checked"])
    assert "CPU counters (no samples" in gaps
    assert "storage counters (no samples" in gaps


def test_an_earlier_boots_kernel_panic_is_not_this_boots() -> None:
    text = (
        "[    0.000000] Linux version 5.14.0 (old boot)\n"
        "Kernel panic - not syncing: VFS: Unable to mount root fs\n"
        "[    0.000000] Linux version 5.14.0 (this boot)\n"
        "host login:\n"
    )

    result = vmlog.read_serial(text, tail_lines=5)

    assert result["linux_findings"] == []
    assert result["linux_findings_scoped_to_current_boot"] is True
    assert [finding["kind"] for finding in result["linux_findings_earlier_boots"]] == ["kernel_panic"]


def test_the_esxi_tools_running_status_lines_are_read() -> None:
    up = "2026-10-29T02:00:00.000Z In(05) vcpu-0 - Tools: Changing running status: 0 => 1."
    down = "2026-10-29T02:05:00.000Z In(05) vcpu-0 - Tools: Changing running status: 1 => 0."
    lines = vmlog.parse_lines(
        "2026-10-29T01:59:00.000Z In(05) vmx - Powering on the VM\n" + up + "\n" + down + "\n"
    )

    timeline = vmlog.boot_timeline(lines)

    assert timeline["last_stage"] == "tools"
    assert timeline["annotations"]["tools_state"]["count"] == 1


class _WindowPool:
    def __init__(self, result: dict) -> None:
        self.result = result

    async def run(self, _name: str, _work: object) -> dict:
        return self.result

    async def sweep(self, _name: str, _work: object) -> dict:
        return self.result


def test_a_window_with_resets_never_opens_with_nothing_found() -> None:
    quiet_but_reset = {
        "events_read": 50,
        "events_capped": False,
        "events_by_type": {"VmResettingEvent": 50},
        "events_by_host": {"esx-1": 50},
        "vms_with_most_events": {},
        "hosts_over_cpu_threshold": [],
        "cpu_counters_unavailable": [],
        "cpu_window_read": True,
        "storage_window_read": True,
        "storage": {"findings": []},
    }

    pool = _WindowPool(quiet_but_reset)
    begin = NOW - timedelta(hours=1)
    result = asyncio.run(scan.diagnose_window(pool, Settings(), ["vc-a"], begin, NOW))  # type: ignore[arg-type]

    assert not result["findings"][0].startswith("no resets")
    assert "50 resets" in result["findings"][0]


# -- fleet reports ------------------------------------------------------------------------------


def test_a_device_kind_is_the_short_name_not_pyvmomis_class_path() -> None:
    from vsphere_triage.inventory import device_kind  # noqa: PLC0415

    assert device_kind(vim.vm.device.VirtualVmxnet3()) == "Vmxnet3"
    assert device_kind(vim.vm.device.VirtualHdAudioCard()) == "HdAudioCard"


class _ProfilePool:
    def __init__(self, rows: list[dict]) -> None:
        self.rows = rows

    async def run(self, _name: str, _work: object) -> list[dict]:
        return self.rows

    async def sweep(self, _name: str, _work: object) -> list[dict]:
        return self.rows


def _device_row(moref: str, nics: int, folder_moref: str = "group-1", environment: str = "env-1") -> dict:
    kinds = ["Vmxnet3"] * nics
    return {
        "vcenter": "vc-a",
        "moref": moref,
        "name": moref,
        "template": False,
        "folder": f"/DC0/vm/{environment}",
        "folder_moref": folder_moref,
        "environment": environment,
        "categories": ["ethernet"],
        "kinds": sorted(set(kinds)),
        "by_category": {"ethernet": kinds},
    }


def test_an_extra_nic_of_the_same_kind_is_an_outlier() -> None:
    from vsphere_triage import hardware  # noqa: PLC0415

    rows = [_device_row("vm-1", 1), _device_row("vm-2", 1), _device_row("vm-3", 2)]
    result = asyncio.run(
        hardware.hardware_profile(
            _ProfilePool(rows),  # type: ignore[arg-type]
            Settings(),
            ["vc-a"],
            under=[],
            include_templates=False,
            limit=10,
        )
    )

    assert [(row["moref"], row["extra"]) for row in result["environment_outliers"]] == [("vm-3", ["Vmxnet3"])]


def test_two_environments_of_the_same_name_are_not_one_norm() -> None:
    from vsphere_triage import hardware  # noqa: PLC0415

    rows = [
        _device_row("vm-1", 1, "group-1"),
        _device_row("vm-2", 1, "group-1"),
        _device_row("vm-3", 2, "group-2"),
        _device_row("vm-4", 2, "group-2"),
    ]
    result = asyncio.run(
        hardware.hardware_profile(
            _ProfilePool(rows),  # type: ignore[arg-type]
            Settings(),
            ["vc-a"],
            under=[],
            include_templates=False,
            limit=10,
        )
    )

    assert result["environment_outliers"] == []


class _SnapLayout:
    def __init__(self, disks: list) -> None:
        self.disk = disks


def test_a_linked_clones_own_delta_is_not_counted_as_a_snapshot() -> None:
    gb = 1024**3
    layoutex = _LayoutEx(
        files=[
            _File(1, "diskExtent", 40 * gb),  # the template's base disk
            _File(2, "diskExtent", 10 * gb),  # the clone's own delta, from before any snapshot
            _File(3, "diskExtent", 3 * gb),  # the one snapshot's delta
        ],
        disks=[_Disk(200, [_Unit(1), _Unit(2), _Unit(3)])],
    )
    layoutex.snapshot = [_SnapLayout([_Disk(200, [_Unit(1), _Unit(2)])])]  # ty: ignore[unresolved-attribute]
    info = _Info([_Tree("snap1", NOW - timedelta(hours=2), "snapshot-1")])

    usage = snapshot_usage(info, layoutex, NOW)

    assert usage["max_chain_depth"] == 1
    assert usage["delta_bytes"] == 3 * gb


def test_a_cpu_limit_above_the_vms_full_speed_caps_nothing() -> None:
    # 2 vCPUs x 2000 MHz = 4000 MHz full speed; the default warns at or under 90%.
    loose = checks.classify(vm(cpu_limit_mhz=100_000), LIMITS)
    tight = checks.classify(vm(cpu_limit_mhz=1000), LIMITS)
    unknown_speed = checks.classify(vm(cpu_limit_mhz=100_000, host_core_mhz=None), LIMITS)

    assert checks.CPU_LIMITED not in loose.flags
    assert checks.CPU_LIMITED in tight.flags
    assert checks.CPU_LIMITED in unknown_speed.flags


def _policy_row(name: str, **fields: object) -> dict:
    base: dict[str, object] = {
        "vcenter": "vc-a",
        "moref": name,
        "name": name,
        "folder": "/DC0/vm/env",
        "base_disk": None,
        "template": False,
        "num_cpu": 2,
        "memory_mb": 4096,
        "cpu_limit_mhz": None,
        "cpu_reservation_mhz": None,
        "memory_limit_mb": None,
        "memory_reservation_mb": None,
    }
    return base | fields


def test_the_tightest_limit_leads_and_a_memory_limit_at_ram_is_not_a_limit() -> None:
    rows = [
        _policy_row("loose-cpu", cpu_limit_mhz=50_000),
        _policy_row("tight-cpu", cpu_limit_mhz=100),
        _policy_row("tight-mem", memory_limit_mb=512),
        _policy_row("mem-at-ram", memory_limit_mb=4096),
    ]
    result = asyncio.run(
        resources.find_resource_limits(
            _ProfilePool(rows),  # type: ignore[arg-type]
            Settings(),
            ["vc-a"],
            kind="limits",
            include_templates=False,
            under=[],
            limit=10,
        )
    )

    assert [row["name"] for row in result["vms"]] == ["tight-cpu", "loose-cpu", "tight-mem"]


def test_a_memory_limit_with_unknown_ram_does_not_say_none_mb() -> None:
    reasons = resources._findings_for(_policy_row("x", memory_limit_mb=512, memory_mb=None))

    assert reasons == ["memory limit 512 MB set (RAM not read) — forces balloon/swap"]


class _ClockSession:
    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.vcenter_clock = NOW

    def now(self) -> datetime:
        return self.vcenter_clock

    def host_datetime(self, _moref: str) -> datetime:
        import time  # noqa: PLC0415

        time.sleep(self.delay)
        return NOW + timedelta(seconds=time.monotonic() - self.started)


def test_host_clock_skew_does_not_grow_with_the_number_of_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    import time  # noqa: PLC0415

    rows = [
        {"moref": f"host-{n}", "connection_state": "connected", "datetime_system_moref": f"dts-{n}"}
        for n in range(20)
    ]
    monkeypatch.setattr(timecheck, "read_host_time", lambda _session: rows)
    session = _ClockSession(delay=0.02)
    session.started = time.monotonic()  # ty: ignore[unresolved-attribute]

    measured = timecheck._scan_host_time(session, measure_skew=True)  # type: ignore[arg-type]

    # 20 hosts x 20 ms would be 0.4 s of false skew by the last host.
    assert max(abs(row["skew_seconds"]) for row in measured) < 0.1


def test_the_last_resort_cut_still_fits_the_budget() -> None:
    # A dict of many short keys is not cut by list cutting, so this reaches the last resort.
    huge = {"findings": ["x" * 1000] * 10_000, "by_key": {f"k{n}": "y" * 100 for n in range(5000)}}

    result = formatting.bounded(huge)

    assert formatting.size(result) <= formatting.MAX_RESPONSE_CHARACTERS


# -- the pool under stalls, and the smaller reads ---------------------------------------------


def test_a_read_past_its_deadline_keeps_the_vcenters_slot_until_its_thread_ends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading  # noqa: PLC0415

    from vsphere_triage.vcenter import VSphereError  # noqa: PLC0415

    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
            "VSPHERE_MAX_CONCURRENT_PER_VCENTER": "1",
        }
    )
    from vsphere_triage.vcenter import VCenterPool  # noqa: PLC0415

    pool = VCenterPool(settings)
    session = pool.session("vc-a")
    monkeypatch.setattr(session, "connect", lambda: None)
    stalled = threading.Event()

    async def scenario() -> tuple[bool, bool]:
        with pytest.raises(VSphereError, match="deadline"):
            await pool.run("vc-a", lambda _s: stalled.wait(5), timeout_seconds=0.05)
        held_while_stalled = pool._limits["vc-a"].locked()
        stalled.set()
        await asyncio.sleep(0.1)
        return held_while_stalled, pool._limits["vc-a"].locked()

    held, still_held = asyncio.run(scenario())

    assert held is True  # the stuck thread still counts against the vCenter
    assert still_held is False  # and gives the slot back once it ends


def test_a_sweep_gets_the_longer_scan_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    from vsphere_triage.vcenter import VCenterPool  # noqa: PLC0415

    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
            "VSPHERE_TIMEOUT_SECONDS": "0.05",
            "VSPHERE_SCAN_TIMEOUT_SECONDS": "5",
        }
    )
    pool = VCenterPool(settings)
    monkeypatch.setattr(pool.session("vc-a"), "connect", lambda: None)

    def slow(_session: VCenterSession) -> str:
        import time  # noqa: PLC0415

        time.sleep(0.2)
        return "swept"

    assert asyncio.run(pool.sweep("vc-a", slow)) == "swept"


class _SessionEntry:
    def __init__(self, key: str, user: str = "svc") -> None:
        self.key = key
        self.userName = user


class _SessionManager:
    def __init__(self, sessions: list) -> None:
        self.sessionList = sessions
        self.currentSession = sessions[0] if sessions else _SessionEntry("own")


def test_only_the_servers_own_session_is_reported_as_a_restricted_view() -> None:
    session = VCenterSession(VCenter(name="vc-a", host="a"), Settings())
    own = _SessionEntry("own")
    session._content = type("Content", (), {"sessionManager": _SessionManager([own])})()

    counted = session.session_count()

    assert counted["visible"] == "own_only"
    assert "Sessions.TerminateSession" in counted["note"]


def test_an_ocr_failure_loses_the_text_not_the_console(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys  # noqa: PLC0415
    import types  # noqa: PLC0415

    broken = types.ModuleType("pytesseract")

    def fail(_image: object) -> str:
        msg = "tesseract crashed"
        raise RuntimeError(msg)

    broken.image_to_string = fail  # ty: ignore[unresolved-attribute]
    monkeypatch.setitem(sys.modules, "pytesseract", broken)
    monkeypatch.setattr(console.shutil, "which", lambda _name: "/usr/bin/tesseract")
    buffer = io.BytesIO()
    Image.new("RGB", (8, 8)).save(buffer, format="PNG")

    text, how = console.ocr(buffer.getvalue())

    assert text is None
    assert "OCR failed" in how


def test_vrops_alerts_are_read_across_pages() -> None:
    from vsphere_triage import vrops  # noqa: PLC0415

    since = datetime(2026, 10, 29, 0, 0, tzinfo=UTC)
    recent = int(since.timestamp() * 1000) + 60_000

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/auth/token/acquire"):
            return httpx.Response(200, json={"token": "t"})
        page = int(request.url.params["page"])
        size = int(request.url.params["pageSize"])
        if page == 0:
            batch = [{"alertDefinitionName": "old", "startTimeUTC": 1} for _ in range(size)]
        else:
            batch = [{"alertDefinitionName": "the new one", "startTimeUTC": recent}]
        return httpx.Response(200, json={"alerts": batch, "pageInfo": {"totalCount": size + 1}})

    settings = Settings.from_environment(
        {
            "VSPHERE_VROPS_URL": "https://vrops.example",
            "VSPHERE_VROPS_USERNAME": "reader",
            "VSPHERE_VROPS_PASSWORD": "secret",
        }
    )
    client = vrops.Vrops(settings, transport=httpx.MockTransport(respond))

    alerts = asyncio.run(client.alerts("host-1", since))

    assert [alert["name"] for alert in alerts] == ["the new one"]


def test_the_plugin_runs_the_same_version_the_package_is() -> None:
    import pathlib  # noqa: PLC0415
    import tomllib  # noqa: PLC0415

    root = pathlib.Path(__file__).resolve().parents[1]
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    plugin = json.loads((root / ".claude-plugin" / "plugin.json").read_text())

    # The skill ships in the plugin and the server from the index: pinned together,
    # so a plugin install never runs a server older or newer than its skill.
    assert plugin["version"] == version
    assert plugin["mcpServers"]["vsphere-triage"]["args"] == [f"vsphere-triage=={version}"]


def test_a_catastrophic_caller_pattern_is_refused_without_freezing_the_loop() -> None:
    lines = vmlog.parse_lines(
        "\n".join(f"2026-10-29T02:00:{n % 60:02d}.000Z In(05) vmx - " + "a" * 34 + "!" for n in range(50))
    )

    async def scenario() -> tuple[int, BaseException | None]:
        ticks = 0
        failure: BaseException | None = None

        async def ticker() -> None:
            nonlocal ticks
            while True:
                await asyncio.sleep(0.05)
                ticks += 1

        beat = asyncio.ensure_future(ticker())
        try:
            await asyncio.to_thread(vmlog.grep, lines, "(a|aa)+$", limit=10)
        except ValueError as error:
            failure = error
        beat.cancel()
        return ticks, failure

    ticks, failure = asyncio.run(scenario())

    assert isinstance(failure, ValueError)
    assert "simpler pattern" in str(failure)
    assert ticks >= 10  # the loop kept answering while the pattern ran out its budget


def test_a_healthy_environment_is_not_reported_as_having_a_lone_abnormal_vm() -> None:
    up = {"tools_running": "guestToolsRunning", "heartbeat": "green"}
    peers = [
        (vm(moref=f"vm-{n}", **up), checks.classify(vm(moref=f"vm-{n}", **up), LIMITS)) for n in range(3)
    ]

    result = diagnose.environment_pattern(peers[0][0], peers, about_vm=False)

    assert result["findings"] == []
    assert result["signals"] == []


def test_a_sibling_being_the_odd_one_out_is_not_said_of_the_diagnosed_vm() -> None:
    up = {"tools_running": "guestToolsRunning", "heartbeat": "green"}
    me = vm(moref="vm-1", **up)
    stuck = vm(moref="vm-2", name="db-01")
    peers = [(me, checks.classify(me, LIMITS)), (stuck, checks.classify(stuck, LIMITS))]

    result = diagnose.environment_pattern(me, peers)

    assert result["signals"] == []
    assert result["findings"] == ["db-01 (vm-2) is the only abnormal VM of 2 here"]


def test_a_vm_is_not_compared_with_its_own_devices() -> None:
    nic = "network adapter 'ethernet-0' is not connected (no link; PXE/DHCP would fail)"
    me = vm(moref="vm-1", uptime_minutes=2.0)  # booting, so on the healthy side
    me.device_blocks = [nic]
    peers = [(me, checks.classify(me, LIMITS))]

    assert diagnose.environment_pattern(me, peers)["healthy_device_blocks"] == []


# -- round two: answers that must not be mistaken for others ----------------------------------


class _ToolServer:
    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self, *, name: str, annotations: object) -> object:  # noqa: ARG002
        def register(function: object) -> object:
            self.tools[name] = function
            return function

        return register


def test_a_bug_is_reported_as_an_internal_error_not_as_not_found() -> None:
    from mcp.server.mcpserver.exceptions import ToolError  # noqa: PLC0415

    from vsphere_triage.config import NotFoundError  # noqa: PLC0415
    from vsphere_triage.server import _registrar  # noqa: PLC0415

    fake = _ToolServer()
    tool = _registrar(fake, Settings())  # type: ignore[arg-type]

    @tool("buggy")
    async def buggy() -> dict:
        return {}["missing"]

    @tool("absent")
    async def absent() -> dict:
        msg = "vm-9 not found"
        raise NotFoundError(msg)

    with pytest.raises(ToolError, match="internal error"):
        asyncio.run(fake.tools["buggy"]())  # type: ignore[operator]
    assert asyncio.run(fake.tools["absent"]()) == {"found": False, "reason": "vm-9 not found"}  # type: ignore[operator]


def test_a_window_must_start_before_it_ends_and_a_huge_look_back_is_capped() -> None:
    from vsphere_triage.server import MAX_LOOKBACK, _ago, _ordered  # noqa: PLC0415

    with pytest.raises(ValueError, match="at or after it ends"):
        _ordered(NOW, NOW - timedelta(hours=1))
    assert _ago(minutes=10**12) == MAX_LOOKBACK
    assert _ago(minutes=-5) == timedelta(minutes=1)


def test_a_datastore_whose_capacity_was_not_read_is_unjudged_not_healthy() -> None:
    verdict = storagehealth.classify_datastore(_store(capacity_bytes=None, free_bytes=None), LIMITS)

    assert verdict["healthy"] is None
    assert "capacity" in verdict["not_read"]


def test_a_full_clone_with_a_snapshot_has_no_linked_clone_base() -> None:
    from vsphere_triage.inventory import linked_bases  # noqa: PLC0415

    full_clone = [["[DS] web-01/web-01-000001.vmdk", "[DS] web-01/web-01.vmdk"]]
    linked = [["[DS] web-02/web-02.vmdk", "[DS] Cool/Cool.vmdk"]]

    assert linked_bases(full_clone) == []
    assert linked_bases(linked) == ["[DS] Cool/Cool.vmdk"]


def test_waiting_for_a_slot_held_by_a_stalled_read_has_a_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    import threading  # noqa: PLC0415

    from vsphere_triage.vcenter import VCenterPool, VSphereError  # noqa: PLC0415

    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
            "VSPHERE_MAX_CONCURRENT_PER_VCENTER": "1",
            "VSPHERE_TIMEOUT_SECONDS": "0.1",
        }
    )
    pool = VCenterPool(settings)
    monkeypatch.setattr(pool.session("vc-a"), "connect", lambda: None)
    stalled = threading.Event()

    async def scenario() -> None:
        with pytest.raises(VSphereError, match="deadline"):
            await pool.run("vc-a", lambda _s: stalled.wait(5))
        try:
            with pytest.raises(VSphereError, match="read slots are still busy"):
                await pool.run("vc-a", lambda _s: "never runs")
        finally:
            stalled.set()

    asyncio.run(scenario())


def test_a_guest_command_past_its_deadline_says_it_may_still_be_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading  # noqa: PLC0415

    from vsphere_triage.vcenter import VCenterPool, VSphereError  # noqa: PLC0415

    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
        }
    )
    pool = VCenterPool(settings)
    monkeypatch.setattr(pool.session("vc-a"), "connect", lambda: None)
    stalled = threading.Event()

    async def scenario() -> None:
        try:
            with pytest.raises(VSphereError, match="may still be under way"):
                await pool.run("vc-a", lambda _s: stalled.wait(5), retry=False, timeout_seconds=0.05)
        finally:
            stalled.set()

    asyncio.run(scenario())


def test_a_still_update_screen_is_still_read_as_working() -> None:
    busy = vm(cpu_mhz=3000.0, uptime_minutes=40.0)
    console_read = {
        "available": True,
        "frozen": True,
        "black": False,
        "screen_states": [{"state": "windows_updating", "meaning": "Working on updates"}],
        "stop_codes": [],
    }

    result = _conclude_on(busy, console=console_read)

    assert result["causes"][0]["cause"] == diagnose.STILL_WORKING
    assert diagnose.EARLY_HANG not in [entry["cause"] for entry in result["causes"]]


# -- round three ------------------------------------------------------------------------------


def test_an_old_panic_matching_several_kinds_is_weighed_once() -> None:
    serial = {
        "available": True,
        "files": [
            {
                "windows_stop_codes": [],
                "linux_findings": [],
                "linux_findings_earlier_boots": [
                    {"kind": kind, "points_at": None, "count": 1, "examples": ["x"]}
                    for kind in ("kernel_panic", "hung_task", "oops")
                ],
            }
        ],
    }

    result = conclude(serial=serial)

    kernel = next(entry for entry in result["causes"] if entry["cause"] == diagnose.KERNEL_ERROR)
    assert kernel["score"] == 1


def test_a_login_prompt_on_a_dark_screen_is_not_a_blank_hang() -> None:
    image = Image.new("RGB", (640, 480))
    for x in range(10, 120):  # a line of light text, "host login:"
        for y in range(10, 22):
            if (x + y) % 3:
                image.putpixel((x, y), (200, 200, 200))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    capture = buffer.getvalue()

    read = console.read_captures([capture, capture], black_fraction=0.98, frozen_difference=0.5)

    assert read["black"] is True
    assert read["text_on_black"] is True
    result = conclude(console={"available": True, "screen_states": [], "stop_codes": [], **read})
    assert diagnose.EARLY_HANG not in [entry["cause"] for entry in result["causes"]]


def test_a_truly_black_screen_still_has_no_text() -> None:
    buffer = io.BytesIO()
    Image.new("RGB", (640, 480)).save(buffer, format="PNG")

    read = console.read_captures([buffer.getvalue()] * 2, black_fraction=0.98, frozen_difference=0.5)

    assert read["black"] is True
    assert read["text_on_black"] is False


def test_an_absurd_look_back_is_capped_without_overflowing() -> None:
    from vsphere_triage.server import MAX_LOOKBACK, _ago  # noqa: PLC0415

    assert _ago(minutes=10**13) == MAX_LOOKBACK


def test_a_session_expiry_inside_a_diagnosis_piece_reaches_the_pool() -> None:
    def expire() -> dict:
        raise vim.fault.NotAuthenticated

    with pytest.raises(vim.fault.NotAuthenticated):
        diagnose.piece("events", expire)


# -- capabilities: naming the evidence we lack --------------------------------


def _settings(**env: str) -> Settings:
    base = {
        "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
        "VSPHERE_USERNAME": "u",
        "VSPHERE_PASSWORD": "p",
    }
    return Settings.from_environment(base | env)


def test_vrops_gap_is_named_only_when_vrops_is_not_configured() -> None:
    assert capabilities.vrops_gap(_settings()) is not None
    configured = _settings(
        VSPHERE_VROPS_URL="https://vrops", VSPHERE_VROPS_USERNAME="u", VSPHERE_VROPS_PASSWORD="p"
    )
    assert capabilities.vrops_gap(configured) is None


def test_serial_console_gap_is_tuned_by_guest_os() -> None:
    assert capabilities.serial_console_gap(vm(serial_files=["[ds] vm/vm.ser"])) is None
    windows = capabilities.serial_console_gap(vm(os_family="windows", serial_files=[]))
    assert windows is not None
    assert "EMS" in windows["how_to_enable"]
    linux = capabilities.serial_console_gap(vm(os_family="linux", serial_files=[]))
    assert "console=ttyS0" in linux["how_to_enable"]


def test_guest_gap_distinguishes_no_tools_from_no_credentials() -> None:
    no_creds = capabilities.guest_gap(_settings(), vm(tools_running="guestToolsRunning"))
    assert no_creds is not None
    assert "VSPHERE_GUEST_USERNAME" in no_creds["how_to_enable"]
    with_creds = _settings(VSPHERE_GUEST_USERNAME="a", VSPHERE_GUEST_PASSWORD="b")
    tools_down = capabilities.guest_gap(with_creds, vm(tools_running="guestToolsNotRunning"))
    assert tools_down is not None
    assert "Tools" in tools_down["how_to_enable"]
    assert capabilities.guest_gap(with_creds, vm(tools_running="guestToolsRunning")) is None
    assert capabilities.guest_gap(_settings(), vm(power_state="poweredOff")) is None


# -- EMS / BCD parsing --------------------------------------------------------


def test_bcd_output_reads_the_ems_flag_and_port() -> None:
    payload = json.dumps(
        {
            "current": "Windows Boot Loader\n  identifier  {current}\n  ems         Yes\n",
            "emssettings": "  emsport      1\n  emsbaudrate  115200\n",
        }
    )
    parsed = emscheck.parse_bcd_output(payload)
    assert parsed["ems_enabled"] is True
    assert parsed["emsport"] == "1"
    assert parsed["emsbaudrate"] == 115200


def test_bcd_output_access_denied_is_unconfirmed_not_off() -> None:
    parsed = emscheck.parse_bcd_output(json.dumps({"current": "ERROR: Access is denied.", "emssettings": ""}))
    assert parsed["ems_enabled"] is None
    assert parsed["access_denied"] is True


def test_ems_verdict_covers_each_outcome() -> None:
    seen = emscheck._verdict("windows", has_serial_to_file=True, ems_output_seen=True, bcd=None, gap=None)
    assert seen["available"] is True
    gap = capabilities.serial_console_gap(vm(os_family="windows", serial_files=[]))
    none_port = emscheck._verdict(
        "windows", has_serial_to_file=False, ems_output_seen=False, bcd=None, gap=gap
    )
    assert none_port["available"] is False
    assert none_port["state"] == "no_serial_port"
    ems_off = emscheck._verdict(
        "windows", has_serial_to_file=True, ems_output_seen=False, bcd={"ems_enabled": False}, gap=None
    )
    assert ems_off["available"] is False
    assert ems_off["state"] == "serial_port_but_ems_off"
    unconfirmed = emscheck._verdict(
        "windows", has_serial_to_file=True, ems_output_seen=False, bcd=None, gap=None
    )
    assert unconfirmed["available"] is None


# -- Windows boot picture -----------------------------------------------------


def test_windows_boot_picture_decodes_the_bugcheck_and_names_timeouts() -> None:
    parsed = {
        "last_boot": "2026-10-29T02:00:00Z",
        "bugchecks": [{"time": "2026-10-29T01:55:00Z", "message": "The bugcheck was: 0x0000007a (0x..)."}],
        "service_timeouts": [
            {"time": "t", "id": 7011, "provider": "Service Control Manager", "message": "timeout"}
        ],
        "dirty_shutdown": [{"time": "t", "id": 6008, "message": "unexpected"}],
        "boot_performance": [{"time": "t", "id": 101, "message": "app slow"}],
        "newest_minidump": {"name": "x.dmp", "time": "t"},
        "memory_dmp": True,
        "ntbtlog": False,
        "srttrail": None,
        "panther_present": False,
    }
    summary = winboot.summarize_windows_boot(parsed)
    codes = summary["bugchecks"][0]["stop_codes"]
    assert codes
    assert codes[0]["name"] == "KERNEL_DATA_INPAGE_ERROR"
    assert any("bugcheck" in line for line in summary["picture"])
    assert any("timeout" in line.lower() for line in summary["picture"])


def test_windows_boot_picture_is_calm_when_nothing_is_wrong() -> None:
    summary = winboot.summarize_windows_boot({"last_boot": "t"})
    assert len(summary["picture"]) == 1
    assert summary["picture"][0].startswith("no boot faults found in the event log")


# -- vCenter session history --------------------------------------------------


def test_session_history_flags_a_login_surge_from_one_source() -> None:
    rows = [
        {
            "type": "UserLoginSessionEvent",
            "time": NOW - timedelta(minutes=m),
            "user": "svc",
            "source": "10.0.0.9",
        }
        for m in range(0, 40, 2)
    ]
    rows.append({"type": "BadUsernameSessionEvent", "time": NOW, "user": "", "source": "10.0.0.9"})
    summary = connhistory.summarize_session_events(rows, now=NOW, window_minutes=180)
    assert summary["logins"] == 20
    assert summary["failed_logins"] == 1
    assert summary["top_sources"]["10.0.0.9"] == 20
    assert any("churning" in finding for finding in summary["findings"])


def test_session_history_says_so_when_there_is_nothing() -> None:
    summary = connhistory.summarize_session_events([], now=NOW, window_minutes=60)
    assert summary["total_events"] == 0
    assert any("no session events" in finding for finding in summary["findings"])


# -- cluster events: why a whole cluster moved -------------------------------


def test_cluster_events_names_an_ha_restart_wave() -> None:
    rows = [
        {
            "type": "VmRestartedByHaEvent",
            "time": NOW - timedelta(minutes=m),
            "message": "vSphere HA restarted this virtual machine",
            "host": "esx-31",
            "vm": f"vm-{m}",
        }
        for m in range(5)
    ]
    rows.append(
        {
            "type": "HostConnectionLostEvent",
            "time": NOW - timedelta(minutes=6),
            "message": "Host connection lost",
            "host": "esx-31",
            "vm": None,
        }
    )
    summary = clusterevents.summarize_cluster_events(rows, now=NOW, window_minutes=120)
    assert summary["buckets"]["ha_vm_restart"]["count"] == 5
    assert "esx-31" in summary["buckets"]["ha_vm_restart"]["hosts"]
    assert any("HA restarted" in finding for finding in summary["findings"])


def test_cluster_events_classify_falls_through_for_noise() -> None:
    assert clusterevents.classify_event("UserLoginSessionEvent", "logged in") is None
    assert clusterevents.classify_event("DrsVmMigratedEvent", "migrated")[0] == "drs_migration"


# -- task history: what was done ---------------------------------------------


def test_task_categories_and_wave_detection() -> None:
    assert taskhistory.categorize("VirtualMachine.relocate") == "migration"
    assert taskhistory.categorize("VirtualMachine.reconfigure") == "reconfigure"
    rows = [
        {
            "operation": "Datastore.relocate",
            "target": f"vm-{i}",
            "state": "success",
            "time": NOW,
            "user": "svc",
        }
        for i in range(12)
    ]
    rows.append(
        {"operation": "VirtualMachine.clone", "target": "vm-x", "state": "error", "time": NOW, "user": "bob"}
    )
    summary = taskhistory.summarize_tasks(rows, now=NOW, window_minutes=120)
    assert summary["by_family"]["migration"] == 12
    assert len(summary["failures"]) == 1
    assert any("migration" in finding for finding in summary["findings"])


# -- Linux boot picture ------------------------------------------------------


def test_linux_boot_picture_classifies_dmesg_and_names_slow_units() -> None:
    output = (
        "===LAST_BOOT===\n2026-10-29 02:00:00\n"
        "===BLAME===\n45.123s cloud-init.service\n2.000s sshd.service\n"
        "===CRITICAL===\ngraphical.target @48.0s\n"
        "===DMESG===\n[  12.3] INFO: task jbd2:131 blocked for more than 120 seconds.\n"
        "===JOURNAL===\n2026-10-29T02:00:10 kernel: EXT4-fs error (device sda1): ext4_find_entry\n"
        "===END==="
    )
    summary = linuxboot.summarize_linux_boot(output)
    kinds = {finding["kind"] for finding in summary["kernel_findings"]}
    assert "hung_task" in kinds
    assert "filesystem" in kinds
    assert summary["slow_units"][0]["unit"] == "cloud-init.service"
    assert summary["restricted"] is False


def test_linux_boot_reports_a_restricted_read() -> None:
    output = "===LAST_BOOT===\n2026\n===BLAME===\n===CRITICAL===\n===DMESG===\n===JOURNAL===\n===END==="
    summary = linuxboot.summarize_linux_boot(output)
    assert summary["restricted"] is True
    assert any("restricted" in line for line in summary["picture"])


# -- PowerFlex backend -------------------------------------------------------


def test_powerflex_lun_and_naa_helpers() -> None:
    assert powerflex.is_powerflex_lun("DellEMC", "ScaleIO") is True
    assert powerflex.is_powerflex_lun("NETAPP", "LUN") is False
    assert powerflex.volume_id_from_naa("naa.6e00abcd0123456789abcdef01234567") == "89abcdef01234567"
    assert powerflex.volume_id_from_naa(None) is None


def test_powerflex_health_flags_a_rebuild_and_a_down_sds() -> None:
    sds = [
        {
            "name": "sds-1",
            "sdsState": "Normal",
            "mdmConnectionState": "Connected",
            "membershipState": "Joined",
        },
        {"name": "sds-2", "sdsState": "Disconnected", "mdmConnectionState": "Disconnected"},
    ]
    devices = [{"id": "d1", "deviceState": "Normal", "errorState": "None"}]
    stats = {"rebuildPendingCapacityInKb": 5000, "rebalancePendingCapacityInKb": 0}
    summary = powerflex.summarize_health(sds, devices, stats)
    assert summary["healthy"] is False
    assert summary["rebuild_active"] is True
    assert "sds-2" in summary["sds_down"]
    assert any("rebuild" in finding for finding in summary["findings"])


def test_powerflex_health_is_calm_when_all_is_well() -> None:
    sds = [
        {
            "name": "sds-1",
            "sdsState": "Normal",
            "mdmConnectionState": "Connected",
            "membershipState": "Joined",
        }
    ]
    devices = [{"id": "d1", "deviceState": "Normal", "errorState": "None"}]
    stats = {"pendingFwdRebuildCapacityInKb": 0, "pendingRebalanceCapacityInKb": 0}
    summary = powerflex.summarize_health(sds, devices, stats)
    assert summary["healthy"] is True


def test_powerflex_gap_named_only_when_unconfigured() -> None:
    assert capabilities.powerflex_gap(_settings()) is not None
    configured = _settings(
        VSPHERE_POWERFLEX_URL="https://gw", VSPHERE_POWERFLEX_USERNAME="u", VSPHERE_POWERFLEX_PASSWORD="p"
    )
    assert capabilities.powerflex_gap(configured) is None


# -- VMCI in the hardware view -----------------------------------------------


def test_vmci_device_surfaces_its_config_and_flags_unrestricted() -> None:
    device = vim.vm.device.VirtualVMCIDevice(allowUnrestrictedCommunication=True, filterEnable=False)
    described, findings, _blocking = describe_devices([device])
    assert described[0]["category"] == "vmci"
    assert described[0]["allow_unrestricted_communication"] is True
    assert any("unrestricted" in finding for finding in findings)


def test_powerflex_bwc_rate_and_traffic_prefers_user_data() -> None:
    assert powerflex.bwc_rate({"numOccured": 600, "numSeconds": 10, "totalWeightInKb": 20000}) == {
        "iops": 60.0,
        "kb_per_s": 2000.0,
    }
    assert powerflex.bwc_rate({"numSeconds": 0}) == {"iops": 0.0, "kb_per_s": 0.0}
    stats = {
        "userDataReadBwc": {"numOccured": 100, "numSeconds": 10, "totalWeightInKb": 4000},
        "userDataWriteBwc": {"numOccured": 50, "numSeconds": 10, "totalWeightInKb": 2000},
        "totalReadBwc": {"numOccured": 9999, "numSeconds": 10, "totalWeightInKb": 9999},
    }
    traffic = powerflex.traffic_of(stats)
    assert traffic["read_iops"] == 10.0  # userData wins over totalReadBwc
    assert traffic["total_iops"] == 15.0


def test_powerflex_ranks_a_hot_protection_domain() -> None:
    rows = [
        {"name": "pd-busy", "id": "1", "state": "Active", "traffic": {"total_iops": 800.0}},
        {"name": "pd-quiet", "id": "2", "state": "Active", "traffic": {"total_iops": 200.0}},
    ]
    ranked = powerflex.rank_protection_domains(rows)
    assert ranked["ranked"][0]["name"] == "pd-busy"
    assert ranked["total_iops"] == 1000.0
    assert any("hot protection domain" in finding for finding in ranked["findings"])


def test_powerflex_even_traffic_names_no_hotspot() -> None:
    rows = [
        {"name": "pd-a", "id": "1", "state": "Active", "traffic": {"total_iops": 300.0}},
        {"name": "pd-b", "id": "2", "state": "Active", "traffic": {"total_iops": 300.0}},
    ]
    ranked = powerflex.rank_protection_domains(rows)
    assert any("none dominates" in finding for finding in ranked["findings"])


# -- PowerFlex -> vSphere reverse mapping ------------------------------------


def test_datastore_backing_naas_reads_vmfs_extents() -> None:
    info = SimpleNamespace(
        vmfs=SimpleNamespace(
            extent=[SimpleNamespace(diskName="naa.6abc"), SimpleNamespace(diskName="naa.6def")]
        )
    )
    assert datastore_backing_naas(info) == ["naa.6abc", "naa.6def"]
    assert datastore_backing_naas(SimpleNamespace(nas=object())) == []  # NFS: no vmfs extent


def test_map_backend_impact_picks_volumes_on_troubled_pds() -> None:
    pds = [{"id": "pd1", "name": "prod"}, {"id": "pd2", "name": "quiet"}]
    pd_stats = {
        "pd1": {"rebuildPendingCapacityInKb": 9000},  # degraded -> troubled
        "pd2": {},
    }
    pools = [{"id": "sp1", "protectionDomainId": "pd1"}, {"id": "sp2", "protectionDomainId": "pd2"}]
    volumes = [
        {"id": "VOL-AAAA", "name": "ds-a", "storagePoolId": "sp1"},
        {"id": "VOL-BBBB", "name": "ds-b", "storagePoolId": "sp2"},
    ]
    impact = powerflex.map_backend_impact(pds, pd_stats, pools, volumes)
    assert impact["volume_to_pd"] == {"vol-aaaa": "prod"}
    assert "prod" in impact["troubled_protection_domains"]


def test_affected_vms_joins_volumes_to_datastores_to_suffering_vms() -> None:
    volume_to_pd = {"vol-aaaa": "prod"}
    datastores = [
        {"vcenter": "vc-a", "moref": "ds-1", "name": "ds-a", "powerflex_volume_ids": ["vol-aaaa"]},
        {"vcenter": "vc-a", "moref": "ds-2", "name": "ds-b", "powerflex_volume_ids": ["vol-zzzz"]},
    ]
    vms_by_datastore = {
        "vc-a:ds-1": [
            {"name": "web-01", "moref": "vm-1", "vcenter": "vc-a", "state": "busy_not_up", "suffering": True},
            {"name": "web-02", "moref": "vm-2", "vcenter": "vc-a", "state": "up", "suffering": False},
        ]
    }
    result = powerflex.affected_vms(volume_to_pd, datastores, vms_by_datastore)
    assert len(result["affected_datastores"]) == 1
    hit = result["affected_datastores"][0]
    assert hit["datastore"] == "ds-a"
    assert hit["protection_domain"] == "prod"
    assert hit["suffering_total"] == 1
    assert result["suffering_total"] == 1


def test_affected_vms_says_so_when_nothing_maps() -> None:
    result = powerflex.affected_vms({"vol-x": "pd"}, [], {})
    assert result["affected_datastores"] == []
    assert any("no datastore" in finding for finding in result["findings"])


def _powerflex_client(handler: object) -> object:
    settings = _settings(
        VSPHERE_POWERFLEX_URL="https://gw",
        VSPHERE_POWERFLEX_USERNAME="u",
        VSPHERE_POWERFLEX_PASSWORD="p",
    )
    return powerflex.PowerFlex(settings, transport=httpx.MockTransport(handler))


def test_powerflex_client_is_get_only_and_reuses_its_token() -> None:
    logins = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"  # the read-only proof: the client never writes
        path = request.url.path
        if path == "/api/login":
            logins["count"] += 1
            return httpx.Response(200, text='"tok-123"')
        if path == "/api/logout":
            return httpx.Response(200, text='""')
        bodies: dict[str, object] = {
            "/api/types/Sds/instances": [
                {"name": "sds-1", "sdsState": "Normal", "mdmConnectionState": "Connected"}
            ],
            "/api/types/ProtectionDomain/instances": [{"id": "pd1", "name": "prod"}],
            "/api/types/StoragePool/instances": [{"id": "sp1", "protectionDomainId": "pd1"}],
            "/api/types/Volume/instances": [{"id": "VOL1", "name": "ds-a", "storagePoolId": "sp1"}],
        }
        if path in bodies:
            return httpx.Response(200, json=bodies[path])
        if "Statistics" in path:
            return httpx.Response(
                200, json={"userDataReadBwc": {"numOccured": 100, "numSeconds": 10, "totalWeightInKb": 4000}}
            )
        return httpx.Response(404, json={})

    client = _powerflex_client(handler)

    async def drive() -> tuple:
        sds = await client.sds()
        pds = await client.protection_domains()
        stats = await client.protection_domain_statistics("pd1")
        await client.aclose()
        return sds, pds, stats

    sds, pds, stats = asyncio.run(drive())
    assert sds[0]["name"] == "sds-1"
    assert pds[0]["id"] == "pd1"
    assert powerflex.traffic_of(stats)["read_iops"] == 10.0
    assert logins["count"] == 1  # token acquired once, then reused across calls


def test_powerflex_login_failure_is_reported() -> None:
    client = _powerflex_client(lambda _request: httpx.Response(401, text="denied"))
    with pytest.raises(powerflex.PowerFlexError):
        asyncio.run(client.sds())


# -- host hardware sensors ----------------------------------------------------


def test_host_sensors_flag_red_and_yellow() -> None:
    sensors = [
        {"name": "PSU1", "type": "power", "health": "green"},
        {"name": "PSU2", "type": "power", "health": "red"},
        {"name": "DIMM3", "type": "memory", "health": "yellow"},
    ]
    verdict = hostsensors.classify_sensors(sensors)
    assert verdict["healthy"] is False
    assert verdict["red"][0]["name"] == "PSU2"
    assert any("CRITICAL" in finding for finding in verdict["findings"])


def test_host_sensors_no_data_is_said_not_assumed_healthy() -> None:
    verdict = hostsensors.classify_sensors([])
    assert verdict["healthy"] is None
    assert any("no hardware sensor data" in finding for finding in verdict["findings"])


# -- crash dump header decode -------------------------------------------------


def test_crash_dump_decodes_the_bugcheck_and_parameters() -> None:
    parsed = {
        "found": True,
        "name": "103025-1234.dmp",
        "signature": "PAGEDU64",
        "code": 0x7A,
        "params": [0x1, 0xFFFFF8000000, 0xC000000E, 0x2000],
    }
    decoded = crashdump.decode_dump(parsed)
    assert decoded["found"] is True
    assert decoded["bugcheck"]["code"] == "0x0000007A"
    assert decoded["bugcheck"]["name"] == "KERNEL_DATA_INPAGE_ERROR"
    assert decoded["parameters"][0] == "0x0000000000000001"


def test_crash_dump_absent_is_reported() -> None:
    assert crashdump.decode_dump({"found": False})["found"] is False


def test_a_hard_reset_is_never_sent_twice_after_a_session_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    from vsphere_triage import power  # noqa: PLC0415
    from vsphere_triage.vcenter import VCenterPool, VSphereError  # noqa: PLC0415

    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
        }
    )
    pool = VCenterPool(settings)
    session = pool.session("vc-a")

    def fake_login() -> None:
        session._content = object()
        session.generation += 1

    monkeypatch.setattr(session, "_login", fake_login)
    target = vm(moref="vm-7", tools_running="guestToolsNotRunning")
    monkeypatch.setattr(power, "locate", lambda *_a, **_k: {"found": True, "vm": target})
    sent = {"n": 0}

    def reset(_moref: str) -> dict:
        sent["n"] += 1
        raise vim.fault.NotAuthenticated

    monkeypatch.setattr(session, "hard_reset", reset)

    with pytest.raises(VSphereError, match="may or may not have run"):
        asyncio.run(power.hard_reset(pool, settings, "vc-a", moref="vm-7", env_id=None, vm_name="web-01"))

    assert sent["n"] == 1


# -- review of main: PowerFlex ------------------------------------------------------------------


def test_powerflex_logs_in_again_when_its_token_expires() -> None:
    logins = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/login":
            logins["count"] += 1
            return httpx.Response(200, text=f'"tok-{logins["count"]}"')
        token = (request.headers.get("authorization") or "").split()[-1]
        import base64 as b64  # noqa: PLC0415

        if b64.b64decode(token).decode().endswith("tok-1"):
            return httpx.Response(401)  # the first token has expired
        return httpx.Response(200, json=[{"name": "sds-1"}])

    client = _powerflex_client(handler)

    assert asyncio.run(client.sds()) == [{"name": "sds-1"}]  # type: ignore[attr-defined]
    assert logins["count"] == 2


def test_affected_vms_keeps_two_vcenters_same_datastore_moref_apart() -> None:
    volume_to_pd = {"vol-aaaa": "prod"}
    datastores = [
        {"vcenter": "vc-1", "moref": "datastore-12", "name": "sick", "powerflex_volume_ids": ["vol-aaaa"]},
        {"vcenter": "vc-2", "moref": "datastore-12", "name": "fine", "powerflex_volume_ids": ["vol-zzzz"]},
    ]
    vms_by_datastore = {
        powerflex.datastore_key("vc-1", "datastore-12"): [
            {"name": "stuck", "moref": "vm-1", "vcenter": "vc-1", "state": "hung", "suffering": True}
        ],
        powerflex.datastore_key("vc-2", "datastore-12"): [
            {"name": "ok", "moref": "vm-1", "vcenter": "vc-2", "state": "healthy", "suffering": False}
        ],
    }

    result = powerflex.affected_vms(volume_to_pd, datastores, vms_by_datastore)

    hit = result["affected_datastores"][0]
    assert hit["vcenter"] == "vc-1"
    assert [vm["name"] for vm in hit["suffering_vms"]] == ["stuck"]


def test_a_rebuilding_system_beside_a_healthy_one_is_not_healthy() -> None:
    merged = powerflex.merge_statistics(
        [{"pendingFwdRebuildCapacityInKb": 9000}, {"pendingFwdRebuildCapacityInKb": 0}]
    )
    sds = [{"name": "sds-1", "sdsState": "Normal"}]
    devices = [{"id": "d1", "deviceState": "Normal", "errorState": "None"}]

    summary = powerflex.summarize_health(sds, devices, merged)

    assert merged["pendingFwdRebuildCapacityInKb"] == 9000
    assert summary["healthy"] is False
    assert summary["rebuild_active"] is True


def test_failed_capacity_means_data_unavailable() -> None:
    sds = [{"name": "sds-1", "sdsState": "Normal"}]
    devices = [{"id": "d1", "deviceState": "Normal", "errorState": "None"}]

    summary = powerflex.summarize_health(sds, devices, {"failedCapacityInKb": 100})

    assert summary["healthy"] is False
    assert summary["data_unavailable"] is True


def test_powerflex_with_nothing_read_is_unknown_not_healthy() -> None:
    summary = powerflex.summarize_health([], [], {})

    assert summary["healthy"] is None
    assert "not evidence it is healthy" in summary["findings"][0]


def test_a_51_49_split_of_two_protection_domains_is_not_a_hotspot() -> None:
    rows = [
        {"name": "pd-a", "id": "1", "state": "Active", "traffic": {"total_iops": 510.0}},
        {"name": "pd-b", "id": "2", "state": "Active", "traffic": {"total_iops": 490.0}},
    ]

    ranked = powerflex.rank_protection_domains(rows)

    assert any("none dominates" in finding for finding in ranked["findings"])


# -- review of main: the tools that act on a VM -------------------------------------------------


def test_an_acting_tool_refuses_a_moref_whose_name_does_not_match(monkeypatch: pytest.MonkeyPatch) -> None:
    other = vm(moref="vm-1243", name="web-07")
    monkeypatch.setattr(diagnose.Layout, "of", classmethod(lambda _cls, _s: SimpleNamespace(folders={})))
    monkeypatch.setattr(diagnose, "read_vms", lambda *_a, **_k: [(other, {})])
    session = SimpleNamespace(reference=lambda *_a: None, vcenter=SimpleNamespace(name="vc-a"))

    lenient = diagnose.locate(session, Settings(), env_id=None, vm_name="db01", moref="vm-1243")  # type: ignore[arg-type]
    strict = diagnose.locate(session, Settings(), env_id=None, vm_name="db01", moref="vm-1243", strict=True)  # type: ignore[arg-type]

    assert lenient["found"] is True
    assert strict["found"] is False
    assert "refusing to act" in strict["reason"]


def test_an_acting_tool_refuses_a_partial_environment_id(monkeypatch: pytest.MonkeyPatch) -> None:
    folders = {"g1": folder("g1", "env-142", "g0", "/DC0/vm/env-142", "vm")}
    monkeypatch.setattr(diagnose.Layout, "of", classmethod(lambda _cls, _s: SimpleNamespace(folders=folders)))
    monkeypatch.setattr(diagnose, "read_vms", lambda *_a, **_k: [(vm(name="db01"), {})])
    session = SimpleNamespace(reference=lambda *_a: None, vcenter=SimpleNamespace(name="vc-a"))

    strict = diagnose.locate(session, Settings(), env_id="42", vm_name="db01", moref=None, strict=True)  # type: ignore[arg-type]

    assert strict["found"] is False
    assert "partial environment id" in strict["reason"]


def test_a_boot_entry_without_an_ems_line_is_ems_off_not_access_denied() -> None:
    from vsphere_triage import emscheck  # noqa: PLC0415

    dump = (
        "Windows Boot Loader\n-------------------\nidentifier              {current}\n"
        "path                    \\Windows\\system32\\winload.efi\n"
        "bootstatuspolicy        IgnoreAllFailures\n"
    )
    localized = dump + "ems                     Ja\n"

    assert emscheck.parse_bcd_output(dump)["ems_enabled"] is False
    assert emscheck.parse_bcd_output(localized)["ems_enabled"] is True
    assert emscheck.parse_bcd_output("garbage")["ems_enabled"] is None


def test_an_unreadable_minidump_folder_is_not_no_dump() -> None:
    from vsphere_triage import crashdump  # noqa: PLC0415

    assert "elevated" in crashdump.decode_dump({"found": False, "denied": True})["reason"]
    assert "not evidence" in crashdump.decode_dump({})["reason"]


def test_a_failed_guest_probe_is_not_read_as_a_clean_one() -> None:
    assert "timeout" in guestexec.probe_failed({"timed_out": True, "exit_code": None, "output": ""})
    assert "no output" in guestexec.probe_failed({"timed_out": False, "exit_code": 127, "output": " "})
    assert guestexec.probe_failed({"timed_out": False, "exit_code": 0, "output": "{}"}) is None


def test_the_windows_boot_probe_cuts_messages_by_their_collapsed_length() -> None:
    script = winboot.boot_probe_powershell()

    assert "$m.Substring(0,[Math]::Min(300,$m.Length))" in script
    assert "($_.Message).Length" not in script
    assert "$o.srttrail=$(if" in script


# -- review of main: the new read tools ---------------------------------------------------------


def test_an_eventex_ha_restart_is_recognised() -> None:
    from vsphere_triage import clusterevents  # noqa: PLC0415

    hit = clusterevents.classify_event(
        "com.vmware.vc.ha.VmRestartedByHAEvent",
        "vSphere HA restarted virtual machine web-01 on host esx-2 in cluster c1",
    )

    assert hit is not None
    assert hit[0] == "ha_vm_restart"


def test_a_lost_connection_is_not_a_failed_host_and_one_vmotion_counts_once() -> None:
    from vsphere_triage import clusterevents  # noqa: PLC0415

    lost = clusterevents.classify_event("HostConnectionLostEvent", "Host esx-1 is not responding")
    being = clusterevents.classify_event("VmBeingHotMigratedEvent", "Migrating web-01 from esx-1 to esx-2")
    task = clusterevents.classify_event("TaskEvent", "Task: Migrate virtual machine")
    done = clusterevents.classify_event("VmMigratedEvent", "Migration of web-01 from esx-1 completed")

    assert lost is not None
    assert lost[0] == "host_connection_lost"
    assert being is None
    assert task is None
    assert done is not None
    assert done[0] == "drs_migration"


class _EventsSession:
    """A session whose QueryEvents answers at most 1000 events, the newest, like vCenter."""

    def __init__(self, stamps: list[datetime]) -> None:
        self.stamps = stamps
        self.queries = 0

    def events(self, **kwargs: object) -> list:
        self.queries += 1
        begin, end = kwargs["begin"], kwargs["end"]
        inside = [s for s in self.stamps if begin <= s <= end]  # type: ignore[operator]
        return [SimpleNamespace(key=s.timestamp(), createdTime=s) for s in inside[-1000:]]


def test_a_busy_window_is_read_in_pieces_not_cut_to_its_last_minutes() -> None:
    begin = NOW - timedelta(hours=2)
    stamps = [begin + timedelta(seconds=3 * n) for n in range(2400)]  # 2400 events over 2 h
    session = _EventsSession(stamps)

    events, cut = VCenterSession.events_covering(session, begin=begin, end=NOW)  # type: ignore[arg-type]

    assert len(events) == 2400
    assert cut is False
    assert events[0].createdTime == stamps[0]  # the oldest is there, not only the newest 1000


def test_no_sensor_data_is_unknown_and_readings_are_scaled() -> None:
    _sensor_reading = hostsensors._reading

    assert _sensor_reading(SimpleNamespace(currentReading=4500, unitModifier=-2)) == 45.0
    assert _sensor_reading(SimpleNamespace(currentReading=None, unitModifier=0)) is None


# -- review of main, round two ------------------------------------------------------------------


def test_an_acting_tool_refuses_a_stale_moref_from_another_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    folders = {
        "g-a": folder("g-a", "envA", "g0", "/DC0/vm/envA", "vm"),
        "g-b": folder("g-b", "envB", "g0", "/DC0/vm/envB", "vm"),
    }
    stale = vm(moref="vm-123", name="dc01", folder_moref="g-a", folder_path="/DC0/vm/envA")
    monkeypatch.setattr(diagnose.Layout, "of", classmethod(lambda _cls, _s: SimpleNamespace(folders=folders)))
    monkeypatch.setattr(diagnose, "read_vms", lambda *_a, **_k: [(stale, {})])
    session = SimpleNamespace(reference=lambda *_a: None, vcenter=SimpleNamespace(name="vc-a"))

    wrong = diagnose.locate(session, Settings(), env_id="envB", vm_name="dc01", moref="vm-123", strict=True)  # type: ignore[arg-type]
    right = diagnose.locate(session, Settings(), env_id="envA", vm_name="dc01", moref="vm-123", strict=True)  # type: ignore[arg-type]

    assert wrong["found"] is False
    assert "not inside an environment folder named 'envB'" in wrong["reason"]
    assert right["found"] is True


def test_ha_monitoring_resets_and_failover_failures_are_classified() -> None:
    from vsphere_triage import clusterevents  # noqa: PLC0415

    def bucket(kind: str, text: str) -> str | None:
        hit = clusterevents.classify_event(kind, text)
        return hit[0] if hit else None

    assert bucket("VmDasBeingResetEvent", "web-01 is reset by vSphere HA") == "ha_vm_monitoring_reset"
    assert bucket("VmRestartedOnAlternateHostEvent", "web-01 restarted on esx-2") == "ha_vm_restart"
    assert bucket("HostNoRedundantManagementNetworkEvent", "no management redundancy") == (
        "host_no_redundant_management"
    )
    assert (
        bucket("FailedRestartAfterIsolationEvent", "could not restart after isolation")
        == "vm_failover_failed"
    )


def test_a_tiny_window_still_over_the_cap_is_said_to_be_cut() -> None:
    stamps = [NOW - timedelta(milliseconds=n) for n in range(3000)][::-1]  # 3000 events in 3 s
    session = _EventsSession(stamps)

    _events, cut = VCenterSession.events_covering(session, begin=NOW - timedelta(seconds=1), end=NOW)  # type: ignore[arg-type]

    assert cut is True


def test_a_missing_minidump_folder_is_told_apart_from_no_dump() -> None:
    from vsphere_triage import crashdump  # noqa: PLC0415

    assert "does not exist" in crashdump.decode_dump({"found": False, "folder": False})["reason"]
    assert "could not be opened" in crashdump.decode_dump({"found": False, "unreadable": "x.dmp"})["reason"]


# -- review of main, round three ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "message", "bucket"),
    [
        (
            "com.vmware.vc.HA.ClusterFailoverActionCompletedEvent",
            "vSphere HA completed a failover action",
            None,
        ),
        (
            "com.vmware.vc.HA.ClusterFailoverActionInitiatedEvent",
            "vSphere HA initiated a failover action",
            None,
        ),
        ("AlarmStatusChangedEvent", "Alarm 'Host connection failure' on h1 changed from Green to Red", None),
        (
            "DasHostFailedEvent",
            "A possible host failure has been detected by vSphere HA on esx-1",
            "host_failure",
        ),
        ("DasHostIsolatedEvent", "Host esx-1 has been isolated from cluster c1", "host_isolation"),
    ],
)
def test_a_completed_failover_and_alarms_are_not_failures(
    kind: str, message: str, bucket: str | None
) -> None:
    from vsphere_triage import clusterevents  # noqa: PLC0415

    hit = clusterevents.classify_event(kind, message)

    assert (hit[0] if hit else None) == bucket


def test_a_32_bit_dump_is_not_decoded_with_64_bit_offsets() -> None:
    from vsphere_triage import crashdump  # noqa: PLC0415

    decoded = crashdump.decode_dump({"found": True, "name": "x.dmp", "signature": "PAGEDUMP", "code": 0x1E})

    assert decoded["bugcheck"] is None
    assert "PAGEDU64" in decoded["note"]


# -- review of main, round four -----------------------------------------------------------------


def test_an_ha_restart_names_the_failed_host_not_the_one_the_vms_came_back_on() -> None:
    from vsphere_triage import clusterevents  # noqa: PLC0415

    rows = [
        {
            "type": "DasHostFailedEvent",
            "time": NOW - timedelta(minutes=7),
            "message": "A possible host failure has been detected by vSphere HA on esx-1",
            "host": None,
            "affected_host": "esx-1",
            "vm": None,
        },
        *(
            {
                "type": "com.vmware.vc.ha.VmRestartedByHAEvent",
                "time": NOW - timedelta(minutes=m),
                "message": f"vSphere HA restarted virtual machine web-0{m} on host esx-2",
                "host": "esx-2",
                "vm": f"web-0{m}",
            }
            for m in range(3)
        ),
    ]

    summary = clusterevents.summarize_cluster_events(rows, now=NOW, window_minutes=120)

    restart = next(finding for finding in summary["findings"] if "HA restarted" in finding)
    assert "onto esx-2" in restart
    assert "after a failure of esx-1" in restart
    assert summary["buckets"]["host_failure"]["hosts"] == ["esx-1"]


@pytest.mark.parametrize(
    ("kind", "message", "bucket"),
    [
        ("NotEnoughResourcesToStartVmEvent", "Not enough resources to failover web-01", "vm_failover_failed"),
        ("com.vmware.vc.ha.VmFailedRestart", "vSphere HA was unable to restart web-01", "vm_failover_failed"),
        (
            "InsufficientFailoverResourcesEvent",
            "Insufficient resources to satisfy HA failover",
            "ha_capacity_warning",
        ),
        (
            "HostIsolationIpPingFailedEvent",
            "Host esx-1 could not reach isolation address",
            "isolation_address_unreachable",
        ),
    ],
)
def test_ha_wordings_the_patterns_had_missed(kind: str, message: str, bucket: str) -> None:
    from vsphere_triage import clusterevents  # noqa: PLC0415

    hit = clusterevents.classify_event(kind, message)

    assert hit is not None
    assert hit[0] == bucket


# -- review of main, round five -----------------------------------------------------------------


def test_the_linux_probe_reads_the_boot_before_the_reboot() -> None:
    script = linuxboot.boot_probe_shell()
    output = (
        "===LAST_BOOT===\n2026-10-29 02:10:00\n===DMESG_LINES===\n812\n===DMESG===\n===JOURNAL===\n"
        "===BOOTS===\n2\n===PREVIOUS===\n"
        "2026-10-29T01:50:00 host kernel: Kernel panic - not syncing\n===END===\n"
    )

    summary = linuxboot.summarize_linux_boot(output)

    assert "journalctl -b -1" in script
    assert summary["previous_boot_read"] is True
    assert any(finding.startswith("previous boot:") for finding in summary["picture"])
    assert summary["restricted"] is False  # dmesg was readable; it just had no fault lines


def test_a_volatile_journal_says_the_hung_boot_was_not_read() -> None:
    output = "===DMESG_LINES===\n500\n===BOOTS===\n1\n===END===\n"

    summary = linuxboot.summarize_linux_boot(output)

    assert summary["previous_boot_read"] is False
    assert any("the boot that hung was NOT read" in finding for finding in summary["picture"])


def test_an_old_bugcheck_is_history_not_this_incidents_cause() -> None:
    parsed = {
        "last_boot": "2026-10-29T02:00:00+00:00",
        "bugchecks": [
            {
                "time": "2024-03-01T10:00:00+00:00",
                "message": "The computer has rebooted from a bugcheck. The bugcheck was: 0x0000007a (...)",
            }
        ],
    }

    summary = winboot.summarize_windows_boot(parsed)

    assert summary["bugchecks"] == []
    assert len(summary["older_bugchecks"]) == 1
    assert not any(finding.startswith("last bugcheck") for finding in summary["picture"])


def test_host_sensors_that_are_all_unknown_are_not_healthy() -> None:
    verdict = hostsensors.classify_sensors(
        [{"name": "CPU1", "health": "unknown"}, {"name": "PSU1", "health": None}]
    )

    assert verdict["healthy"] is None
    assert any("CIM provider" in finding for finding in verdict["findings"])


def test_drs_power_on_placements_are_not_a_vmotion_wave() -> None:
    assert taskhistory.categorize("Drm.ExecuteVmPowerOnLRO") == "power"
    assert taskhistory.categorize("Drm.ExecuteVMotionLRO") == "migration"
    assert taskhistory.categorize("VirtualMachine.reset") == "power"
    assert taskhistory.categorize("VirtualMachine.resetGuestInformation") == "other"
    assert taskhistory.categorize("VirtualMachine.consolidateDisks") == "snapshot"


def test_vcenters_own_loopback_logins_are_not_a_churning_client() -> None:
    rows = [
        {
            "type": "UserLoginSessionEvent",
            "time": NOW - timedelta(minutes=n),
            "user": "vpxd",
            "source": "127.0.0.1",
        }
        for n in range(30)
    ]

    summary = connhistory.summarize_session_events(rows, now=NOW, window_minutes=60)

    assert not any("churning" in finding for finding in summary["findings"])


# -- review of main, round six ------------------------------------------------------------------


def test_the_journal_boot_count_ignores_the_list_boots_header() -> None:
    script = linuxboot.boot_probe_shell()

    assert "--list-boots --no-pager 2>/dev/null | grep -cE '^ *-?[0-9]+ '" in script


def test_older_boot_events_are_kept_and_named_not_dropped() -> None:
    parsed = {
        "last_boot": "2026-10-29T02:00:00+00:00",
        "service_timeouts": [{"time": "2026-10-26T09:00:00+00:00", "id": 7009, "message": "timeout"}],
    }

    summary = winboot.summarize_windows_boot(parsed)

    assert summary["older_events"]["service_timeouts"]
    assert any("1 older boot event(s)" in finding for finding in summary["picture"])


def test_vms_stunned_on_a_question_by_a_full_datastore_count_as_suffering() -> None:
    from vsphere_triage.server import STORAGE_SUFFERING  # noqa: PLC0415

    assert {checks.BLOCKED_ON_QUESTION, checks.PAUSED, checks.INACCESSIBLE} <= STORAGE_SUFFERING
    assert checks.HEALTHY not in STORAGE_SUFFERING


def test_a_power_operation_by_moref_alone_is_refused() -> None:
    from vsphere_triage import power  # noqa: PLC0415

    class _NoPool:
        async def run(self, *_a: object, **_k: object) -> dict:
            raise AssertionError("nothing may be read or sent")

    result = asyncio.run(
        power.hard_reset(_NoPool(), Settings(), "vc-a", moref="vm-1001", env_id=None, vm_name=None)  # type: ignore[arg-type]
    )

    assert result["found"] is False
    assert "needs the VM's name" in result["reason"]


# -- review against the PowerFlex SDKs ----------------------------------------------------------


def test_a_degraded_pool_with_no_rebuild_running_is_not_healthy() -> None:
    sds = [{"name": "sds-1", "sdsState": "Normal", "mdmConnectionState": "Connected"}]
    devices = [{"id": "d1", "deviceState": "Normal", "errorState": "None"}]

    degraded = powerflex.summarize_health(sds, devices, {"semiProtectedCapacityInKb": 4096})
    unreachable = powerflex.summarize_health(sds, devices, {"inaccessibleCapacityInKb": 10})

    assert degraded["healthy"] is False
    assert degraded["degraded"] is True
    assert degraded["rebuild_active"] is False
    assert any("no rebuild is running" in finding for finding in degraded["findings"])
    assert unreachable["data_unavailable"] is True
    assert any("inaccessibleCapacityInKb" in finding for finding in unreachable["findings"])


def test_the_dmesg_filter_keeps_dracut_failures_and_drops_oops_on_the_command_line() -> None:
    script = linuxboot.boot_probe_shell()
    pattern = re.search(r"grep -iE '([^']+)'", script)
    assert pattern
    keep = re.compile(pattern.group(1), re.IGNORECASE)

    assert keep.search("dracut-initqueue[285]: Warning: Could not boot.")
    assert keep.search("Kernel panic - not syncing: VFS: Unable to mount root fs")
    assert keep.search("Oops: 0000 [#1] SMP PTI")
    assert not keep.search("Kernel command line: BOOT_IMAGE=/vmlinuz root=/dev/sda1 oops=panic")
    oops = next(mark for name, _, mark in vmlog.LINUX_MARKS if name == "oops")
    assert not oops.search("Kernel command line: root=/dev/sda1 oops=panic")
    assert oops.search("Oops: 0000 [#1] SMP PTI")


def test_a_probe_whose_output_could_not_be_read_back_says_why() -> None:
    reason = guestexec.probe_failed({"output": "", "exit_code": 0, "output_error": "ConnectError: refused"})

    assert reason
    assert "ConnectError" in reason


def test_an_sds_state_field_that_is_null_is_not_a_down_sds() -> None:
    sds = [{"name": "sds-1", "sdsState": "Normal", "mdmConnectionState": None, "membershipState": "Joined"}]
    devices = [{"id": "d1", "deviceState": "Normal", "errorState": "None"}]

    summary = powerflex.summarize_health(sds, devices, {"semiProtectedCapacityInKb": 0})

    assert summary["sds_down"] == []
    assert summary["healthy"] is True


# -- review against real guests and the vSphere API --------------------------------------------


def test_a_localized_bugcheck_is_read_from_the_event_data() -> None:
    parsed = {
        "last_boot": "2026-10-29T02:00:00+00:00",
        "bugchecks": [
            {
                "time": "2026-10-29T02:01:00+00:00",
                "message": "Der Computer wurde nach einem Fehler neu gestartet. Fehlercode: ...",
                "data": "0x0000007a (0xffffd7ec, 0xc000000e, 0x0, 0x0) | C:\\Windows\\MEMORY.DMP",
            }
        ],
    }

    summary = winboot.summarize_windows_boot(parsed)

    assert summary["bugchecks"][0]["stop_codes"][0]["code"] == "0x0000007A"


def test_every_windows_probe_prints_its_json_as_utf8() -> None:
    from vsphere_triage import crashdump, emscheck  # noqa: PLC0415

    for script in (
        winboot.boot_probe_powershell(),
        emscheck.bcd_probe_powershell(),
        crashdump.dump_probe_powershell(),
    ):
        assert guestexec.PS_UTF8_OUTPUT in script
    # The BCD probe switches only after bcdedit ran, so bcdedit's output is decoded right.
    bcd = emscheck.bcd_probe_powershell()
    assert bcd.index("bcdedit") < bcd.index(guestexec.PS_UTF8_OUTPUT)


def test_every_windows_probe_fits_cmds_command_line_limit() -> None:
    from vsphere_triage import crashdump, emscheck  # noqa: PLC0415

    for script in (
        winboot.boot_probe_powershell(),
        emscheck.bcd_probe_powershell(),
        crashdump.dump_probe_powershell(),
    ):
        _program, arguments = guestexec.guest_program_spec(
            guestexec.encode_powershell(script), r"C:\Windows\Temp\vsphere-triage-x.txt", windows=True
        )
        assert len(arguments) < 8191


def test_a_slow_unit_over_a_minute_keeps_its_name() -> None:
    output = (
        "===BLAME===\n1min 30.012s systemd-networkd-wait-online.service\n  2.100s sshd.service\n===END===\n"
    )

    summary = linuxboot.summarize_linux_boot(output)

    assert summary["slow_units"][0] == {
        "time": "1min 30.012s",
        "unit": "systemd-networkd-wait-online.service",
    }


def test_no_entries_from_a_restricted_journal_is_not_a_clean_read() -> None:
    output = (
        "===DMESG_LINES===\n0\n===DMESG===\n===JOURNAL===\n-- No entries --\n"
        "===BOOTS===\n3\n===PREVIOUS===\n-- No entries --\n===END===\n"
    )

    summary = linuxboot.summarize_linux_boot(output)

    assert summary["restricted"] is True
    assert summary["previous_boot_read"] is False


def test_the_perf_rollup_matches_the_windows_age() -> None:
    from vsphere_triage.vcenter import perf_interval  # noqa: PLC0415

    assert perf_interval(timedelta(minutes=30)) == 20
    assert perf_interval(timedelta(hours=12)) == 300
    assert perf_interval(timedelta(days=3)) == 1800
    assert perf_interval(timedelta(days=20)) == 7200
    assert perf_interval(timedelta(days=200)) == 86400


# -- review against real screens and logs -------------------------------------------------------


def _screen(colour: tuple[int, int, int], spots: list[tuple[int, int, int, int]] = ()) -> bytes:
    image = Image.new("RGB", (1024, 768), colour)
    for left, top, width, height in spots:
        image.paste((255, 255, 255), (left, top, left + width, top + height))
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


def test_a_moving_boot_spinner_is_not_a_frozen_screen() -> None:
    dots_then = [(500 + 12 * index, 600, 6, 6) for index in range(5)]
    dots_now = [(506, 590 + 10 * index, 6, 6) for index in range(5)]

    result = console.read_captures(
        [_screen((0, 0, 0), dots_then), _screen((0, 0, 0), dots_now)],
        black_fraction=0.98,
        frozen_difference=0.5,
    )

    assert result["mean_difference"] < 0.5
    assert result["frozen"] is False


def test_a_blinking_cursor_alone_does_not_unfreeze_a_screen() -> None:
    text = [(20, 20 + 18 * row, 300, 10) for row in range(4)]

    result = console.read_captures(
        [_screen((0, 0, 0), [*text, (20, 100, 8, 16)]), _screen((0, 0, 0), text)],
        black_fraction=0.9,
        frozen_difference=0.5,
    )

    assert result["frozen"] is True


def _conclude_screen(machine: VmFacts, console_reading: dict) -> dict:
    return diagnose.conclude(
        checks.classify(machine, LIMITS),
        vm=machine,
        cpu={"findings": [], "starved": False},
        disk={"findings": [], "slow": False, "datastores": []},
        environment={"signals": []},
        logs={"available": False},
        serial={"available": False},
        console={"available": True, **console_reading},
        host_log={"available": False},
    )


def test_a_still_blue_screen_without_ocr_is_crash_evidence_only_for_a_windows_vm_that_is_down() -> None:
    blue = {"frozen": True, "blue_screen_colour": True, "screen_states": []}

    down = _conclude_screen(vm(cpu_mhz=3600.0, os_family="windows"), blue)
    idle = _conclude_screen(
        vm(
            cpu_mhz=30.0,
            os_family="windows",
            tools_running="guestToolsRunning",
            heartbeat="green",
            uptime_minutes=4000.0,
        ),
        blue,
    )
    installer = _conclude_screen(vm(cpu_mhz=3600.0, os_family="linux"), blue)

    assert any(cause["cause"] == diagnose.WINDOWS_CRASH for cause in down["causes"])
    assert not any(cause["cause"] == diagnose.WINDOWS_CRASH for cause in idle["causes"])
    assert not any(cause["cause"] == diagnose.WINDOWS_CRASH for cause in installer["causes"])


def test_still_text_on_black_on_a_down_windows_vm_is_a_crash_or_boot_error_not_a_login() -> None:
    result = _conclude_screen(
        vm(cpu_mhz=3600.0, os_family="windows"), {"frozen": True, "black": True, "text_on_black": True}
    )

    causes = [cause["cause"] for cause in result["causes"]]
    assert diagnose.WINDOWS_CRASH in causes
    assert diagnose.CANNOT_BOOT in causes
    assert diagnose.TOOLS_DID_NOT_START not in causes
    assert diagnose.EARLY_HANG not in causes


def test_a_guest_reboot_in_the_same_log_starts_a_new_boot() -> None:
    rows = [
        "2026-10-29T02:00:00.000Z In(05) vmx - Powering on the virtual machine",
        "2026-10-29T02:00:01.000Z In(05) vmx - EFI ROM loaded",
        "2026-10-29T02:00:40.000Z In(05) vmx - Tools: Changing running status: 0 => 1.",
        (
            "2026-10-29T03:00:00.000Z In(05) vcpu-0 - Chipset: The guest has requested that the "
            "virtual machine be hard reset."
        ),
        "2026-10-29T03:00:00.010Z In(05) vcpu-0 - CPU reset: hard (mode Emulation)",
        "2026-10-29T03:00:00.020Z In(05) vcpu-1 - CPU reset: hard (mode Emulation)",
        "2026-10-29T03:00:01.000Z In(05) vmx - EFI boot device order read",
    ]
    log = "\n".join(rows)

    timeline = vmlog.boot_timeline(vmlog.parse_lines(log))

    assert timeline["boot_started"] == datetime(2026, 10, 29, 3, 0, 0, 10000, tzinfo=UTC)
    assert timeline["last_stage"] == "firmware"


def test_routine_snapshot_stuns_and_tools_rpc_timeouts_are_not_storage() -> None:
    rows = [
        "2026-10-29T02:00:00.000Z In(05) vmx - Powering on the virtual machine",
        "2026-10-29T02:10:00.000Z In(05) vmx - Checkpoint_Unstun: vm stopped for 412 us",
        "2026-10-29T02:11:00.000Z In(05) vmx - GuestRpcSendTimedOut: message to toolbox timed out.",
        "2026-10-29T02:12:00.000Z Wa(03) vmx - AIOGNRC: Failed to issue IO to file /vmfs/x.vmdk",
    ]
    log = "\n".join(rows)

    storage = vmlog.boot_timeline(vmlog.parse_lines(log))["annotations"]["storage"]

    assert storage["count"] == 1
    assert "AIOGNRC" in storage["examples"][0]["message"]


def test_continuation_lines_parse_and_old_ones_stay_out_of_a_since_window() -> None:
    rows = [
        "2026-10-29T01:00:00.000Z In(05) vmx - Msg_Question:",
        "2026-10-29T01:00:00.000Z In(05)+ vmx - The datastore is full.",
        "an unparsed body line of the question",
        "2026-10-29T03:00:00.000Z In(05) vmx - Msg_Question: later",
    ]
    log = "\n".join(rows)
    lines = vmlog.parse_lines(log)

    kept, _ = vmlog.grep(lines, "question", since=datetime(2026, 10, 29, 2, tzinfo=UTC), limit=10)

    assert lines[1].time is not None
    assert [line.number for line in kept] == [4]


def test_a_vcenter_that_is_not_a_vim_server_is_reported_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(**_: object) -> None:
        msg = "10.255.255.1:443 is down or is not a VIM server"
        raise Exception(msg)  # noqa: TRY002 - what pyVmomi raises

    from vsphere_triage.vcenter import VSphereError  # noqa: PLC0415

    monkeypatch.setattr("vsphere_triage.vcenter.SmartConnect", refuse)
    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "10.255.255.1"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
        }
    )
    session = VCenterSession(settings.vcenters[0], settings)

    with pytest.raises(VSphereError, match="unreachable"):
        session.connect()


def test_context_flags_on_an_old_fleet_do_not_drown_the_stuck_group() -> None:
    fleet = [
        vm(
            moref=f"vm-{index}",
            host=f"esx-{index % 10}",
            datastores=["ds-17" if index < 40 else f"ds-{index % 5}"],
            created=NOW - timedelta(days=30),
            read_at=NOW,
            uptime_minutes=600.0,
            swapped_mb=64 if index % 2 else 0,
            tools_running="guestToolsNotRunning" if index < 30 else "guestToolsRunning",
            heartbeat="gray" if index < 30 else "green",
        )
        for index in range(300)
    ]

    result = scan.summary(scan_of(fleet), limit=10)

    assert result["findings"][0].startswith("30 abnormal of 300 powered-on VMs")
    assert result["abnormal_vms_total"] == 30
    assert result["context_flagged_vms_total"] == 270
    assert result["strongest_groups"][0]["dimension"] == "datastore"
    assert result["strongest_groups"][0]["value"].endswith("ds-17")
    assert all(item["verdict"]["state"] != "ok" for item in result["abnormal_vms"][:10])


def test_a_vm_in_a_vapp_gets_the_vapp_as_its_environment_folder() -> None:
    from vsphere_triage import inventory  # noqa: PLC0415

    root, vm_folder, vdc = vim.Folder("group-d1"), vim.Folder("group-v3"), vim.Folder("group-v9")
    vapp = vim.VirtualApp("resgroup-v42")
    rows = {
        vim.Datacenter: [{"moref": "datacenter-2", "name": "DC0", "parent": root, "vmFolder": vm_folder}],
        vim.Folder: [
            {"moref": "group-d1", "name": "Datacenters", "parent": None},
            {"moref": "group-v3", "name": "vm", "parent": vim.Datacenter("datacenter-2")},
            {"moref": "group-v9", "name": "vdc-prod", "parent": vm_folder},
        ],
        vim.VirtualApp: [{"moref": "resgroup-v42", "name": "env-1003", "parentFolder": vdc}],
    }
    session = SimpleNamespace(retrieve=lambda kind, _paths: rows.get(kind, []))

    folders = inventory.read_folders(session)
    facts = inventory.vm_facts(
        "vc-a",
        {"moref": "vm-7", "name": "web-01", "parent": None, "parentVApp": vapp},
        NOW,
        folders,
        {},
        {},
        with_devices=False,
    )

    assert facts.folder == "env-1003"
    assert facts.folder_path == "/DC0/vm/vdc-prod/env-1003"
    assert facts.folder_parent == "vdc-prod"
    assert facts.datacenter == "DC0"
    assert [folder.moref for folder in find_environment(folders, "env-1003")] == ["resgroup-v42"]


def test_a_host_that_is_down_does_not_make_its_datastores_unreachable() -> None:
    mounts = [
        {"host_moref": "host-1", "mounted": True, "accessible": True, "inaccessible_reason": None},
        {
            "host_moref": "host-2",
            "mounted": True,
            "accessible": False,
            "inaccessible_reason": None,
            "host_up": False,
        },
    ]

    verdict = storagehealth.classify_datastore(_store(mounts=mounts), LIMITS)

    assert verdict["healthy"] is True
    assert verdict["hosts_unreachable"] == []
    assert verdict["hosts_down_mounting"] == 1
    assert "not connected" in verdict["host_note"]


def test_a_ptp_host_is_not_faulted_for_having_no_ntp() -> None:
    verdict = timecheck.classify_host_time(
        _host_time(ntp_servers=[], clock_protocol="ptp", service_key="ptpd"), LIMITS
    )

    assert verdict["healthy"] is True


def test_a_vm_needing_consolidation_with_no_snapshot_tree_is_listed() -> None:
    from vsphere_triage import inventory  # noqa: PLC0415

    gb = 1024**3
    layout = _LayoutEx(
        files=[_File(1, "diskExtent", 40 * gb), _File(2, "diskExtent", 12 * gb)],
        disks=[_Disk(200, [_Unit(1), _Unit(2)])],
    )
    ref = vim.VirtualMachine("vm-9")
    rows = {
        ("name", "parent", "parentVApp", "config.template", "runtime.consolidationNeeded", "snapshot"): [
            {
                "moref": "vm-9",
                "_ref": ref,
                "name": "db-01",
                "runtime.consolidationNeeded": True,
                "snapshot": None,
            }
        ],
    }

    def retrieve(_kind: object, paths: tuple, objects: object = None) -> list:
        if objects is not None:
            return [{"moref": "vm-9", "layoutEx": layout, "config.hardware.device": []}]
        return rows[tuple(paths)]

    session = SimpleNamespace(retrieve=retrieve, now=lambda: NOW, vcenter=SimpleNamespace(name="vc-a"))

    found = inventory.read_vm_snapshots(session, {})

    assert [item["moref"] for item in found] == ["vm-9"]
    assert found[0]["consolidation_needed"] is True
    assert found[0]["delta_bytes"] == 12 * gb


def test_a_storage_path_going_dead_is_not_a_host_failure() -> None:
    path = clusterevents.classify_event("EsxCommonEvent", "Device naa.600 path state changed to Dead")
    host = clusterevents.classify_event(
        "com.vmware.vc.HA.HostStateChangedEvent",
        "The vSphere HA availability state of the host esx-1 in cluster C1 has changed to Dead",
    )

    assert path is None or path[0] != "host_failure"
    assert host is not None
    assert host[0] == "host_failure"


def test_a_datastore_whose_every_host_is_down_is_unknown_not_unreachable() -> None:
    mounts = [
        {
            "host_moref": "host-1",
            "mounted": True,
            "accessible": False,
            "inaccessible_reason": None,
            "host_up": False,
        }
    ]

    verdict = storagehealth.classify_datastore(_store(accessible=False, mounts=mounts), LIMITS)

    assert verdict["healthy"] is None
    assert verdict["findings"] == []


def test_a_limit_on_the_resource_pool_is_inherited_but_the_root_pool_is_not_a_limit() -> None:
    from vsphere_triage import inventory  # noqa: PLC0415

    cluster = vim.ClusterComputeResource("domain-c7")
    root, team, inner = (
        vim.ResourcePool("resgroup-1"),
        vim.ResourcePool("resgroup-2"),
        vim.ResourcePool("resgroup-3"),
    )
    rows = [
        {"moref": "resgroup-1", "name": "Resources", "parent": cluster, "config.cpuAllocation.limit": 90000},
        {"moref": "resgroup-2", "name": "team", "parent": root, "config.cpuAllocation.limit": 4000},
        {
            "moref": "resgroup-3",
            "name": "batch",
            "parent": team,
            "config.cpuAllocation.limit": -1,
            "config.memoryAllocation.limit": 8192,
        },
    ]
    pools = inventory.pool_limits(SimpleNamespace(retrieve=lambda _kind, _paths: rows))

    assert inventory.inherited_pool_limit(pools, inner._moId, "cpu_limit") == (4000, "team")
    assert inventory.inherited_pool_limit(pools, inner._moId, "memory_limit") == (8192, "batch")
    assert inventory.inherited_pool_limit(pools, root._moId, "cpu_limit") == (None, None)


def test_a_vm_in_a_limited_pool_is_listed_as_limited() -> None:
    row = {
        "cpu_limit_mhz": None,
        "memory_limit_mb": None,
        "memory_mb": 4096,
        "cpu_reservation_mhz": None,
        "memory_reservation_mb": None,
        "pool_cpu_limit_mhz": 4000,
        "pool_cpu_limit_set_on": "team",
        "pool_memory_limit_mb": None,
        "pool_memory_limit_set_on": None,
    }

    assert resources._matches(row, "limits")
    assert any("resource pool 'team'" in reason for reason in resources._findings_for(row))


def test_an_expired_session_mid_scan_is_raised_for_the_pool_to_re_login() -> None:
    def expired(**_: object) -> None:
        raise vim.fault.NotAuthenticated

    session = SimpleNamespace(now=lambda: NOW, events=expired)
    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
        }
    )

    with pytest.raises(vim.fault.NotAuthenticated):
        scan.scan_vcenter(session, settings)


def test_windows_commands_follow_the_guests_system_root() -> None:
    root = guestexec.system_root_from(["SystemRoot=D:\\WINDOWS"])
    program, _ = guestexec.guest_program_spec("ver", r"D:\WINDOWS\Temp\o.txt", windows=True, system_root=root)

    assert root == r"D:\WINDOWS"
    assert program == r"D:\WINDOWS\System32\cmd.exe"
    assert (
        guestexec.guest_temp_path("t", windows=True, system_root=root)
        == r"D:\WINDOWS\Temp\vsphere-triage-t.txt"
    )
    assert guestexec.system_root_from(None) == r"C:\Windows"


def test_a_scan_re_judges_a_vm_rebooted_inside_the_guest_from_its_vmware_log() -> None:
    from vsphere_triage.vcenter import DatastoreFile  # noqa: PLC0415

    machine = vm(
        moref="vm-7",
        datacenter="DC0",
        power_on_time=NOW - timedelta(days=3),
        cpu_mhz=5.0,
        tools_running="guestToolsNotRunning",
    )
    set_effective_boot(machine, NOW, reboots={})
    inventory = Inventory("vc-a", NOW, [machine], {}, {}, {}, base_disks_read=True)
    verdicts = {"vm-7": checks.classify(machine, LIMITS)}
    rows = [
        "2026-10-26T02:00:00.000Z In(05) vmx - Powering on the virtual machine",
        "2026-10-29T02:26:00.000Z In(05) vcpu-0 - CPU reset: soft (mode Emulation)",
        "2026-10-29T02:26:01.000Z In(05) vmx - EFI boot device order read",
    ]
    log = "\n".join(rows)
    session = SimpleNamespace(
        retrieve=lambda _kind, _paths, objects: [
            {"moref": "vm-7", "config.files.vmPathName": "[ds-1] web-01/web-01.vmx"} for _ in objects
        ],
        reference=lambda kind, moref: f"{kind}:{moref}",
        read_datastore_file=lambda _dc, path, _max, **_: DatastoreFile(path, log, len(log), False, 200),
    )
    settings = Settings.from_environment(
        {
            "VSPHERE_VCENTERS": '[{"name": "vc-a", "host": "a"}]',
            "VSPHERE_USERNAME": "u",
            "VSPHERE_PASSWORD": "p",
        }
    )
    assert verdicts["vm-7"].state == checks.HUNG

    notes = scan._recheck_in_guest_reboots(session, inventory, verdicts, {}, {}, settings)

    assert machine.boot_source == "vmware_log"
    assert verdicts["vm-7"].state == checks.BOOTING
    assert "1 had rebooted" in notes[0]


def test_a_scan_names_hosts_whose_hardware_sensors_are_red() -> None:
    fleet = [vm(moref=f"vm-{index}", host="esx-1", host_moref="host-1") for index in range(3)]
    result = scan_of(fleet)
    vscan = result.vcenters["vc-a"]
    vscan.inventory.hosts["host-1"] = HostFacts("host-1", "esx-1", None, "connected", False, None, None, None)
    vscan.hardware = {
        "host-1": hostsensors.classify_sensors(
            [
                {"name": "Power Supply 2", "type": "power", "health": "red"},
                {"name": "Fan 1", "health": "green"},
            ]
        )
    }

    summary = scan.summary(result, limit=10)

    assert summary["hosts_with_hardware_problems"][0]["red"] == ["Power Supply 2"]
    assert summary["hosts_with_hardware_problems"][0]["powered_on_vms"] == 3
    assert any("Power Supply 2" in finding for finding in summary["findings"])


def test_red_host_sensors_are_evidence_in_a_diagnosis() -> None:
    machine = vm(cpu_mhz=3600.0)
    result = diagnose.conclude(
        checks.classify(machine, LIMITS),
        vm=machine,
        cpu={"findings": [], "starved": False},
        disk={"findings": [], "slow": False, "datastores": []},
        environment={"signals": []},
        logs={"available": False},
        serial={"available": False},
        console={"available": False},
        host_log={"available": False},
        host_hardware=hostsensors.classify_sensors(
            [{"name": "CPU1 Temp", "type": "temperature", "health": "red"}]
        ),
    )

    hardware = next(cause for cause in result["causes"] if cause["cause"] == diagnose.HOST_HARDWARE)
    assert "CPU1 Temp" in hardware["for"][0]


def test_sensors_are_read_for_many_hosts_in_one_call() -> None:
    calls = []
    sensor = SimpleNamespace(
        name="PSU 1",
        sensorType="power",
        healthState=SimpleNamespace(key="red"),
        currentReading=1,
        unitModifier=0,
    )

    def retrieve(_kind: object, paths: tuple, objects: list) -> list:
        calls.append(objects)
        return [{"moref": ref, hostsensors.SENSOR_PATHS[0]: [sensor]} for ref in objects]

    session = SimpleNamespace(retrieve=retrieve, reference=lambda _kind, moref: moref)

    found = hostsensors.read_sensors(session, ["host-1", "host-2"])

    assert len(calls) == 1
    assert found["host-2"][0]["health"] == "red"


def test_a_device_reset_line_does_not_start_a_new_boot() -> None:
    rows = [
        "2026-10-26T02:00:00.000Z In(05) vmx - Powering on the virtual machine",
        "2026-10-26T02:01:00.000Z In(05) vmx - Tools: Changing running status: 0 => 1.",
        "2026-10-29T02:28:00.000Z In(05) vcpu-1 - AHCI-VMM: sata0:0: Reset request",
        "2026-10-29T02:28:01.000Z In(05) vmx - PVSCSI: scsi0: Bus reset request",
    ]

    timeline = vmlog.boot_timeline(vmlog.parse_lines("\n".join(rows)))

    assert timeline["boot_started"] == datetime(2026, 10, 26, 2, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("log_boot", "expected"),
    [
        (NOW - timedelta(days=3) + timedelta(seconds=5), "power_on"),  # the power-on itself
        (NOW + timedelta(minutes=10), "power_on"),  # a host clock running ahead
        (NOW - timedelta(minutes=4), "vmware_log"),  # a real reboot since
    ],
)
def test_a_log_boot_counts_only_when_it_is_a_later_reboot(log_boot: datetime, expected: str) -> None:
    machine = vm(power_on_time=NOW - timedelta(days=3), tools_running="guestToolsNotRunning")

    set_effective_boot(machine, NOW, reboots={}, log_boot=log_boot)

    assert machine.boot_source == expected


def test_a_caller_reboot_time_wins_over_the_log() -> None:
    machine = vm(power_on_time=NOW - timedelta(days=3))

    set_effective_boot(
        machine, NOW, reboots={}, rebooted_at=NOW - timedelta(minutes=30), log_boot=NOW - timedelta(minutes=4)
    )

    assert machine.boot_source == "reported_reboot"


def test_a_lost_redundant_power_supply_weighs_less_than_a_hot_cpu() -> None:
    def weight_of(sensor: dict) -> int:
        machine = vm(cpu_mhz=3600.0)
        result = diagnose.conclude(
            checks.classify(machine, LIMITS),
            vm=machine,
            cpu={"findings": [], "starved": False},
            disk={"findings": [], "slow": False, "datastores": []},
            environment={"signals": []},
            logs={"available": False},
            serial={"available": False},
            console={"available": False},
            host_log={"available": False},
            host_hardware=hostsensors.classify_sensors([sensor]),
        )
        return next(cause["score"] for cause in result["causes"] if cause["cause"] == diagnose.HOST_HARDWARE)

    assert weight_of({"name": "PS Redundancy", "type": "power", "health": "red"}) == 1
    assert weight_of({"name": "CPU1 Temp", "type": "temperature", "health": "red"}) == 2


def test_a_green_software_components_sensor_is_no_proof_of_hardware_health() -> None:
    verdict = hostsensors.classify_sensors(
        [{"name": "Software Components", "type": "Software Components", "health": "green"}]
    )

    assert verdict["healthy"] is None


def test_a_pool_well_under_its_limit_is_not_a_limit_in_play() -> None:
    from vsphere_triage import inventory  # noqa: PLC0415

    cluster = vim.ClusterComputeResource("domain-c7")
    root = vim.ResourcePool("resgroup-1")
    rows = [
        {"moref": "resgroup-1", "name": "Resources", "parent": cluster},
        {
            "moref": "resgroup-2",
            "name": "tenant",
            "parent": root,
            "config.cpuAllocation.limit": 100000,
            "runtime.cpu.overallUsage": 2000,
        },
        {
            "moref": "resgroup-3",
            "name": "busy",
            "parent": root,
            "config.cpuAllocation.limit": 4000,
            "runtime.cpu.overallUsage": 3900,
        },
    ]
    pools = inventory.pool_limits(SimpleNamespace(retrieve=lambda _kind, _paths: rows))

    assert inventory.inherited_pool_limit(pools, "resgroup-2", "cpu_limit") == (None, None)
    assert inventory.inherited_pool_limit(pools, "resgroup-3", "cpu_limit") == (4000, "busy")


def test_a_task_started_by_an_alarm_or_schedule_names_it() -> None:
    from vsphere_triage.server import _task_started_by  # noqa: PLC0415

    assert _task_started_by(vim.TaskReasonUser(userName="VSPHERE.LOCAL\\ops")) == "VSPHERE.LOCAL\\ops"
    assert _task_started_by(vim.TaskReasonAlarm(alarmName="Host down")) == "alarm: Host down"
    assert _task_started_by(vim.TaskReasonSystem()) == "system"
