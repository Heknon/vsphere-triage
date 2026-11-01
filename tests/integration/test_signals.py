"""The signals beyond "stuck", and finding environments that have lived too long."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest
from conftest import call
from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError

from vsphere_triage.config import Settings, VCenter
from vsphere_triage.server import build_server

if TYPE_CHECKING:
    from mcp.server import MCPServer


def by_name(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {vm["name"]: vm["verdict"] for vm in result["abnormal_vms"] if vm["folder"] == "env-1004"}


# -- states and flags -------------------------------------------------------------------


def test_a_vm_without_tools_is_not_called_stuck(server: MCPServer) -> None:
    everything = call(server, "scan", {"vcenters": ["vc-a"], "limit": 200})
    only = call(server, "scan", {"vcenters": ["vc-a"], "states": ["no_tools"]})

    assert "notools-01" not in by_name(everything)
    assert [vm["name"] for vm in only["abnormal_vms"]] == ["notools-01"]
    assert only["abnormal_vms"][0]["verdict"]["values"]["tools_status"] == "toolsNotInstalled"
    assert everything["counts_by_state"]["no_tools"] == 1


def test_paused_and_suspended_are_their_own_states(server: MCPServer) -> None:
    result = call(server, "scan", {"vcenters": ["vc-a"], "limit": 200})

    assert by_name(result)["paused-01"]["state"] == "paused"
    assert "susp-01" not in by_name(result)
    assert result["counts_by_state"]["suspended"] == 1


def test_tools_stuck_running_its_startup_scripts_is_said_so(server: MCPServer) -> None:
    result = call(server, "scan", {"vcenters": ["vc-a"], "limit": 200})

    starting = by_name(result)["starting-01"]
    assert starting["state"] == "booted_not_up"
    assert "startup scripts" in starting["reasons"][0]


def test_flags_mark_healthy_vms_that_still_need_a_look(server: MCPServer) -> None:
    result = call(server, "scan", {"vcenters": ["vc-a"], "limit": 200})

    vms = by_name(result)
    assert vms["swap-01"]["state"] == "healthy"
    assert vms["swap-01"]["flags"] == ["memory_reclaimed"]
    assert vms["swap-01"]["values"]["swapped_mb"] == 2048
    assert vms["flaky-01"]["flags"] == ["heartbeat_intermittent"]
    assert vms["alarm-01"]["flags"] == ["vcenter_alarm"]
    alarm = vms["alarm-01"]["values"]["alarms"][0]
    assert alarm["status"] == "red"
    assert alarm["alarm"]
    assert alarm["alarm"] != "alarm-11"  # resolved to its name
    assert result["counts_by_flag"]["memory_reclaimed"] == 1
    assert any("memory_reclaimed" in finding for finding in result["findings"])


def test_a_leftover_vm_is_flagged_long_running(server: MCPServer) -> None:
    result = call(server, "scan", {"states": ["long_running"]})

    assert [(vm["vcenter"], vm["name"]) for vm in result["abnormal_vms"]] == [("vc-a", "left-01")]
    assert result["abnormal_vms"][0]["age_hours"] > 25


def test_memory_reclaim_is_weighed_as_a_cause(server: MCPServer) -> None:
    result = call(
        server,
        "diagnose_vm",
        {"vcenter": "vc-a", "env_id": "env-1004", "vm_name": "swap-01", "console_captures": 0},
    )

    assert result["conclusion"]["causes"][0]["cause"].startswith("memory pressure")
    assert "memory_reclaimed" in result["conclusion"]["flags"]


def test_no_tools_is_explained_in_the_finding(server: MCPServer) -> None:
    result = call(
        server,
        "diagnose_vm",
        {"vcenter": "vc-a", "env_id": "env-1004", "vm_name": "notools-01", "console_captures": 0},
    )

    assert result["machine"]["state"] == "no_tools"
    assert "Tools is not installed" in result["finding"]


def test_a_paused_vm_is_the_cause_of_itself(server: MCPServer) -> None:
    result = call(
        server,
        "diagnose_vm",
        {"vcenter": "vc-a", "env_id": "env-1004", "vm_name": "paused-01", "console_captures": 0},
    )

    assert result["conclusion"]["causes"][0]["cause"] == "the VM is paused"


def test_an_unknown_state_is_refused_with_the_choices(server: MCPServer) -> None:
    # In process the error is raised; an MCP client receives the same words as an error result.
    with pytest.raises(ToolError, match="unknown states or flags") as raised:
        asyncio.run(server.call_tool("scan", {"states": ["sleepy"]}))

    assert not isinstance(raised.value, UnexpectedToolError)
    assert "long_running" in str(raised.value)


def test_an_unreachable_vcenter_is_said_in_words(settings: Settings) -> None:
    broken = settings.model_copy(
        update={"vcenters": (VCenter(name="vc-gone", host="127.0.0.1", port=1),), "timeout_seconds": 5.0}
    )
    server = build_server(broken)

    with pytest.raises(ToolError, match="unreachable") as raised:
        asyncio.run(server.call_tool("diagnose_vm", {"vcenter": "vc-gone", "moref": "vm-1"}))

    assert not isinstance(raised.value, UnexpectedToolError)


# -- environments that have lived too long ---------------------------------------------------


def folders(result: dict[str, Any]) -> list[tuple[str, str]]:
    return [(entry["vcenter"], entry["folder"]) for entry in result["environments"]]


def test_old_environments_are_found_anywhere_oldest_first(server: MCPServer) -> None:
    result = call(server, "find_old_environments", {"older_than_hours": 5})

    assert folders(result) == [
        ("vc-a", "/DC0/vm/environments/env-0999"),
        ("vc-b", "/DC0/vm/projects/env-2001"),
        ("vc-b", "/DC0/vm/projects/team-x/env-3001"),
    ]
    oldest = result["environments"][0]
    assert oldest["age_hours"] > 25
    assert oldest["powered_on"] == 1
    assert oldest["parent"] == "environments"
    two = result["environments"][1]
    assert (two["vms"], two["environment"]) == (2, "env-2001")
    assert two["newest_age_hours"] < two["age_hours"]
    assert "2 of them still have powered-on VMs" in result["findings"]


def test_under_narrows_by_a_segment_at_any_depth(server: MCPServer) -> None:
    result = call(server, "find_old_environments", {"older_than_hours": 5, "under": ["projects/"]})

    assert folders(result) == [
        ("vc-b", "/DC0/vm/projects/env-2001"),
        ("vc-b", "/DC0/vm/projects/team-x/env-3001"),
    ]


def test_under_takes_a_run_of_segments_too(server: MCPServer) -> None:
    result = call(server, "find_old_environments", {"older_than_hours": 5, "under": ["projects/team-x"]})

    assert folders(result) == [("vc-b", "/DC0/vm/projects/team-x/env-3001")]
    assert result["environments"][0]["states"] == {"off": 1}


def test_under_environments_on_one_vcenter(server: MCPServer) -> None:
    result = call(
        server,
        "find_old_environments",
        {"older_than_hours": 1, "under": ["environments"], "vcenters": ["vc-a"]},
    )

    assert folders(result) == [("vc-a", "/DC0/vm/environments/env-0999")]


def test_vms_outside_any_environment_are_marked(server: MCPServer) -> None:
    result = call(server, "find_old_environments", {"older_than_hours": 0, "vcenters": ["vc-a"]})

    root = [entry for entry in result["environments"] if entry["folder"] == "/DC0/vm"]
    assert root
    assert root[0]["root_vm_folder"] is True
    assert all(
        not entry["root_vm_folder"] for entry in result["environments"] if entry["folder"] != "/DC0/vm"
    )


# -- virtual hardware and vCenter health -----------------------------------------------------


def test_get_vm_hardware_lists_the_virtual_devices(server: MCPServer, worlds: tuple[Any, ...]) -> None:
    moref = worlds[0].moref("environments/env-1001", "web-01")

    result = call(server, "get_vm_hardware", {"vcenter": "vc-a", "moref": moref})

    categories = {entry["category"] for entry in result["devices"]}
    assert "ethernet" in categories
    assert "disk" in categories
    assert "findings" in result


def test_check_vcenters_reports_reachability_and_sessions(server: MCPServer) -> None:
    result = call(server, "check_vcenters")

    names = {row["name"] for row in result["vcenters"] if row.get("reachable")}
    assert names == {"vc-a", "vc-b"}
    reachable = next(row for row in result["vcenters"] if row["name"] == "vc-a")
    assert "login_seconds" in reachable
    assert reachable["sessions"]["visible"] in ("all", "own_only")


def test_find_vms_with_and_without_a_sound_card(server: MCPServer) -> None:
    with_sound = call(
        server, "find_vms_by_device", {"device": "sound", "present": True, "vcenters": ["vc-a"]}
    )
    without_sound = call(
        server, "find_vms_by_device", {"device": "sound", "present": False, "vcenters": ["vc-a"]}
    )

    names_with = {vm["name"] for vm in with_sound["matched"]}
    assert "ok-01" in names_with  # the one VM given a sound card
    names_without = {vm["name"] for vm in without_sound["matched"]}
    assert "web-01" in names_without
    assert "ok-01" not in names_without
    # every VM is in exactly one of the two sets
    assert with_sound["matched_total"] + without_sound["matched_total"] >= with_sound["vcenters_read"]["vc-a"]


def test_find_vms_by_device_matches_a_kind_substring(server: MCPServer) -> None:
    result = call(
        server, "find_vms_by_device", {"device": "E1000", "present": True, "vcenters": ["vc-a"], "limit": 5}
    )

    assert result["matched_total"] > 0
    assert all("E1000" in " ".join(vm["kinds"]) for vm in result["matched"])


def test_vcenter_sessions_groups_the_open_sessions(server: MCPServer) -> None:
    result = call(server, "vcenter_sessions", {"vcenter": "vc-a"})

    # The simulator permits the session list; on a locked-down real account this
    # would be visible == "own_only" instead.
    if result.get("visible") == "all":
        assert result["total"] >= 1
        assert isinstance(result["by_client"], dict)
        assert "findings" in result
    else:
        assert result["visible"] == "own_only"


def test_hardware_profile_counts_devices_and_finds_outliers(server: MCPServer) -> None:
    result = call(server, "hardware_profile", {"vcenters": ["vc-a"], "include_templates": True})

    assert result["vms"] > 0
    assert "ethernet" in result["category_counts"]
    assert result["adapter_kinds"]  # at least one NIC type counted
    # ok-01 has a sound card its env-1003 siblings lack, so it is an outlier.
    outlier_names = {o["name"] for o in result["environment_outliers"]}
    assert "ok-01" in outlier_names
    ok = next(o for o in result["environment_outliers"] if o["name"] == "ok-01")
    assert any("Audio" in extra or "Sound" in extra for extra in ok["extra"])


def test_find_vms_by_snapshot_lists_vms_with_snapshots(server: MCPServer) -> None:
    result = call(server, "find_vms_by_snapshot", {"vcenters": ["vc-a"]})

    names = {vm["name"] for vm in result["vms"]}
    assert "ok-01" in names  # the one VM given snapshots
    ok = next(vm for vm in result["vms"] if vm["name"] == "ok-01")
    assert ok["snapshots"] == 2
    # the simulator reports zero sizes, so a size filter excludes it, a count filter keeps it
    by_size = call(server, "find_vms_by_snapshot", {"vcenters": ["vc-a"], "min_total_gb": 1})
    assert by_size["matched_total"] == 0
    by_count = call(server, "find_vms_by_snapshot", {"vcenters": ["vc-a"], "min_count": 2})
    assert "ok-01" in {vm["name"] for vm in by_count["vms"]}


def test_a_vm_with_snapshots_surfaces_them_in_diagnose(server: MCPServer, worlds: tuple[Any, ...]) -> None:
    moref = worlds[0].moref("environments/env-1003", "ok-01")

    result = call(server, "diagnose_vm", {"vcenter": "vc-a", "moref": moref, "console_captures": 0})

    assert result["snapshots"]["count"] == 2


# -- resource limits, host time, datastore health --------------------------------------------


def test_find_resource_limits_finds_capped_vms_and_marks_templates(server: MCPServer) -> None:
    result = call(server, "find_resource_limits", {"vcenters": ["vc-a"]})

    by_name = {vm["name"]: vm for vm in result["vms"]}
    assert "capped-01" in by_name
    assert by_name["capped-01"]["cpu_limit_mhz"] == 600
    assert by_name["capped-01"]["memory_limit_mb"] == 2048
    assert any("mimics starvation" in problem for problem in by_name["capped-01"]["problems"])
    # the template carries a limit and is marked, with the clone-inheritance note.
    template = next((vm for vm in result["vms"] if vm["template"]), None)
    assert template is not None
    assert template["cpu_limit_mhz"] == 500
    assert any("are templates" in finding for finding in result["findings"])


def test_resource_limits_can_exclude_templates(server: MCPServer) -> None:
    result = call(server, "find_resource_limits", {"vcenters": ["vc-a"], "include_templates": False})

    assert all(not vm["template"] for vm in result["vms"])
    assert "capped-01" in {vm["name"] for vm in result["vms"]}


def test_check_host_time_returns_a_row_per_host(server: MCPServer) -> None:
    result = call(server, "check_host_time", {"vcenters": ["vc-a"], "measure_skew": True})

    assert result["hosts_total"] >= 1
    # Every row carries the NTP and skew fields, whatever the simulator populates.
    row = result["hosts"][0]
    assert "ntp_servers" in row
    assert "skew_seconds" in row
    assert "time_service_running" in row


def test_check_datastores_reports_each_store_and_marks_template_datastores(server: MCPServer) -> None:
    result = call(server, "check_datastores", {"vcenters": ["vc-a"]})

    assert result["datastores_total"] >= 1
    row = result["datastores"][0]
    assert "free_percent" in row
    assert "overprovision_ratio" in row
    assert "hosts_mounting" in row
    # LocalDS_0 holds the template's base disk, so it is marked as a clone-root datastore.
    assert any(store["holds_template"] for store in result["datastores"])


# -- template (base-disk) rollups: broad issues named by template ----------------------------


def test_snapshot_findings_roll_up_to_the_template_even_when_clones_are_renamed(
    server: MCPServer,
) -> None:
    result = call(server, "find_vms_by_snapshot", {"vcenters": ["vc-a"], "min_count": 2})

    # Every VM row names the base disk (its template).
    assert all("base_disk" in vm for vm in result["vms"])
    # The two differently-named Cool-Win clones roll up under their shared base disk.
    cool = next(t for t in result["by_template"] if "coolwin" in (t["base_disk"] or ""))
    assert cool["clones"] == 2
    assert set(cool["names"]) == {"coolwin-blue", "coolwin-green"}
    assert any("template-wide" in finding for finding in result["findings"])
    # vcsim reports no snapshot file sizes: said as unknown, not as 0 GB.
    assert all(vm["total_gb"] is None for vm in result["vms"])
    assert "no size reported" in result["findings"][0]
    assert not any("0.0 GB" in finding for finding in result["findings"])


def test_resource_limits_carry_the_template_base_disk(server: MCPServer) -> None:
    result = call(server, "find_resource_limits", {"vcenters": ["vc-a"]})

    capped = next(vm for vm in result["vms"] if vm["name"] == "capped-01")
    assert "coolwin" in (capped["base_disk"] or "")
    # the rollup names the template the capped clone came from
    assert any("coolwin" in (t["base_disk"] or "") for t in result["by_template"])


# -- connection failures past the session count ---------------------------------------------


def test_a_vcenter_at_its_configured_session_cap_says_so(server: MCPServer) -> None:
    import scenario  # noqa: PLC0415 - the fixture's own module

    result = call(server, "check_vcenters")

    rows = {row["name"]: row for row in result["vcenters"]}
    capped = rows["vc-b"]["sessions"]
    assert capped["session_limit"] == scenario.SESSION_CAP
    assert capped["total"] >= scenario.SESSION_CAP
    assert "at its session limit" in capped["limit_finding"]
    assert any(finding.startswith("vc-b: ") and "session limit" in finding for finding in result["findings"])
    # vc-a has no cap set: the default applies, and the result says it cannot read it.
    assert rows["vc-a"]["sessions"]["session_limit"] is None
    assert "the API cannot read it" in rows["vc-a"]["sessions"]["session_limit_note"]


def test_the_session_breakdown_names_the_leaking_client_against_the_cap(server: MCPServer) -> None:
    import scenario  # noqa: PLC0415 - the fixture's own module

    result = call(server, "vcenter_sessions", {"vcenter": "vc-b"})

    assert result["visible"] == "all"
    assert result["session_limit"] == scenario.SESSION_CAP
    assert result["by_user"]["report"] == scenario.LEAKED_SESSIONS
    assert "configured cap of 10" in result["findings"][0]
    assert result["connection_settings"]["config.vmacore.soap.maxSessionCount"] == "10"
    assert any(client.startswith("report @") for client in result["calls_by_client"])


def test_hosts_with_no_address_to_probe_are_said_not_tested(server: MCPServer) -> None:
    result = call(server, "check_host_tls", {"vcenters": ["vc-a"]})

    # vcsim's hosts are named DC0_C0_H0 and the like (no DNS has them), with vmk0 at 0.0.0.0.
    assert result["hosts_probed"] >= 4
    assert result["by_outcome"] == {"no_address_to_probe": result["hosts_probed"]}
    assert result["findings"][0].startswith(f"no host ({result['hosts_probed']}) could be probed")
    assert "not evidence the path is broken" in result["findings"][0]


def test_a_handshake_with_the_simulator_is_judged_by_trust(worlds: tuple[Any, Any]) -> None:
    from vsphere_triage import hosttls  # noqa: PLC0415

    # The simulator's own TLS endpoint stands in for a host: self-signed, so not trusted.
    port = worlds[0].port
    verified = asyncio.run(hosttls.probe("127.0.0.1", Settings(), port=port))
    unverified = asyncio.run(hosttls.probe("127.0.0.1", Settings(tls_verify=False), port=port))

    assert verified["outcome"] in (hosttls.UNTRUSTED, hosttls.NAME_MISMATCH)
    assert unverified["outcome"] == hosttls.OK


def test_a_host_log_sweep_the_simulator_cannot_answer_is_not_called_clean(server: MCPServer) -> None:
    result = call(server, "search_host_logs", {"vcenters": ["vc-a"]})

    assert result["hosts_read"] == 0
    assert result["unread"]
    assert "not evidence there are none" in result["findings"][0]


def test_vcenters_own_log_the_simulator_lacks_is_reported(server: MCPServer) -> None:
    result = call(server, "read_vcenter_log", {"vcenter": "vc-a"})

    assert result["available"] is False
    assert "QueryDescriptions" in result["reason"]


def test_an_appliance_without_the_rest_api_is_said_in_words(server: MCPServer) -> None:
    with pytest.raises(ToolError, match="appliance REST API"):
        asyncio.run(server.call_tool("vcenter_appliance_health", {"vcenter": "vc-a"}))


# -- mass Tools errors ---------------------------------------------------------------------


def test_tools_trouble_is_lined_up_per_host_with_cpu_and_creation(server: MCPServer) -> None:
    result = call(server, "correlate_hosts", {"vcenters": ["vc-a"], "minutes": 60})

    hosts = {row["host"]: row for row in result["hosts"]}
    # The overcommitted host from the CPU scenario, with its two busy env-1002 VMs.
    assert hosts["DC0_C1_H0"]["overcommitted"] is True
    assert hosts["DC0_C1_H0"]["tools_trouble"] >= 2
    # env-1001's three clones hung on slow storage sit on hosts that are not overcommitted.
    assert hosts["DC0_C0_H0"]["overcommitted"] is False
    assert hosts["DC0_C0_H0"]["tools_trouble"] >= 2
    assert any("host CPU is not the common factor" in finding for finding in result["findings"])
    # Every VM was created and powered on inside the hour: the burst is visible.
    assert sum(row["powered_on_in_window"] for row in result["hosts"]) >= 10
    # vcsim has no host logs: said, not read as "no failures".
    assert any("no hostd log could be read" in note for note in result["notes"])
