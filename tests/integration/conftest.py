"""Two simulated vCenters in Docker, and a server reading them.

The vCenters are built once per session (`scenario.fleet`). vcsim's
performance counters are random, so `perf` is replaced with one that returns
the numbers each scenario needs: an overcommitted host for the CPU case, a
slow datastore for the storage case, healthy everywhere else. Everything else
the server reads (inventory, folders, disks, events, files) comes from vcsim.
"""

from __future__ import annotations

import asyncio
import io
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest
import scenario
from mcp.types import CallToolResult
from PIL import Image

from vsphere_triage.config import Settings
from vsphere_triage.server import build_server
from vsphere_triage.vcenter import PerfSeries, VCenterSession

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime
    from pathlib import Path

    from mcp.server import MCPServer

CORE_MHZ = 2294  # vcsim's hosts: 2 cores at 2294 MHz
HOST_CAPACITY = 2 * CORE_MHZ


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)


@pytest.fixture(scope="session")
def worlds(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[scenario.World, scenario.World]]:
    if not scenario.docker_available():
        pytest.skip("Docker with the vmware/vcsim and vmware/govc images is needed")
    work: Path = tmp_path_factory.mktemp("vcsim")
    a, b = scenario.fleet(work)
    yield a, b
    for world in (a, b):
        scenario.stop(world.container)


@pytest.fixture
def settings(worlds: tuple[scenario.World, scenario.World]) -> Settings:
    a, b = worlds
    vcenters = (
        f'[{{"name": "vc-a", "host": "127.0.0.1", "port": {a.port}, "aliases": ["vca.lab.example"]}},'
        f' {{"name": "vc-b", "host": "localhost", "port": {b.port}}}]'
    )
    return Settings.from_environment(
        {
            "VSPHERE_VCENTERS": vcenters,
            "VSPHERE_USERNAME": "user",
            "VSPHERE_PASSWORD": "pass",
            "VSPHERE_TLS_VERIFY": "0",
            "VSPHERE_ENV_PARENT_HINTS": "environments,projects",
        }
    )


class Plan:
    """What each counter reads, by vCenter, entity and instance. Healthy unless told."""

    def __init__(self, a: scenario.World) -> None:
        self.values: dict[tuple[str, str, str], dict[str, float]] = {}
        # The CPU incident: one host at 120% demand; its stuck VMs wait 30% of the time.
        self.set(a, a.hosts["DC0_C1_H0"], "cpu.demand.average", {"": 1.2 * HOST_CAPACITY})
        self.set(a, a.hosts["DC0_C1_H0"], "cpu.usagemhz.average", {"": 0.99 * HOST_CAPACITY})
        for name in ("web-01", "db-01"):
            moref = a.moref("environments/env-1002", name)
            self.set(a, moref, "cpu.ready.summation", {"": 0.30 * 20_000 * 2})
        # The storage incident: LocalDS_0 slow from the hosts env-1001's clones run on,
        # and so their own disks too. vcsim backs both datastores with one device, so
        # DC0_C0_H2 (app-02, on LocalDS_1) stays healthy or the device would read slow there too.
        for name in ("web-01", "db-01", "app-01"):
            moref = a.moref("environments/env-1001", name)
            self.set(a, moref, "virtualDisk.totalReadLatency.average", {"scsi0:0": 90.0})
            self.set(a, moref, "virtualDisk.totalWriteLatency.average", {"scsi0:0": 160.0})
        for host in ("DC0_C0_H0", "DC0_C0_H1"):
            self.set(
                a,
                a.hosts[host],
                "datastore.totalWriteLatency.average",
                {"LocalDS_0": 180.0, "LocalDS_1": 4.0},
            )
            self.set(
                a, a.hosts[host], "datastore.totalReadLatency.average", {"LocalDS_0": 95.0, "LocalDS_1": 2.0}
            )
            self.set(
                a,
                a.hosts[host],
                "disk.deviceLatency.average",
                {"naa.6000c290000000000000000000000000": 170.0},
            )

    def set(self, world: scenario.World, moref: str, counter: str, instances: dict[str, float]) -> None:
        self.values[(str(world.port), moref, counter)] = instances

    @staticmethod
    def healthy(moref: str, counter: str, vcpus: int) -> dict[str, float]:
        if moref.startswith("host-"):
            return {
                "cpu.demand.average": {"": 0.4 * HOST_CAPACITY},
                "cpu.usagemhz.average": {"": 0.4 * HOST_CAPACITY},
                "datastore.totalWriteLatency.average": {"LocalDS_0": 3.0, "LocalDS_1": 3.0},
                "datastore.totalReadLatency.average": {"LocalDS_0": 2.0, "LocalDS_1": 2.0},
                "datastore.numberReadAveraged.average": {"LocalDS_0": 150.0, "LocalDS_1": 150.0},
                "datastore.numberWriteAveraged.average": {"LocalDS_0": 80.0, "LocalDS_1": 80.0},
                "disk.deviceLatency.average": {"naa.6000c290000000000000000000000000": 2.0},
                "disk.kernelLatency.average": {"naa.6000c290000000000000000000000000": 0.1},
                "disk.queueLatency.average": {"naa.6000c290000000000000000000000000": 0.0},
                "disk.commandsAborted.summation": {"naa.6000c290000000000000000000000000": 0.0},
                "disk.busResets.summation": {"naa.6000c290000000000000000000000000": 0.0},
            }.get(counter, {})
        return {
            "cpu.ready.summation": {"": 0.01 * 20_000 * vcpus},
            "cpu.costop.summation": {"": 0.0},
            "cpu.usagemhz.average": {"": 200.0},
            "virtualDisk.totalReadLatency.average": {"scsi0:0": 2.0},
            "virtualDisk.totalWriteLatency.average": {"scsi0:0": 3.0},
            "virtualDisk.numberReadAveraged.average": {"scsi0:0": 20.0},
            "virtualDisk.numberWriteAveraged.average": {"scsi0:0": 10.0},
        }.get(counter, {})

    def perf(
        self,
        session: VCenterSession,
        entities: list[Any],
        counter_names: list[str],
        *,
        begin: datetime,
        end: datetime,
        instance: str = "*",
    ) -> tuple[dict[str, dict[str, PerfSeries]], list[str]]:
        stamps = []
        moment = begin
        while moment <= end:
            stamps.append(moment)
            moment += timedelta(seconds=20)
        result: dict[str, dict[str, PerfSeries]] = {}
        for entity in entities:
            moref = entity._moId
            for counter in counter_names:
                values = self.values.get((f"{session.vcenter.port}", moref, counter)) or self.healthy(
                    moref, counter, 2
                )
                kept = {key: value for key, value in values.items() if (key == "") == (instance == "")}
                if not kept:
                    continue
                result.setdefault(moref, {})[counter] = PerfSeries(
                    counter=counter,
                    unit="millisecond" if "Latency" in counter or "summation" in counter else "megaHertz",
                    interval_seconds=20,
                    samples={key: [(stamp, value) for stamp in stamps] for key, value in kept.items()},
                )
        return result, []


@pytest.fixture
def plan(worlds: tuple[scenario.World, scenario.World], monkeypatch: pytest.MonkeyPatch) -> Plan:
    controlled = Plan(worlds[0])

    def perf(self: VCenterSession, *args: Any, **kwargs: Any) -> Any:
        return controlled.perf(self, *args, **kwargs)

    monkeypatch.setattr(VCenterSession, "perf", perf)
    return controlled


@pytest.fixture
def server(settings: Settings, plan: Plan) -> Iterator[MCPServer]:
    built = build_server(settings)
    yield built
    built.vcenters.close()


def call(server: MCPServer, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    result = asyncio.run(server.call_tool(name, arguments or {}))
    assert isinstance(result, CallToolResult)
    assert not result.is_error, result.content
    return result.structured_content


def png(colour: tuple[int, int, int], size: tuple[int, int] = (320, 240)) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", size, colour).save(buffer, format="PNG")
    return buffer.getvalue()
