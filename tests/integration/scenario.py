"""Two simulated vCenters that look like the fleet: short-lived environments, linked clones, stuck VMs.

vcsim (VMware's govmomi simulator, the `vmware/vcsim` image) speaks the same
SOAP API as vCenter. It cannot be told that a VM booted 25 minutes ago, uses
30 MHz and has a pending question while it runs, so each vCenter is built in
three steps:

1. a builder vcsim, driven with pyVmomi: folders, linked clones on chosen
   hosts and datastores, Windows guest ids, serial ports writing to files;
2. its inventory saved with `govc object.save`, then edited: boot times, CPU
   use, Tools state, heartbeat, pending questions, linked-clone parent disks;
3. a fresh vcsim started with `-load` on the edited inventory, then given
   `vmware.log` and serial files over `/folder` and events over `PostEvent`.

These writes are the fixture building its world. The server under test only
ever reads, and the test proves it.

What vcsim cannot simulate at all is said in the tests that need it: its
performance counters are random (so CPU and storage numbers are supplied by a
fake `perf`), and it has no console `/screen` endpoint and no host logs.
"""

from __future__ import annotations

import shutil
import ssl
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx
from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

if TYPE_CHECKING:
    from pathlib import Path

VCSIM_IMAGE = "vmware/vcsim:v0.52.0"
GOVC_IMAGE = "vmware/govc:v0.52.0"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
WINDOWS = ("windows9_64Guest", "Microsoft Windows 10 (64-bit)", "windowsGuest")
WINDOWS_7 = ("windows7_64Guest", "Microsoft Windows 7 (64-bit)", "windowsGuest")
LINUX = ("rhel8_64Guest", "Red Hat Enterprise Linux 8 (64-bit)", "linuxGuest")


def docker_available() -> bool:
    """Whether a Docker daemon answers and both images are present or pullable."""
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "info"], check=True, capture_output=True, timeout=20)
        for image in (VCSIM_IMAGE, GOVC_IMAGE):
            present = subprocess.run(["docker", "image", "inspect", image], capture_output=True, check=False)
            if present.returncode != 0:
                subprocess.run(["docker", "pull", "-q", image], check=True, capture_output=True, timeout=600)
    except (subprocess.SubprocessError, OSError):
        return False
    return True


def start_vcsim(name: str, *arguments: str, mount: Path | None = None) -> int:
    """Start a vcsim container on a random loopback port and wait for it to answer."""
    command = ["docker", "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::8989"]
    if mount is not None:
        command += ["-v", f"{mount}:/model:ro"]
    command += [VCSIM_IMAGE, "-l", "0.0.0.0:8989", "-api-version", "8.0.2.0", *arguments]
    subprocess.run(command, check=True, capture_output=True)
    mapped = subprocess.run(["docker", "port", name, "8989"], check=True, capture_output=True, text=True)
    port = int(mapped.stdout.splitlines()[0].rsplit(":", 1)[1])
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            httpx.get(f"https://127.0.0.1:{port}/about", verify=False, timeout=2)  # noqa: S501 - the simulator
        except httpx.HTTPError:
            time.sleep(0.3)
        else:
            return port
    logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True, check=False)
    msg = f"vcsim {name} did not start: {logs.stdout[-2000:]}{logs.stderr[-2000:]}"
    raise RuntimeError(msg)


def stop(name: str) -> None:
    """Remove a container, if it exists."""
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


def save_model(builder: str, directory: Path) -> None:
    """`govc object.save` the builder's inventory into `directory`."""
    directory.parent.mkdir(parents=True, exist_ok=True)
    directory.parent.chmod(0o777)
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            f"container:{builder}",
            "-e",
            "GOVC_URL=https://user:pass@127.0.0.1:8989/sdk",
            "-e",
            "GOVC_INSECURE=1",
            "-v",
            f"{directory.parent}:/out",
            "--entrypoint",
            "/govc",
            GOVC_IMAGE,
            "object.save",
            "-d",
            f"/out/{directory.name}",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(["chmod", "-R", "a+rwX", str(directory)], check=False)


def wait(task: Any) -> Any:
    """Wait for a vSphere task (pyVim's helper trips over vcsim's task names)."""
    while task.info.state in ("queued", "running"):
        time.sleep(0.05)
    if task.info.state != "success":
        raise RuntimeError(task.info.error)
    return task.info.result


@dataclass
class Machine:
    """One VM to build, and what it should look like once loaded."""

    name: str
    folder: str
    host: str
    datastore: str
    guest: tuple[str, str, str] = WINDOWS
    vcpus: int = 2
    powered_on: bool = True
    booted_minutes_ago: float | None = 25.0
    cpu_mhz: int = 30
    tools: str = "guestToolsNotRunning"
    heartbeat: str = "gray"
    question: str | None = None
    base_disk: str | None = None
    serial: bool = False
    sound: bool = False
    snapshots: int = 0
    template: bool = False
    cpu_limit_mhz: int | None = None
    mem_size_mb: int | None = None
    mem_limit_mb: int | None = None
    vmware_log: str | None = None
    previous_log: str | None = None
    serial_text: str | None = None
    resets: int = 0
    tools_installed: bool = True
    paused: bool = False
    suspended: bool = False
    ballooned_mb: int = 0
    swapped_mb: int = 0
    alarm: str | None = None
    created_hours_ago: float = 0.5
    moref: str = ""


@dataclass
class World:
    """One built and loaded vCenter."""

    name: str
    port: int
    container: str
    machines: dict[str, Machine] = field(default_factory=dict)
    hosts: dict[str, str] = field(default_factory=dict)
    datastores: dict[str, str] = field(default_factory=dict)

    def moref(self, folder: str, name: str) -> str:
        """The moref of the VM `name` in folder `folder`."""
        return self.machines[f"{folder}/{name}"].moref


def connect(port: int) -> Any:
    """A raw (unguarded) pyVmomi session: the fixture's own, never the server's."""
    return SmartConnect(
        host="127.0.0.1",
        port=port,
        user="user",
        pwd="pass",
        sslContext=ssl._create_unverified_context(),  # noqa: S323
    )


def build(container: str, folders: list[str], machines: list[Machine], *, work: Path) -> World:  # noqa: PLR0912 - one fixture build
    """Build, save, edit and load one vCenter. Returns the loaded world."""
    builder = f"{container}-builder"
    stop(builder)
    stop(container)
    port = start_vcsim(builder, "-cluster", "2", "-host", "3", "-ds", "2", "-autostart=false")
    service = connect(port)
    try:
        content = service.content
        datacenter = content.rootFolder.childEntity[0]
        view = content.viewManager.CreateContainerView
        hosts = {host.name: host for host in view(content.rootFolder, [vim.HostSystem], True).view}
        stores = {store.name: store for store in view(content.rootFolder, [vim.Datastore], True).view}
        seed = next(
            vm
            for vm in view(content.rootFolder, [vim.VirtualMachine], True).view
            if vm.name == "DC0_C0_RP0_VM0"
        )
        made: dict[str, Any] = {}
        for path in folders:
            parent = datacenter.vmFolder
            for part in path.split("/"):
                existing = next(
                    (
                        child
                        for child in parent.childEntity
                        if isinstance(child, vim.Folder) and child.name == part
                    ),
                    None,
                )
                parent = existing or parent.CreateFolder(part)
            made[path] = parent
        for machine in machines:
            host = hosts[machine.host]
            spec = vim.vm.CloneSpec(
                location=vim.vm.RelocateSpec(
                    host=host, pool=host.parent.resourcePool, datastore=stores[machine.datastore]
                ),
                powerOn=False,
            )
            vm = wait(seed.CloneVM_Task(folder=made[machine.folder], name=machine.name, spec=spec))
            changes = []
            if machine.serial:
                folder = vm.config.files.logDirectory
                changes.append(
                    vim.vm.device.VirtualDeviceSpec(
                        operation="add",
                        device=vim.vm.device.VirtualSerialPort(
                            key=-1,
                            backing=vim.vm.device.VirtualSerialPort.FileBackingInfo(
                                fileName=f"{folder}/serial.log"
                            ),
                            yieldOnPoll=True,
                        ),
                    )
                )
            if machine.sound:
                changes.append(
                    vim.vm.device.VirtualDeviceSpec(
                        operation="add", device=vim.vm.device.VirtualHdAudioCard(key=-1)
                    )
                )
            spec_kwargs: dict[str, Any] = {
                "guestId": machine.guest[0],
                "numCPUs": machine.vcpus,
                "deviceChange": changes,
            }
            if machine.mem_size_mb is not None:
                spec_kwargs["memoryMB"] = machine.mem_size_mb
            if machine.cpu_limit_mhz is not None:
                spec_kwargs["cpuAllocation"] = vim.ResourceAllocationInfo(limit=machine.cpu_limit_mhz)
            if machine.mem_limit_mb is not None:
                spec_kwargs["memoryAllocation"] = vim.ResourceAllocationInfo(limit=machine.mem_limit_mb)
            wait(vm.ReconfigVM_Task(vim.vm.ConfigSpec(**spec_kwargs)))
            for index in range(machine.snapshots):
                wait(vm.CreateSnapshot_Task(f"snap{index + 1}", "", memory=False, quiesce=False))
            machine.moref = vm._moId
        world_hosts = {name: host._moId for name, host in hosts.items()}
        world_stores = {name: store._moId for name, store in stores.items()}
        for seed_vm in view(content.rootFolder, [vim.VirtualMachine], True).view:
            if seed_vm.name.startswith("DC0_") and seed_vm.runtime.powerState == "poweredOn":
                wait(seed_vm.PowerOffVM_Task())
    finally:
        Disconnect(service)
    model = work / container
    save_model(builder, model)
    stop(builder)
    for machine in machines:
        edit(model, machine)
    port = start_vcsim(container, "-load", "/model", mount=model)
    world = World(name=container, port=port, container=container, hosts=world_hosts, datastores=world_stores)
    world.machines = {f"{machine.folder}/{machine.name}": machine for machine in machines}
    furnish(world)
    return world


# -- editing a saved inventory --------------------------------------------------


def _propset(root: ET.Element, name: str) -> ET.Element | None:
    for propset in root.findall("propSet"):
        if propset.findtext("name") == name:
            return propset.find("val")
    return None


def _child(parent: ET.Element, tag: str, text: str | None = None) -> ET.Element:
    element = parent.find(tag)
    if element is None:
        element = ET.SubElement(parent, tag)
    if text is not None:
        element.text = text
    return element


def _stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def edit(model: Path, machine: Machine) -> None:  # noqa: PLR0912 - one saved-VM edit
    """Give one saved VM the runtime state it should be loaded with."""
    path = next(model.glob(f"*-VirtualMachine-{machine.moref}.xml"))
    tree = ET.parse(path)  # noqa: S314 - our own file
    root = tree.getroot()
    now = datetime.now(UTC)
    power = "suspended" if machine.suspended else "poweredOn" if machine.powered_on else "poweredOff"
    runtime = _propset(root, "runtime")
    summary = _propset(root, "summary")
    guest = _propset(root, "guest")
    config = _propset(root, "config")
    assert runtime is not None and summary is not None and guest is not None and config is not None  # noqa: PT018
    summary_runtime = summary.find("runtime")
    assert summary_runtime is not None
    for element in (runtime, summary_runtime):
        _child(element, "powerState", power)
        for old in element.findall("bootTime"):
            element.remove(old)
        if machine.powered_on and machine.booted_minutes_ago is not None:
            _child(element, "bootTime", _stamp(now - timedelta(minutes=machine.booted_minutes_ago)))
    if machine.question:
        question = ET.SubElement(runtime, "question")
        _child(question, "id", "question-1")
        _child(question, "text", machine.question)
        choice = ET.SubElement(question, "choice")
        for key, label in (("0", "Cancel"), ("1", "I Moved It"), ("2", "I Copied It")):
            info = ET.SubElement(choice, "choiceInfo")
            info.set(f"{{{XSI}}}type", "ElementDescription")
            _child(info, "label", label)
            _child(info, "summary", label)
            _child(info, "key", key)
        _child(choice, "defaultIndex", "2")
    quick = _child(summary, "quickStats")
    _child(quick, "overallCpuUsage", str(machine.cpu_mhz if machine.powered_on else 0))
    _child(quick, "guestHeartbeatStatus", machine.heartbeat)
    _child(quick, "balloonedMemory", str(machine.ballooned_mb))
    _child(quick, "swappedMemory", str(machine.swapped_mb))
    if machine.paused:
        _child(runtime, "paused", "true")
    running = machine.tools if machine.powered_on else "guestToolsNotRunning"
    _child(guest, "toolsRunningStatus", running)
    if not machine.tools_installed:
        _child(guest, "toolsStatus", "toolsNotInstalled")
    else:
        _child(guest, "toolsStatus", "toolsOk" if running == "guestToolsRunning" else "toolsNotRunning")
    _child(config, "createDate", _stamp(now - timedelta(hours=machine.created_hours_ago)))
    if machine.alarm:
        alarms = _propset(root, "triggeredAlarmState")
        assert alarms is not None
        state = ET.SubElement(alarms, "AlarmState")
        _child(state, "key", f"{machine.alarm}.{machine.moref}")
        entity = ET.SubElement(state, "entity")
        entity.set("type", "VirtualMachine")
        entity.text = machine.moref
        alarm = ET.SubElement(state, "alarm")
        alarm.set("type", "Alarm")
        alarm.text = machine.alarm
        _child(state, "overallStatus", "red")
        _child(state, "time", _stamp(now - timedelta(minutes=12)))
        _child(state, "acknowledged", "false")
    _child(guest, "guestFamily", machine.guest[2])
    _child(config, "guestFullName", machine.guest[1])
    if machine.template:
        _child(config, "template", "true")
    if machine.base_disk:
        for backing in root.iter("backing"):
            if (
                backing.get(f"{{{XSI}}}type") == "VirtualDiskFlatVer2BackingInfo"
                and backing.find("parent") is None
            ):
                parent = ET.SubElement(backing, "parent")
                _child(parent, "fileName", machine.base_disk)
                datastore = ET.SubElement(parent, "datastore")
                datastore.set("type", "Datastore")
                datastore.text = (backing.findtext("datastore") or "").strip()
                _child(parent, "diskMode", "persistent")
    tree.write(path)


# -- furnishing the loaded vCenter ----------------------------------------------


def furnish(world: World) -> None:
    """Put each VM's logs and serial file on its datastore, and post its events."""
    service = connect(world.port)
    try:
        content = service.content
        cookie = service._stub.cookie.split(";", 1)[0]
        client = httpx.Client(verify=False, headers={"Cookie": cookie}, timeout=10)  # noqa: S501
        for machine in world.machines.values():
            vm = vim.VirtualMachine(machine.moref, service._stub)
            folder = vm.config.files.logDirectory
            datastore, inside = folder[1:].split("]", 1)
            files = {
                "vmware.log": machine.vmware_log,
                "vmware-1.log": machine.previous_log,
                "serial.log": machine.serial_text,
            }
            for name, text in files.items():
                if text is None:
                    continue
                response = client.put(
                    f"https://127.0.0.1:{world.port}/folder/{inside.strip()}/{name}",
                    params={"dcPath": "DC0", "dsName": datastore.strip()},
                    content=text.encode(),
                )
                response.raise_for_status()
            for _ in range(machine.resets):
                event = vim.event.VmResettingEvent(
                    vm=vim.event.VmEventArgument(vm=vm, name=machine.name),
                    host=vim.event.HostEventArgument(
                        host=vim.HostSystem(world.hosts[machine.host], service._stub),
                        name=machine.host,
                    ),
                    createdTime=service.CurrentTime(),
                    userName="",
                    key=0,
                    chainId=0,
                    fullFormattedMessage=f"{machine.name} on {machine.host} is reset",
                )
                content.eventManager.PostEvent(event)
        client.close()
    finally:
        Disconnect(service)


# -- logs, written the way the VMX writes them ----------------------------------


def log_lines(boot: datetime, steps: list[tuple[float, str, str]]) -> str:
    """vmware.log text in the ESXi 7+ format: (seconds after boot, thread, message)."""
    return "".join(
        f"{_stamp_ms(boot + timedelta(seconds=offset))} In(05) {thread} - {message}\n"
        for offset, thread, message in steps
    )


def old_log_lines(boot: datetime, steps: list[tuple[float, str, str]]) -> str:
    """vmware.log text in the ESXi 6 format."""
    return "".join(
        f"{_stamp_ms(boot + timedelta(seconds=offset))}| {thread}| I125: {message}\n"
        for offset, thread, message in steps
    )


def _stamp_ms(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


HUNG_IN_FIRMWARE = [
    (0, "vmx", "Transitioned vmx/execState/val to poweredOn"),
    (1, "vmx", "Powering on mks"),
    (2, "vcpu-0", "EFI ROM: boot order: Windows Boot Manager"),
    (3, "vcpu-0", "EFI: Boot device found, loading Windows Boot Manager"),
]
DRIVERS_THEN_NOTHING = [
    (0, "vmx", "Transitioned vmx/execState/val to poweredOn"),
    (2, "vcpu-0", "EFI ROM: boot order: Windows Boot Manager"),
    (20, "vmx", "HBACommon: First write on scsi0:0.fileName='disk.vmdk'"),
    (95, "vmx", "VMXNET3 user: Ethernet0 Driver Info: version = 16846848 gosBits = 2"),
    (110, "mks", "SVGA: Guest resolution changed to 1024x768"),
]
BOOTED_WITH_TOOLS = [
    (0, "vmx", "Transitioned vmx/execState/val to poweredOn"),
    (2, "vcpu-0", "EFI ROM: boot order: Windows Boot Manager"),
    (15, "vmx", "HBACommon: First write on scsi0:0.fileName='disk.vmdk'"),
    (40, "vmx", "VMXNET3 user: Ethernet0 Driver Info: version = 16846848"),
    (70, "vmx", "ToolsSetVersion: Tools version 12352 (current)"),
    (71, "vmx", "GuestRpc: Channel 0 reinitialized."),
]
BOOT_LOOP = [
    (0, "vmx", "Transitioned vmx/execState/val to poweredOn"),
    (30, "vcpu-0", "Guest-initiated reset"),
    (60, "vcpu-0", "Guest-initiated reset"),
    (90, "vcpu-0", "Guest-initiated reset"),
    (92, "vcpu-0", "EFI ROM: boot order: Windows Boot Manager"),
]
EMS_STOP = (
    "Computer is booting, SAC started and initialized.\r\n"
    'Use the "ch -?" command for information about using channels.\r\n'
    "SAC>\r\n"
    "*** STOP: 0x0000007A (0xFFFFF6FC40009B88, 0xFFFFFFFFC000000E, "
    "0x00000000A4BFB860, 0xFFFFF88001371000)\r\n"
    "KERNEL_DATA_INPAGE_ERROR\r\n"
)
LINUX_SERIAL = (
    "[    3.112] Run /init as init process\n"
    "[  125.400] watchdog: BUG: soft lockup - CPU#1 stuck for 23s! [systemd-udevd:211]\n"
    "[  190.002] INFO: task jbd2/sda1-8:302 blocked for more than 120 seconds.\n"
)


def fleet(work: Path) -> tuple[World, World]:
    """The two vCenters the integration tests run against."""
    now = datetime.now(UTC)
    base_a = "[LocalDS_0] base-win10/base-win10.vmdk"
    base_b = "[LocalDS_1] base-win7/base-win7.vmdk"
    a_machines = [
        # env-1004: one of each signal beyond "stuck", on a host of its own.
        Machine(
            "notools-01",
            "environments/env-1004",
            "DC0_C1_H1",
            "LocalDS_1",
            tools_installed=False,
            cpu_mhz=600,
        ),
        Machine("paused-01", "environments/env-1004", "DC0_C1_H1", "LocalDS_1", paused=True),
        Machine("susp-01", "environments/env-1004", "DC0_C1_H1", "LocalDS_1", suspended=True),
        Machine(
            "starting-01",
            "environments/env-1004",
            "DC0_C1_H1",
            "LocalDS_1",
            tools="guestToolsExecutingScripts",
            cpu_mhz=1000,
        ),
        Machine(
            "swap-01",
            "environments/env-1004",
            "DC0_C1_H1",
            "LocalDS_1",
            tools="guestToolsRunning",
            heartbeat="green",
            cpu_mhz=900,
            ballooned_mb=512,
            swapped_mb=2048,
        ),
        Machine(
            "alarm-01",
            "environments/env-1004",
            "DC0_C1_H1",
            "LocalDS_1",
            tools="guestToolsRunning",
            heartbeat="green",
            cpu_mhz=300,
            alarm="alarm-11",
        ),
        Machine(
            "flaky-01",
            "environments/env-1004",
            "DC0_C1_H1",
            "LocalDS_1",
            tools="guestToolsRunning",
            heartbeat="yellow",
            cpu_mhz=300,
        ),
        # env-0999: left behind, powered on, a day old.
        Machine(
            "left-01",
            "environments/env-0999",
            "DC0_H0",
            "LocalDS_0",
            tools="guestToolsRunning",
            heartbeat="green",
            cpu_mhz=200,
            created_hours_ago=26,
        ),
        # env-1001: linked clones of one base disk on LocalDS_0, three stuck. A storage storm.
        Machine(
            "web-01",
            "environments/env-1001",
            "DC0_C0_H0",
            "LocalDS_0",
            base_disk=base_a,
            vmware_log=log_lines(now - timedelta(minutes=25), HUNG_IN_FIRMWARE),
            previous_log=log_lines(now - timedelta(hours=3), BOOTED_WITH_TOOLS),
        ),
        Machine(
            "db-01",
            "environments/env-1001",
            "DC0_C0_H1",
            "LocalDS_0",
            base_disk=base_a,
            vmware_log=log_lines(now - timedelta(minutes=24), HUNG_IN_FIRMWARE),
        ),
        Machine("app-01", "environments/env-1001", "DC0_C0_H0", "LocalDS_0", base_disk=base_a),
        Machine(
            "app-02",
            "environments/env-1001",
            "DC0_C0_H2",
            "LocalDS_1",
            base_disk=base_b,
            tools="guestToolsRunning",
            heartbeat="green",
            cpu_mhz=300,
        ),
        # env-1002: two VMs busy on one overcommitted host, one healthy elsewhere. CPU starvation.
        # Its web-01 shares a name with env-1001's: the name means nothing outside its folder.
        Machine(
            "web-01",
            "environments/env-1002",
            "DC0_C1_H0",
            "LocalDS_1",
            base_disk=base_b,
            cpu_mhz=4100,
            vmware_log=old_log_lines(now - timedelta(minutes=20), DRIVERS_THEN_NOTHING),
        ),
        Machine("db-01", "environments/env-1002", "DC0_C1_H0", "LocalDS_1", base_disk=base_b, cpu_mhz=3900),
        Machine(
            "app-01",
            "environments/env-1002",
            "DC0_C1_H1",
            "LocalDS_1",
            base_disk=base_b,
            tools="guestToolsRunning",
            heartbeat="green",
            cpu_mhz=500,
        ),
        # env-1003: one of each other kind.
        Machine(
            "asks-01",
            "environments/env-1003",
            "DC0_C1_H2",
            "LocalDS_1",
            question="This virtual machine might have been moved or copied.",
        ),
        Machine("fresh-01", "environments/env-1003", "DC0_C1_H2", "LocalDS_1", booted_minutes_ago=3),
        Machine(
            "bsod-01",
            "environments/env-1003",
            "DC0_C1_H2",
            "LocalDS_1",
            guest=WINDOWS_7,
            cpu_mhz=10,
            serial=True,
            serial_text=EMS_STOP,
            vmware_log=log_lines(now - timedelta(minutes=30), DRIVERS_THEN_NOTHING),
        ),
        Machine(
            "loop-01",
            "environments/env-1003",
            "DC0_C1_H2",
            "LocalDS_1",
            booted_minutes_ago=1,
            resets=4,
            vmware_log=log_lines(now - timedelta(minutes=2), BOOT_LOOP),
        ),
        Machine(
            "ok-01",
            "environments/env-1003",
            "DC0_C1_H2",
            "LocalDS_1",
            serial=True,
            serial_text="",
            sound=True,
            snapshots=2,
            tools="guestToolsRunning",
            heartbeat="green",
            cpu_mhz=200,
        ),
        Machine(
            "lnx-01",
            "environments/env-1003",
            "DC0_C1_H2",
            "LocalDS_1",
            guest=LINUX,
            serial=True,
            serial_text=LINUX_SERIAL,
            cpu_mhz=2200,
            vcpus=1,
        ),
        Machine("off-01", "environments/env-1003", "DC0_C1_H2", "LocalDS_1", powered_on=False),
        # env-1005: a healthy VM throttled by a configured CPU limit and a memory limit
        # below its RAM — looks starved/pressured but is config, not the host. A clone of
        # the Cool-Win template, so the limit traces back to that template.
        Machine(
            "capped-01",
            "environments/env-1005",
            "DC0_C0_H0",
            "LocalDS_0",
            base_disk="[LocalDS_0] tmpl-coolwin/tmpl-coolwin.vmdk",
            tools="guestToolsRunning",
            heartbeat="green",
            cpu_mhz=400,
            cpu_limit_mhz=600,
            mem_size_mb=8192,
            mem_limit_mb=2048,
        ),
        # env-1006: two differently-named clones of ONE template, each carrying snapshots —
        # the template-wide snapshot case. Their shared base disk names the template.
        Machine(
            "coolwin-blue",
            "environments/env-1006",
            "DC0_C0_H0",
            "LocalDS_0",
            base_disk="[LocalDS_0] tmpl-coolwin/tmpl-coolwin.vmdk",
            snapshots=2,
            tools="guestToolsRunning",
            heartbeat="green",
            cpu_mhz=200,
        ),
        Machine(
            "coolwin-green",
            "environments/env-1006",
            "DC0_C0_H1",
            "LocalDS_0",
            base_disk="[LocalDS_0] tmpl-coolwin/tmpl-coolwin.vmdk",
            snapshots=2,
            tools="guestToolsRunning",
            heartbeat="green",
            cpu_mhz=200,
        ),
        # The template its linked clones come from, carrying a CPU limit every clone inherits.
        Machine(
            "tmpl-win10",
            "templates",
            "DC0_C0_H0",
            "LocalDS_0",
            powered_on=False,
            template=True,
            cpu_limit_mhz=500,
        ),
    ]
    b_machines = [
        Machine(
            "p-01",
            "projects/env-2001",
            "DC0_C0_H0",
            "LocalDS_0",
            tools="guestToolsRunning",
            heartbeat="green",
            cpu_mhz=400,
            created_hours_ago=7,
        ),
        Machine(
            "p-02",
            "projects/env-2001",
            "DC0_C0_H1",
            "LocalDS_0",
            tools="guestToolsRunning",
            heartbeat="green",
            cpu_mhz=400,
            created_hours_ago=6.5,
        ),
        Machine(
            "p-01",
            "projects/env-20015",
            "DC0_C0_H1",
            "LocalDS_1",
            tools="guestToolsRunning",
            heartbeat="green",
            cpu_mhz=400,
            created_hours_ago=2,
        ),
        # One level deeper: an environment under a team folder under projects.
        Machine(
            "t-01",
            "projects/team-x/env-3001",
            "DC0_C0_H2",
            "LocalDS_0",
            powered_on=False,
            created_hours_ago=6,
        ),
        # The same env id as on the other vCenter: found on both, and said so.
        Machine(
            "x-01",
            "projects/env-1001",
            "DC0_C0_H2",
            "LocalDS_1",
            tools="guestToolsRunning",
            heartbeat="green",
            cpu_mhz=400,
        ),
    ]
    a = build(
        "vsphere-mcp-test-a",
        [
            "environments/env-1001",
            "environments/env-1002",
            "environments/env-1003",
            "environments/env-1004",
            "environments/env-1005",
            "environments/env-1006",
            "environments/env-0999",
            "templates",
        ],
        a_machines,
        work=work,
    )
    b = build(
        "vsphere-mcp-test-b",
        ["projects/env-2001", "projects/env-20015", "projects/env-1001", "projects/team-x/env-3001"],
        b_machines,
        work=work,
    )
    return a, b
