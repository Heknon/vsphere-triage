# vsphere-triage

An MCP server for diagnosing VMware VMs that are stuck: VMs that did not come
back after a boot or reboot, keep losing VMware Tools, wait on a question, or
are starved by their host or storage. It reads from one or more vCenters,
judges every VM, groups the abnormal ones by what they share (host, datastore,
linked-clone base disk, environment folder), and gives a likely cause with the
evidence for and against it.

It is built for fleets of short-lived VMs whose names are reused (CI or lab
environments created by an orchestrator). It works against vCenter alone;
vROps and Dell PowerFlex are optional extra sources.

The repo contains:

- **The MCP server**: the `vsphere_triage` Python package, installed as the
  `vsphere-triage` command and published to PyPI.
- **The `vm-incident` skill** ([`skills/vm-incident/`](skills/vm-incident/)):
  the incident procedure a Claude Code agent follows when it drives the server.
- **A Claude Code plugin** ([`.claude-plugin/`](.claude-plugin/)) that installs
  both at once.
- **Live evals** ([`evals/live/`](evals/live/)): a model drives the real tools
  and the skill against the integration scenario's simulated vCenters, and its
  verdicts and tool calls are scored.

[docs/orchestrator-integration.md](docs/orchestrator-integration.md) covers
wiring it to the system that creates your VMs.

## Quick start

The server is a Python package; there is no separate binary to download.
Installing it from PyPI puts a `vsphere-triage` command on your `PATH`, and
the MCP client starts that command over stdio. What you need on the machine:

- [uv](https://docs.astral.sh/uv/getting-started/installation/) (recommended):
  `uvx` downloads the package and, if needed, a Python 3.12+ interpreter, and
  caches both. The Claude Code plugin uses `uvx`, so it needs uv on the `PATH`.
- or Python 3.12+ with `pipx` or `pip`.
- `tesseract` on the `PATH`, only for OCR of the console screen (the `[ocr]`
  extra); without it, console analysis still works but reads no text.

```sh
uvx vsphere-triage                 # run from PyPI without installing
uv tool install vsphere-triage     # or install the command
pipx install vsphere-triage        # or with pipx
uv tool install '.[ocr]'           # from a checkout, with console OCR (also needs the tesseract binary)
```

Without public PyPI, point uv at a mirror
(`UV_INDEX_URL=https://pypi.internal/simple uvx vsphere-triage`) or install
from git (`uvx --from git+https://git.internal/vsphere-triage.git vsphere-triage`).

The minimum configuration is the vCenter list and a login:

```json
{
  "mcpServers": {
    "vsphere-triage": {
      "command": "vsphere-triage",
      "env": {
        "VSPHERE_VCENTERS": "[{\"name\": \"vc-01\", \"host\": \"vc01.example\"}]",
        "VSPHERE_USERNAME": "svc-triage@vsphere.local",
        "VSPHERE_PASSWORD": "...",
        "VSPHERE_CA_BUNDLE": "/etc/pki/internal-ca.pem",
        "VSPHERE_ENV_PARENT_HINTS": "environments,projects"
      }
    }
  }
}
```

The server speaks MCP over stdio by default. With `uvx`, use
`"command": "uvx", "args": ["vsphere-triage"]` (pin a version with
`"vsphere-triage==0.3.0"`); with a `uv tool` or `pipx` install, use
`"command": "vsphere-triage"` as above.

## Two ways to start

**From an alert about one VM.** A monitoring alert usually names the vCenter,
the environment id and the machine. Pass them to `diagnose_vm`:

```
diagnose_vm(vcenter="vc-01", env_id="env-1042", vm_name="web-01")
```

It runs every check in a fixed order (machine state, CPU, storage, the rest of
the environment, events, boot timeline from `vmware.log`, serial console,
console screen, snapshots, hardware) and returns a `finding`, the ranked
causes with the evidence for and against each, what it could not read
(`not_checked`), and the next checks to run. If your orchestrator knows when it
rebooted the VM, pass `rebooted_at`. vCenter does not move `runtime.bootTime`
on an in-guest reboot and logs no event for it, so `diagnose_vm` also reads the
last power-on or reset from the VM's `vmware.log`, and `scan` does the same for
up to 40 VMs per vCenter that look stuck only because their uptime is counted
from power-on.

**From a question about the fleet.** `scan` judges every VM on some or all
vCenters and groups the abnormal ones. Each group is compared with its
population, e.g. "29 of 210 VMs on ds-17 are abnormal, 6x the fleet rate".
Then:

1. `explain_group(scan_id, dimension, value)` on the strongest group: what its
   abnormal VMs share that the healthy VMs beside them do not, plus host CPU
   and datastore latency over their boot window.
2. `diagnose_vm` on the representatives that `explain_group` returns.

For an incident that has already passed (the VMs may be gone),
`diagnose_window(since, until)` reads resets, failed power-ons, host CPU and
storage for that window. `cluster_events` explains a mass reboot from vSphere
HA restarts, host failures and migration waves.

## How VMs, environments and vCenters are found

- **Environments.** An environment is a VM folder named by its environment id,
  under any parent folder (`environments/`, `projects/team-x/`, or anything
  else). `find_environment` looks for a folder with exactly that name first,
  then for names that contain it. It returns the path and the parent of every
  match; when several match, it lists them and asks you to choose.
  `VSPHERE_ENV_PARENT_HINTS` sets which parents are searched first.
- **VMs.** Every result identifies a VM by `vcenter` and `moref` (e.g.
  `vm-1042`). A VM name is looked up only inside its environment folder,
  because later environments reuse the same names. A moref is unique on one
  vCenter only, so always pass the vCenter with it.
- **vCenter names.** A vCenter can be named by its configured `name`, its
  `host`, any of its `aliases`, or the first label of its host (`vc01` for
  `vc01.example`), so the spelling in an alert resolves. A name that matches
  two vCenters is refused rather than guessed.
- **Group values** carry their vCenter (`vc-a:esx-07`), so hosts or datastores
  with the same name on two vCenters stay separate.
- **Thresholds.** Every check returns the raw numbers it judged next to its
  verdict. The thresholds are defaults (see [States and flags](#states-and-flags))
  that you can override with `VSPHERE_THRESHOLDS`.

## Configuration

Everything is set through `VSPHERE_*` environment variables. Only
`VSPHERE_VCENTERS` and credentials are required.

| Variable | Default | Meaning |
| --- | --- | --- |
| `VSPHERE_VCENTERS` | none | JSON list of `{"name", "host", "port", "aliases", "username", "password"}`; `port` defaults to 443, per-vCenter credentials override the shared ones |
| `VSPHERE_USERNAME`, `VSPHERE_PASSWORD` | none | shared vCenter credentials |
| `VSPHERE_CA_BUNDLE` | system store | PEM bundle for an internal CA; also used for vROps and PowerFlex |
| `VSPHERE_TLS_VERIFY` | `1` | set `0` only against a simulator; a warning is logged |
| `VSPHERE_ENV_PARENT_HINTS` | none | parent folders searched first for an environment, e.g. `environments,projects` |
| `VSPHERE_THRESHOLDS` | see below | JSON object overriding any threshold, e.g. `{"booted_not_up_minutes": 15}` |
| `VSPHERE_SCAN_BASE_DISKS` | `1` | read each VM's disk chain during `scan`, so linked clones group by base disk; `0` makes large scans faster |
| `VSPHERE_TIMEOUT_SECONDS` | `60` | deadline for one vCenter read |
| `VSPHERE_SCAN_TIMEOUT_SECONDS` | `300` | deadline for a whole-vCenter sweep (`scan`, `diagnose_window`, the fleet reports, event history) |
| `VSPHERE_MAX_CONCURRENT_TOOLS` | `4` | tool calls running at once |
| `VSPHERE_MAX_CONCURRENT_PER_VCENTER` | `4` | reads running at once against one vCenter |
| `VSPHERE_MAX_LOG_BYTES` | 4 MiB | how much of the end of a log file is read |
| `VSPHERE_MAX_DOWNLOAD_BYTES` | 128 MiB | most bytes pulled for one datastore file when vCenter ignores the Range request |
| `VSPHERE_MAX_LOG_LINES` | `400` | most log lines in one result |
| `VSPHERE_MAX_SCREENSHOT_BYTES` | 16 MiB | largest console screenshot accepted |
| `VSPHERE_MAX_SCANS_KEPT` | `10` | how many past scans `explain_group` can refer to |
| `VSPHERE_GUEST_USERNAME`, `VSPHERE_GUEST_PASSWORD` | none | default guest-OS account for the tools that run a command in a guest; when unset, pass credentials per call |
| `VSPHERE_GUEST_EXEC_TIMEOUT_SECONDS` | `30` | how long a guest command may run before it is terminated |
| `VSPHERE_GUEST_EXEC_MAX_OUTPUT_BYTES` | 1 MiB | most guest-command output returned |
| `VSPHERE_GUEST_EXEC_OVER_HTTP` | `0` | also offer the tools that act on a VM over the HTTP transport (see [Transports](#transports)) |
| `VSPHERE_VROPS_URL`, `VSPHERE_VROPS_USERNAME`, `VSPHERE_VROPS_PASSWORD`, `VSPHERE_VROPS_AUTH_SOURCE` | none | optional vROps (Aria / VCF Operations); the `vrops_*` tools are registered only when the URL is set |
| `VSPHERE_POWERFLEX_URL`, `VSPHERE_POWERFLEX_USERNAME`, `VSPHERE_POWERFLEX_PASSWORD` | none | optional Dell PowerFlex (ScaleIO / VxFlex) Gateway, 3.x API; the `powerflex_*` tools are registered only when the URL is set |

## Transports

**stdio** (the default) serves one MCP client and offers every tool.

**Streamable HTTP** shares one server between several clients:

```sh
vsphere-triage --transport streamable-http --host 0.0.0.0 --port 8000 --allowed-host vsphere-triage.example
```

`/healthz` answers health probes. The HTTP transport has no authentication of
its own, and every caller uses the configured vCenter and guest credentials.
For that reason the seven tools that act on a VM (listed under
[Tools that act on a VM](#tools-that-act-on-a-vm)) are not registered over
HTTP unless `VSPHERE_GUEST_EXEC_OVER_HTTP=1`. Set it only behind a proxy that
authenticates callers.

## Install as a Claude Code plugin

The plugin installs the server and the `vm-incident` skill together:

```
/plugin marketplace add Heknon/vsphere-triage
/plugin install vsphere-triage@vsphere-triage
```

The install asks for:

- the vCenters JSON, username and password;
- optionally: environment parent-folder hints, a CA bundle path, vROps URL and
  credentials, PowerFlex URL and credentials, and guest-OS credentials;
- the Python package index (public PyPI, or your internal mirror).

Passwords are kept in the OS credential store. Leave an optional field blank to
turn it off. Settings the install does not ask for (thresholds, timeouts,
`VSPHERE_TLS_VERIFY`, ...) are read from the environment the server inherits.

The plugin runs the server with `uvx vsphere-triage==<plugin version>`, so the
server always matches the skill. Invoke the skill as
`/vsphere-triage:vm-incident`.

## Tools

### Fleet

| Tool | What it returns |
| --- | --- |
| `list_vcenters` | each configured vCenter: reachable or not, version, clock |
| `scan` | every VM judged; abnormal VMs grouped by vCenter, cluster, host, datastore, environment folder, its parent folder, base disk and OS, each group against its population; hosts over the CPU threshold, hosts near memory capacity, hosts whose hardware sensors are red or yellow (with the sensors and how many VMs run there), slow storage. The first `limit` abnormal VMs (10 by default) come in full, and `more_abnormal_vms` names the rest one line each |
| `explain_group` | for one group from a scan: what its abnormal VMs share that the healthy ones do not, and host CPU and storage over their boot window |
| `diagnose_window` | resets, failed power-ons, host CPU and storage over a past window |
| `cluster_events` | vSphere HA restarts and VM-monitoring resets, host failures, isolations and lost connections, failed failovers, maintenance mode and migration waves over a window; names the failed host and the hosts VMs restarted onto |
| `recent_tasks` | tasks over a window grouped by kind (migration, reconfigure, snapshot, clone, power, destroy), flagging 10 or more migrations, reconfigures or snapshot operations as a wave, and the tasks that failed, with their error. Read through a task history collector created and destroyed for the call |
| `find_old_environments` | environment folders older than N hours (age of their oldest VM), optionally under given path segments, oldest first |
| `hardware_profile` | device counts per category and kind across the fleet, NIC types, and VMs whose devices differ from the rest of their environment |
| `find_vms_by_device` | VMs that have, or lack, a device category (`sound`, `usb`, `ethernet`, ...) or kind (`Vmxnet3`, `HdAudioCard`) |
| `find_vms_by_snapshot` | VMs with snapshots, largest first: delta and memory-state size, oldest age, redo-chain depth, consolidation needed; rolled up per template |
| `find_resource_limits` | VMs with a CPU or memory limit or reservation, tightest limit first, templates marked (linked clones inherit a template's limit), and VMs in a resource pool or vApp running at 85% or more of a limit set on it, with the pool named |
| `check_datastores` | each datastore's free space, thin over-provisioning ratio and per-host reachability (APD/PDL); datastores holding a template's base disk are marked |
| `check_host_time` | each host's NTP configuration and clock skew from vCenter |

### One environment or VM

| Tool | What it returns |
| --- | --- |
| `find_environment` | the folder(s) matching an environment id, on which vCenter, and their VMs |
| `diagnose_environment` | every VM of one environment judged, with host CPU and storage for their hosts and datastores |
| `diagnose_vm` | the full diagnosis of one VM, ending in ranked causes (see [Two ways to start](#two-ways-to-start)) |
| `get_boot_timeline` | how far the last boot got according to `vmware.log` (power-on, firmware, first disk I/O, drivers, Tools), plus the serial console |
| `read_vm_log` | `vmware.log` or `vmware-N.log` lines, filtered by a regex on the server (2 s match budget) |
| `read_serial_console` | the serial-port file (Windows EMS, a Linux kernel console) with stop codes and the layer each points at |
| `get_vm_console` | the console screen in words: black, frozen or changing, blue screen, OCR text and the boot screen it shows; optionally a thumbnail |
| `get_vm_events` | a VM's events by moref; a destroyed VM is reported as destroyed |
| `get_vm_hardware` | virtual devices and vCenter's connection state for each; flags a disconnected boot NIC, a mounted ISO or a device error |

### Hosts, datastores and vCenter

| Tool | What it returns |
| --- | --- |
| `get_host_health` | a host's CPU demand against capacity, its storage, its hardware sensors (power supplies, fans, temperature, memory) and its VMs |
| `get_datastore_health` | a datastore's latency and IOPS from every host that mounts it, which of those hosts see it slow (`slow_from_hosts`: a path or an array), and its VMs |
| `read_host_log` | `vmkernel`, `hostd` or `vpxa` lines, regex-filtered |
| `check_vcenters` | per vCenter: reachable, the server's last login time, a round-trip time and the open-session count, for SSL EOFs and resets caused by session exhaustion |
| `vcenter_sessions` | a vCenter's open API sessions grouped by user, source IP and client, with idle counts and the oldest |
| `vcenter_history` | login, logout and failed-login events over a past window, in 10-minute buckets, with the busiest sources |

### Tools that act on a VM

These seven change state or run code in a guest. Each one finds the VM
strictly: an exact environment name, a matching VM name, and with a moref the
name must match too. Each sends its action once and does not resend it if the
vCenter session drops mid-call (the error then says the action may have run).

| Tool | What it does |
| --- | --- |
| `run_in_guest` | runs a command in the guest OS through VMware Tools and returns its output and exit code; needs Tools running, guest credentials, and the VM's name with its moref (as every acting tool does; a mismatch is refused). Output goes to a temp file in the guest, which is downloaded and deleted |
| `reboot_guest` | asks the guest OS to restart through Tools (a clean shutdown and boot); needs Tools. Requires the VM name together with a moref |
| `hard_reset` | power-cycles the VM (`ResetVM_Task`) without asking the guest; works on a fully hung VM, but in-flight writes and unwritten crash dumps are lost. Use it only when `reboot_guest` cannot. Requires the VM name together with a moref |
| `check_ems` | whether the serial console can carry the guest's boot output: serial-port hardware and output already seen (no Tools needed), and on Windows the `bcdedit` EMS setting (needs Tools and guest credentials) |
| `investigate_windows_boot` | reads the guest's event log: the last bugcheck (WER 1001, decoded), Kernel-Power 41 / EventLog 6008 unclean shutdowns, service and driver start timeouts (SCM 7000/7009/7011/7026), slow-boot components, crash dumps, Startup Repair and Panther logs. Only events from a day before the latest boot onward count; older ones are listed separately |
| `investigate_linux_boot` | reads `dmesg` (panics, soft lockups, hung tasks, I/O errors, filesystem errors), `systemd-analyze blame` and `critical-chain`, and the journal for the current and the previous boot. Says when the journal is not persistent, so the boot before a reboot was not read |
| `read_crash_dump` | decodes the newest Windows minidump header: bugcheck code, its four parameters and when the dump was written. It does not name the faulting driver (that needs WinDbg and symbols) |

The usual order for a wedged VM: read everything first, then `reboot_guest`, and
`hard_reset` only if that fails or Tools is down. Then run the
`investigate_*` tools on the fresh boot. A powered-off VM must be powered on by
your orchestrator or in vCenter; the server has no power-on tool.

### Optional: vROps

`vrops_find_resource`, `vrops_list_stat_keys`, `vrops_get_stats`,
`vrops_compare_window` (a window against the same hours on previous days) and
`vrops_get_alerts`. vROps keeps longer and finer history than vCenter, which
keeps 20-second samples for about an hour and 5-minute rollups for about a
day.

### Optional: PowerFlex

| Tool | What it returns |
| --- | --- |
| `powerflex_health` | SDS and device state, rebuild and rebalance activity, and failed capacity, across every system the Gateway manages |
| `powerflex_protection_domains` | protection domains ranked by read/write IOPS and throughput; one carrying over half the IOPS and 1.5x its even share is marked hot |
| `powerflex_find_volume` | the PowerFlex volume behind a datastore, by volume name, id or ESXi device id (`eui.` / `naa.`) |
| `powerflex_affected_vms` | troubled or hot protection domains, the datastores on their volumes, and the VMs on those datastores, split into suffering and not |

## States and flags

Every VM gets one state from the bulk property read, checked in this order:

| State | Condition |
| --- | --- |
| `inaccessible` | connection state is not `connected` (orphaned, inaccessible, invalid) |
| `blocked_on_question` | a VM question is pending |
| `suspended` | power state is suspended |
| `off` | powered off |
| `paused` | powered on but paused |
| `lost_heartbeat` | Tools running, heartbeat red |
| `healthy` | Tools running |
| `no_tools` | Tools not installed; not counted as stuck, judged by CPU, console and boot log |
| `no_boot_time` | powered on, Tools not running, no boot time reported |
| `booting` | booted less than `booted_not_up_minutes` (10) ago |
| `hung` | booted longer ago, Tools not running, CPU at or below `hung_cpu_mhz` (100 MHz) |
| `busy_not_up` | the same, but CPU at or above `busy_cpu_fraction` (50%) of its vCPUs |
| `booted_not_up` | booted longer ago, Tools not running, CPU in between |

Uptime is measured from the latest reset or guest-reboot event when there is
one, because `runtime.bootTime` only changes on a power cycle.

Flags appear next to the state. These count as abnormal on their own:
`boot_loop` (3 resets in 30 minutes), `tools_flapping`,
`heartbeat_intermittent` (yellow heartbeat), `memory_reclaimed` (ballooned,
swapped or compressed), `host_memory_pressure` (host at 95% memory or more),
`vcenter_alarm` (a red alarm on the VM), `host_not_connected`, `long_running`
(older than 24 hours) and `consolidation_needed`. These add detail only:
`host_in_maintenance`, `tools_outdated`, `cpu_limited` (a CPU limit at or
below 90% of the VM's full speed) and `memory_limited` (a memory limit below
its RAM).

`scan(states=[...])` selects any state or flag, e.g. `["no_tools"]` or
`["long_running"]`.

Other default thresholds: CPU ready 10% per vCPU, co-stop 3%, host CPU demand
100% of capacity, datastore and device latency 50 ms, kernel queue latency
10 ms, snapshots 20 GB or 24 hours old or a chain 4 deep, clock skew 60 s,
datastore 5% free, thin over-provisioning 2x, console black at 98% dark
pixels.

## What the diagnosis measures

- **CPU starvation.** The VM's `cpu.ready.summation` as a percentage per vCPU,
  and the host's `cpu.demand.average` against cores × core MHz. Demand over
  100% is overcommit. When only `cpu.usagemhz` is available, overcommit is
  reported as unknown, because usage cannot exceed capacity.
- **Storage.** Per host, `datastore.totalReadLatency` /
  `totalWriteLatency` for the VM's datastores, and
  `disk.deviceLatency` / `kernelLatency` / `queueLatency` with aborts and
  resets per device. High device latency points at the array; high queue
  latency points at the host's own queue. A full or unreachable datastore is
  reported as a separate cause from latency.
- **The environment.** Whether the healthy VMs in the same environment share
  the stuck VM's host, datastore or base disk. If they do, that argues against
  the shared object being the cause.
- **The boot.** `vmware.log` is written by the hypervisor, so it shows how far
  a boot got but never the guest kernel's messages. Those come from the serial
  console (when the VM has a serial port writing to a file), the console
  screen, and the guest probes.
- **Missing data** is listed as missing (`not_checked`, `available: false`
  with a reason, `healthy: null`), never treated as healthy. Counters that
  vCenter has already rolled up for an old window are reported as gaps.

Results start with `finding` or `findings`, keep the raw values, and are cut
to 60,000 characters (under common clients' tool-output limit), saying what was
cut. A steady series is marked `steady` and its finding says "held at", so a
flat counter is not given a peak time it does not have.

## What can change vSphere

Every vSphere API call from the read-only tools goes through
`readonly.ReadOnlyStub`, which refuses any method not on `ALLOWED_METHODS`
before it is sent. The list is: `RetrieveServiceContent`, `Login`, `Logout`,
`CurrentTime`, `Fetch`, `RetrievePropertiesEx`, `ContinueRetrievePropertiesEx`,
`CreateContainerView`, `DestroyView`, `QueryEvents`, `QueryPerf`,
`QueryDescriptions`, `BrowseDiagnosticLog`, `QueryDateTime`, `QueryOptions` and
`SearchDatastore_Task` (which only lists files).

HTTP reads (`vmware.log` and serial files over `/folder`, the console over
`/screen`) are GET only, and redirects are not followed. The console is read
through `/screen`; `CreateScreenshot_Task` is not used, because it writes a PNG
into the VM's folder. The vROps and PowerFlex clients send only GET requests,
apart from vROps's token request.

The seven tools that act on a VM use the session's unguarded stub. Tests check
that every read-only tool, run against the simulators, sends only allowed
methods; that power, reset, answer, reconfigure, destroy and
screenshot-to-datastore are refused through a live session; and that the acting
tools never add a method to the guarded surface.

Running with a dedicated vCenter role limits the account as well. The stock
Read-only role is not enough for every read:

| Privilege | Needed for |
| --- | --- |
| Read-only (System.View, System.Read) | inventory, events, performance counters |
| `Datastore.Browse` | `vmware.log`, serial-console files and datastore listings (`read_vm_log`, `get_boot_timeline`, `read_serial_console`); without it these return HTTP 403 |
| `Global.Diagnostics` | host logs (`read_host_log`) |
| the console privilege `/screen` needs (confirm on your version) | `get_vm_console` |
| `Sessions.TerminateSession` | the full session list in `check_vcenters` / `vcenter_sessions`; vSphere has no separate view privilege for it, and without it only this server's own session is visible |
| `VirtualMachine.GuestOperations.Query`, `.Modify`, `.Execute` | the guest-command tools |
| `VirtualMachine.Interact.Reset` | `reboot_guest` and `hard_reset` |

vCenter's default statistics level is 1. Host CPU demand, co-stop and the
per-device storage counters are level 2 or 3, so on a stock vCenter they are
kept only in the realtime hour; for older windows raise the statistics level, or
use vROps. Each result says when a window's counters could not be read.

## Development

The project uses [uv](https://docs.astral.sh/uv/). `uv.lock` is committed and
`uv sync` installs the dev tools (pytest, ruff, ty).

```sh
uv sync                                        # dev environment from the lock
uv run python -m pytest -m "not integration"   # unit tests, about 5 s (what CI runs)
uv run python -m pytest                         # unit + integration (needs Docker)
uv run ruff check . && uv run ruff format --check .
uv run ty check vsphere_triage                  # type check, package only
```

Ruff runs with `select = ["ALL"]` and a short ignore list in `pyproject.toml`.
`ty` checks the `vsphere_triage` package; the tests are not type-checked.

`.github/workflows/ci.yml` runs lint, format, type check and the unit tests on
every push and pull request. The integration suite runs by hand: Actions → CI
→ Run workflow → `integration = true`, or locally.

### Integration tests

`tests/integration/` builds two simulated vCenters in Docker with
`vmware/vcsim:v0.52.0` and `vmware/govc:v0.52.0`, one with an `environments/`
layout and one with `projects/`. They hold linked clones, stuck Windows and
Linux VMs, a pending question, a boot loop, an EMS stop code, one environment
id on both vCenters and machine names reused across environments. On an
air-gapped machine, `docker save` both images and `docker load` them there.

The simulator's limits, and how the tests handle them:

- Performance counters are random, so CPU and storage numbers come from a
  controlled fake of `VCenterSession.perf`.
- There is no `/screen` endpoint: the 404 path is tested against vcsim, and the
  image analysis against generated screenshots.
- There are no host logs: tested as "unavailable".
- Guest operations, snapshot sizes, NTP state, thin provisioning, APD/PDL and
  HA events are not modelled: that logic is unit-tested only.

### Live evals

`evals/live/` serves the real tool surface over the integration scenario for a
model to drive, logs every call, and scores runs on twelve scenarios
(`scenarios.json`: what each verdict must and must not say). Like the
integration suite it needs Docker and is not on any CI path; its README has
the steps and the results so far. `tests/test_surface.py`, on the per-commit
path, checks that every tool, argument, state, cause and stop code the skill
and the docs name exists in the code.

### To confirm on a real vCenter

- The privilege `/screen` needs, and what it returns for a black console.
- Which counters your statistics level keeps past the realtime hour, and how
  `/folder` handles a suffix `Range` request.
- The datastore counter instance names (the volume id from
  `ds:///vmfs/volumes/<id>/` is tried first, then the name).
- The `vmware.log` lines your ESXi version writes for a stuck boot, a stun and
  an APD. The patterns in `vmlog.py` are heuristics, and each match is
  returned with its line.
- What EMS writes on your Windows versions, and the vROps stat keys on your
  version (`vrops_list_stat_keys` lists them).
- Snapshot sizes from `layoutEx` (the simulator reports none, so they come back
  `null` and "no size reported").
- Guest exec: the guest-operation privileges, and that output capture works on
  your Windows and Linux guests.
- That an in-guest reboot shows in `vmware.log` as a reset (`CPU reset` on
  vcpu-0, or the chipset's reset request). If your orchestrator knows the
  reboot time, `rebooted_at` is still the surest input.
- The HA event ids and messages your vCenter version writes, which
  `cluster_events` matches by pattern.
- A datacenter inside a folder, and one datastore name in two datacenters (the
  simulator has one flat datacenter).

## Releasing

`.github/workflows/release.yml` publishes to PyPI with Trusted Publishing; no
token is stored in the repo. The one-time setup at
[pypi.org/manage/account/publishing](https://pypi.org/manage/account/publishing)
is a publisher for project `vsphere-triage`, owner `Heknon`, repository
`vsphere-triage`, workflow `release.yml`, environment `pypi` (and the same on
test.pypi.org for the `testpypi` dispatch).

To release:

1. Raise `version` in `pyproject.toml`, and set the same version and the
   `vsphere-triage==X.Y.Z` pin in `.claude-plugin/plugin.json`. A unit test
   fails if they differ.
2. Merge to `main`. The workflow sees a version with no `vX.Y.Z` tag, runs the
   CI gate, builds the sdist and wheel, installs and smoke-tests the wheel,
   publishes to PyPI, tags the commit and creates the GitHub release.

A merge that does not change the version publishes nothing. Pushing a tag by
hand (`git tag vX.Y.Z && git push origin vX.Y.Z`) also releases, and a manual
dispatch can publish the current branch to TestPyPI first. Run the integration
suite before a release.
