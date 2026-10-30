# vsphere-triage

A read-only vSphere MCP server that triages VMs which are stuck, did not come
back after a reboot, or keep losing VMware Tools — across a fleet of vCenters
where VMs are short-lived and their names are reused. It sweeps the fleet,
groups the abnormal VMs by what they share, weighs the causes, and ends in a
verdict. It discovers each vCenter's layout rather than assuming it, so it is
not tied to any one platform; it plugs into whatever orchestrator creates your
VMs through configuration and a skill (see [Using it with an
orchestrator](docs/orchestrator-integration.md)).

This repo ships two things: the **MCP server** (the `vsphere_triage` package,
installed as the `vsphere-triage` command) and a **diagnosis skill** under
[`skills/vm-incident/`](skills/vm-incident/) — the step-by-step incident
procedure for a Claude Code agent driving the server. The server is delivered
through PyPI; the skill through your Claude Code plugin / skills channel.

vROps (Aria / VCF Operations) is an **optional** integration: configure
`VSPHERE_VROPS_URL` and it adds a handful of history tools (longer and finer
than vCenter keeps). Everything else — the whole diagnosis — runs on vCenter
alone, so the server is fully useful with no vROps at all.

It is read-only with deliberate exceptions that act on a VM: `run_in_guest`
executes a command inside a guest OS for a diagnostic a read cannot answer,
`reboot_guest` / `hard_reset` reboot a wedged VM so it writes a fresh boot log,
and `check_ems` / `investigate_windows_boot` read the guest's BCD and event log
(so they too run a command in the guest). All are marked not-read-only and
routed outside the read-only guard on purpose (see below); nothing else can
change a VM.

It answers two kinds of question:

- **From a VMware Tools error your monitoring raised** (which names the vCenter,
  the machine and the environment id): `diagnose_vm(vcenter, env_id, vm_name)`
  runs every check in a fixed order and ends in the likely cause.
- **About the fleet** ("anything stuck on these vCenters?"): `scan` judges
  every VM, groups the abnormal ones by what they share (host, datastore,
  linked-clone base disk, environment, ...) against their population, and
  `explain_group` says why a group is abnormal.

## Read-only, by construction (with marked exceptions)

The accounts it may run with can write, so the guarantee is in the code, not
the account:

- Every vSphere call goes through `readonly.ReadOnlyStub`, which refuses any
  method not on a short `ALLOWED_METHODS` allowlist before a byte is sent:
  login and logout, the clock, property reads, container views, `QueryEvents`,
  `QueryPerf`, `BrowseDiagnosticLog` / `QueryDescriptions`, `QueryDateTime` (a
  host's clock) and `SearchDatastore_Task` (which only lists files).
- Every HTTP request (`vmware.log` and serial files over `/folder`, the
  console over `/screen`) goes through `ensure_read_request`: GET only.
- The console is read through `/screen`, never `CreateScreenshot_Task`, which
  writes a PNG into the VM's folder.
- A test drives every read-only tool against simulated vCenters and asserts
  that the methods sent are a subset of the allowlist; another tries power,
  reset, answer, reconfigure, destroy and screenshot-to-datastore through a
  live session and expects each to be refused.

**The exceptions are the three tools that act on a VM**, enabled deliberately
and all routed outside the guard on the session's raw stub, never through
`ReadOnlyStub`; a test proves that invoking each one never adds a method to the
read-only (guarded) surface:

- **`run_in_guest`** runs a command inside a guest OS through VMware Tools, for a
  diagnostic a read cannot answer. It needs Tools running and guest-OS
  credentials (per call, or `VSPHERE_GUEST_USERNAME` / `VSPHERE_GUEST_PASSWORD`),
  and captures output via a temp file in the guest that it downloads and deletes.
- **`reboot_guest`** asks the guest to reboot gracefully through Tools — no data
  loss, but needs Tools and a responsive guest. Try it first.
- **`hard_reset`** power-cycles the VM (`ResetVM_Task`) with no Tools, so it can
  reboot a fully hung VM — but it is destructive: the guest is never asked, so
  in-flight writes and in-guest evidence (an unwritten crash dump, update
  progress) can be lost. Both exist because a wedged VM often has to be rebooted
  before it writes a fresh boot log; prefer the graceful one.

Everything else is read-only: nothing is created, changed, answered or deleted,
and the server runs nothing in the background.

## Concepts, not constants

Nothing hard-codes a folder path, a log field or a naming pattern:

- An environment is a folder named by its environment id. `find_environment`
  looks for it (exact name first, then names containing it) and reports where it
  found it and under which parent (environments, projects, anything). Several
  matches are reported, never guessed between.
  `VSPHERE_ENV_PARENT_HINTS` only orders the search.
- A VM is identified by `(vcenter, moref)`. Its name is looked up only inside
  its environment folder, since later environments reuse it.
- A vCenter answers to its name, host, the host's first label and any
  configured alias, so whatever spelling an upstream log uses resolves.
- Group values carry their vCenter (`vc-a:DC0_H0`): two vCenters' hosts of the
  same name are different hosts.
- Every check returns the numbers it judged, beside its verdict; thresholds
  are defaults in `VSPHERE_THRESHOLDS`, tuned on real incidents.

## Install and configure

```sh
uvx vsphere-triage                           # run straight from PyPI, no install
uv tool install vsphere-triage               # or install the command
uv tool install .                             # or from a checkout; add [ocr] for console OCR (needs tesseract)
pipx install vsphere-triage                   # or with pipx / pip
```

**Internal / air-gapped:** the package need not come from public PyPI. Point uv
at an internal mirror — `UV_INDEX_URL=https://pypi.internal/simple uvx
vsphere-triage` — or install it straight from the git repo with no index at
all: `uvx --from git+https://git.internal/vsphere-triage.git vsphere-triage`.

Configure it entirely through `VSPHERE_`-prefixed environment variables — only
`VSPHERE_VCENTERS` plus credentials are required; everything else has a default.

| Variable | Default | Meaning |
| --- | --- | --- |
| `VSPHERE_VCENTERS` | none | JSON list: `[{"name": "vc-04", "host": "vc04.example", "port": 443, "aliases": ["vc04-old"]}]`; per-vCenter `username` / `password` override the shared ones |
| `VSPHERE_USERNAME`, `VSPHERE_PASSWORD` | none | shared credentials |
| `VSPHERE_CA_BUNDLE` | system | PEM bundle for an internal CA |
| `VSPHERE_TLS_VERIFY` | `1` | `0` only against a simulator; warned about |
| `VSPHERE_ENV_PARENT_HINTS` | none | folder names to look under first, e.g. `environments,projects` |
| `VSPHERE_THRESHOLDS` | see `config.Thresholds` | JSON object overriding any threshold |
| `VSPHERE_SCAN_BASE_DISKS` | `1` | read disk chains in a scan, to group linked clones by base disk |
| `VSPHERE_TIMEOUT_SECONDS` | `60` | deadline per vCenter read |
| `VSPHERE_MAX_CONCURRENT_TOOLS` | `4` | tool calls at once |
| `VSPHERE_MAX_CONCURRENT_PER_VCENTER` | `4` | reads at once per vCenter |
| `VSPHERE_MAX_LOG_BYTES` | 4 MiB | how much of the end of a log is read |
| `VSPHERE_MAX_DOWNLOAD_BYTES` | 128 MiB | ceiling on one datastore file when vCenter ignores a Range request |
| `VSPHERE_MAX_LOG_LINES` | `400` | most lines one result returns |
| `VSPHERE_MAX_SCREENSHOT_BYTES` | 16 MiB | ceiling on one console screenshot |
| `VSPHERE_MAX_SCANS_KEPT` | `10` | how many recent scans stay available for `explain_group` (history depth, not a per-vCenter count) |
| `VSPHERE_GUEST_USERNAME`, `VSPHERE_GUEST_PASSWORD` | none | **default guest-OS credentials for `run_in_guest`** — the one tool that is not read-only; omit to require them per call |
| `VSPHERE_GUEST_EXEC_TIMEOUT_SECONDS` | `30` | how long `run_in_guest` waits for a command to finish |
| `VSPHERE_GUEST_EXEC_MAX_OUTPUT_BYTES` | 1 MiB | most command output `run_in_guest` returns |
| `VSPHERE_VROPS_URL`, `VSPHERE_VROPS_USERNAME`, `VSPHERE_VROPS_PASSWORD`, `VSPHERE_VROPS_AUTH_SOURCE` | none | **optional** vROps (Aria / VCF Operations); its 5 history tools appear only when the URL is set |
| `VSPHERE_POWERFLEX_URL`, `VSPHERE_POWERFLEX_USERNAME`, `VSPHERE_POWERFLEX_PASSWORD` | none | **optional** Dell PowerFlex (ScaleIO / VxFlex) Gateway; its backend-health tools appear only when the URL is set |

An MCP client config, over stdio:

```json
{
  "mcpServers": {
    "vsphere-triage": {
      "command": "vsphere-triage",
      "env": {
        "VSPHERE_VCENTERS": "[{\"name\": \"vc-01\", \"host\": \"vc01.example\"}]",
        "VSPHERE_USERNAME": "svc-readonly@vsphere.local",
        "VSPHERE_PASSWORD": "...",
        "VSPHERE_CA_BUNDLE": "/etc/pki/internal-ca.pem",
        "VSPHERE_ENV_PARENT_HINTS": "environments,projects"
      }
    }
  }
}
```

Or shared over HTTP, alongside your other MCP servers:
`vsphere-triage --transport streamable-http --host 0.0.0.0 --port 8000 --allowed-host vsphere-triage.example`
(`/healthz` for probes). Over HTTP every caller shares the configured
credential, which is read-only in effect either way.

A dedicated vCenter role is still worth creating where the account allows it,
so the guarantee holds twice: read inventory, console screen read (confirm
the privilege `/screen` needs on your version), datastore browse and file
read, and diagnostics (host logs).

## Install into Claude Code as a plugin (server + skill)

`.mcp.json` registers the server but not the skill. To get **both** the MCP
server and the `vm-incident` skill in one step, this repo is also a Claude Code
plugin marketplace (`.claude-plugin/`). Add the marketplace and install:

```
/plugin marketplace add Heknon/vsphere-triage
/plugin install vsphere-triage@vsphere-triage
```

The install prompts for the vCenters JSON, username and password (kept in the
OS secure store), and optionally the environment parent-folder hints, a CA
bundle, vROps URL/credentials, `run_in_guest` credentials, and the package
index (public PyPI, or an internal mirror for air-gapped installs). Leave any
optional field blank to disable it. Anything not prompted here — thresholds,
timeouts, `VSPHERE_TLS_VERIFY`, and the rest of the `VSPHERE_*` table above —
is read from the environment the server inherits, so you can set those the
usual way. The server runs via `uvx` and auto-starts; the skill is invoked as
`/vsphere-triage:vm-incident`. Nothing is published to npm — the plugin is
served straight from the git repo, and the Python package from PyPI or your
internal index.

## Tools

| Tool | Answers |
| --- | --- |
| `list_vcenters` | which vCenters, reachable, version, clock |
| `check_vcenters` | reachability, login time and open-session count per vCenter, for when the vCenter API itself is failing (SSL EOF, resets) — the sign of connection/session exhaustion |
| `vcenter_sessions` | a vCenter's open sessions grouped by user, source IP and client, with idle counts and the oldest — finds the client leaking sessions behind the exhaustion |
| `vcenter_history` | a vCenter's session/login events over a past window (login surge, failed logins, one source churning) — for an SSL EOF or exhaustion that has since cleared, which the live `check_vcenters` cannot see |
| `cluster_events` | cluster-level events over a window: vSphere HA restarts, host isolation/failure/connection-lost, DRS migration waves — names a mass-reboot cause above the VMs instead of inferring it |
| `recent_tasks` | what was *done* on a vCenter in a window (migrations, reconfigures, snapshots, failures), grouped and wave-flagged — the "someone did X" cause that shows in no single VM |
| `scan` | abnormal VMs on some or all vCenters, grouped by what they share; hosts over the CPU threshold and slow storage right now |
| `explain_group` | what a scan group's abnormal VMs share that the healthy ones beside them do not; CPU and storage over its boot window |
| `find_old_environments` | environments older than N hours (the age of their oldest VM), optionally only under `projects`, `environments`, `projects/team-x` or any other path segments, oldest first, with their VMs' states |
| `diagnose_window` | resets, failed power-ons, host CPU and storage over a past window, when VMs may be gone |
| `find_environment` | where an environment's folder is, on which vCenter(s), and its VMs |
| `diagnose_vm` | one VM: machine, CPU, storage, environment, boot timeline, serial console (EMS), console; the likely cause with evidence for and against |
| `diagnose_environment` | every VM of an environment, grouped, with CPU and storage |
| `run_in_guest` | **not read-only** — runs a command inside a guest OS (needs VMware Tools and guest credentials) and returns its output and exit code, for a diagnostic a read cannot answer |
| `reboot_guest` | **not read-only** — asks the guest to reboot gracefully through VMware Tools (no data loss, needs Tools); try this before `hard_reset` to make a wedged VM write a fresh boot log |
| `hard_reset` | **not read-only, destructive** — power-cycles the VM (`ResetVM_Task`, no Tools needed) to reboot a fully hung VM; the guest is not asked, so in-flight writes and in-guest evidence can be lost |
| `check_ems` | **not read-only** (reads the BCD in-guest) — whether the serial console (EMS on Windows) can carry the guest's boot words: serial-port hardware, output seen, and the `bcdedit` EMS state; says why it is unavailable and how to enable it |
| `investigate_windows_boot` | **not read-only** (reads the guest) — the Windows boot picture from the guest's own event log: last bugcheck (WER 1001, decoded), unclean shutdowns, service/driver timeouts, slow-boot components, crash dumps and repair/update logs |
| `investigate_linux_boot` | **not read-only** (reads the guest) — the Linux boot picture: dmesg (panics, soft-lockups, hung tasks, device timeouts, filesystem errors), systemd-analyze blame/critical-chain, journalctl -b, mapped to the layer each points at |
| `powerflex_health` | **optional** (PowerFlex configured) — Dell PowerFlex backend health: SDS/device state and any rebuild/rebalance in progress, the usual cause of a PowerFlex-backed datastore going slow |
| `powerflex_protection_domains` | **optional** — protection domains ranked by traffic (read/write IOPS + throughput), flagging a hot PD carrying a disproportionate share — the busy-PD pattern behind datastores on it going slow |
| `powerflex_find_volume` | **optional** — map a slow datastore to its PowerFlex volume by name, id, or ESXi device id (naa/eui) |
| `get_boot_timeline` | how far the last boot got, from `vmware.log`, plus the serial console |
| `read_vm_log` | `vmware.log` / `vmware-N.log` lines, filtered on the server |
| `read_serial_console` | Windows EMS or a Linux kernel console, when the VM has a serial port to a file; stop codes with the layer each points at |
| `get_vm_console` | the screen in words: black, frozen or changing, blue screen, OCR text and the boot screen it shows |
| `get_vm_events` | a VM's events, by moref (a destroyed VM is reported as such) |
| `get_vm_hardware` | the VM's virtual devices (adapters, controllers, disks, CD-ROM, sound, serial, USB, video) and vCenter's connection view; flags a down boot NIC, a mounted ISO or a device error |
| `find_vms_by_device` | every VM across the vCenters that has, or lacks, a device — by category (sound, ethernet, usb, ...) or a kind substring (Vmxnet3, HdAudioCard); scoped with vcenters/under |
| `hardware_profile` | the whole fleet's virtual hardware generically: counts per category and kind, NIC-type breakdown, and the VMs that differ from their environment's norm |
| `find_vms_by_snapshot` | VMs with snapshots across the vCenters, biggest first — delta + memory-state size, oldest age, redo-chain depth, and consolidation-needed; the fleet view that catches a forgotten 50 GB snapshot |
| `find_resource_limits` | VMs throttled or constrained by a configured CPU/memory limit or reservation — a CPU limit mimics host starvation, a memory limit forces balloon/swap; templates marked, since a linked clone inherits the template's limit |
| `check_host_time` | each ESXi host's NTP configuration and clock skew from vCenter — drift breaks TLS and Kerberos/AD auth, a root of the SSL/handshake errors separate from session exhaustion |
| `check_datastores` | every datastore's fill, thin over-provisioning and per-host reachability (APD/PDL); datastores holding a template's base disk are marked, since they take every clone down with them |
| `get_host_health` | a host's CPU demand against capacity, its storage, its VMs |
| `get_datastore_health` | a datastore's latency and IOPS from every host mounting it, its VMs |
| `read_host_log` | `vmkernel` / `hostd` / `vpxa` lines, filtered |
| `vrops_*` | find a resource, list its stat keys, read stats, compare a window with previous days, alerts |

### States and flags

Every VM gets exactly one state, from the bulk read alone:

| State | Means |
| --- | --- |
| `inaccessible` | vCenter cannot reach or account for it |
| `blocked_on_question` | waiting on a VM question |
| `paused` | powered on, but the hypervisor is not running it |
| `hung` | booted over 10 min ago, Tools never up, almost no CPU |
| `busy_not_up` | the same, but burning CPU: starved, spinning or still working |
| `booted_not_up` | booted over 10 min ago, Tools never up (or stuck running its startup scripts) |
| `lost_heartbeat` | Tools runs, heartbeat red |
| `no_boot_time` | powered on, no boot time reported |
| `no_tools` | Tools not installed: not counted as stuck; judged by CPU, console and boot log |
| `booting` | booted recently, normal so far |
| `healthy`, `suspended`, `off` | as named |

Flags ride beside the state. Those that matter alone (counted as abnormal):
`boot_loop`, `tools_flapping`, `heartbeat_intermittent` (yellow heartbeat:
Tools may be crashing), `memory_reclaimed` (ballooned, swapped or compressed),
`host_memory_pressure`, `vcenter_alarm` (a red alarm, by name),
`host_not_connected`, `long_running` (older than `long_running_hours`, 24 by
default), `consolidation_needed`. Those that only add detail:
`host_in_maintenance`, `tools_outdated`, `cpu_limited` (a CPU limit caps it
below full speed — apparent starvation that is configured, not the host) and
`memory_limited` (a memory limit below its RAM forces balloon/swap).
`scan(states=[...])` selects any state or flag, for example `["no_tools"]` or
`["long_running"]`.

The bulk read asks for about 35 properties per VM. A property an older vCenter
does not have is dropped and the read retried, rather than failing the scan,
and the result names what was dropped.

Results lead with `finding` / `findings`, keep the raw values, say what was
not read (`not_checked`, `available: false` with a reason), and are bounded to
fit a context window.

## What the diagnoses rest on

- **CPU starvation**: the VM's `cpu.ready.summation` as a percent per vCPU,
  and the host's `cpu.demand.average` against cores x MHz. Demand over 100% is
  overcommit; usage alone is reported as such, since it cannot exceed 100%.
- **Storage**: the hosts' `datastore.total{Read,Write}Latency` for the VM's
  datastores, `disk.{device,kernel,queue}Latency`, aborts and resets per
  device. High device latency points at the storage array (e.g. PowerFlex),
  high queue latency at the host's own queue.
- **The environment**: whether the healthy VMs beside a stuck one share its
  host, datastore and base disk (which argues against them) or not.
- **The boot**: `vmware.log` is the hypervisor's log, not the guest's. It shows
  how far a boot got (power-on or reset, firmware, first disk I/O, drivers,
  Tools), never the guest kernel's own words.
- **The guest's words**, when present: a serial port writing to a file
  (Windows EMS, a Linux kernel console) and the console screen. A VM without
  them is normal and the result says so.

## Developing and testing

The project is managed with [uv](https://docs.astral.sh/uv/); `uv.lock` is
committed, so `uv sync` reproduces the exact dev environment (the `dev`
dependency group — pytest, ruff, ty — installs by default). CI runs `uv sync
--frozen`.

```sh
uv sync                                        # set up the dev environment from the lock
uv run python -m pytest -m "not integration"   # the fast unit suite (what CI runs)
uv run python -m pytest                         # everything, including the vcsim integration tests
uv run ruff check . && uv run ruff format --check .
uv run ty check vsphere_triage                  # type check (Astral's ty)
```

Lint is `ruff` with `select = ["ALL"]` (a short, documented ignore list in
`pyproject.toml`); types are checked with `ty`, scoped to the package — the
tests use deliberately loose fixture typing. Python 3.12+.

CI (`.github/workflows/ci.yml`) runs lint, format, type check and the unit
suite on every push, Linux only. The Docker-backed integration suite is not run per-commit — dispatch it by
hand (Actions → CI → Run workflow → integration = true) or run it locally.

The integration tests build two simulated vCenters in Docker with
`vmware/vcsim:v0.52.0` and `vmware/govc:v0.52.0`. One uses the environments
layout and one the projects layout. They hold linked clones, stuck Windows
and Linux VMs, a pending question, a boot loop, an EMS stop code, an
environment id present on both vCenters and machine names reused across
environments. For an air-gapped machine, `docker save` both images and
`docker load` them there.

What the simulator cannot do, and how the tests deal with it:

- Its performance counters are random, so CPU and storage numbers come from a
  controlled fake of `VCenterSession.perf`. Everything else (inventory,
  folders, disk chains, serial ports, events, files) is read from vcsim.
- It has no `/screen` endpoint. The 404 path is tested against it; the image
  analysis is tested with generated screenshots.
- It has no host logs. That path is tested as "unavailable, said so".

## To confirm on a real vCenter

- The privilege `/screen` needs, and what it returns for a black console.
- The statistics level: what `QueryPerf` keeps past the realtime hour.
- The datastore counter instances (volume id from `ds:///vmfs/volumes/<id>/`).
  The datastore name and the last part of the URL are tried after it.
- The `vmware.log` lines a real stuck boot, a stun and an APD leave. The
  patterns in `vmlog.py` are heuristics, and every match is returned with
  its line.
- What EMS writes to the serial port on the Windows versions in the fleet.
- The vROps stat keys on your version. `vrops_list_stat_keys` reads them.
- Snapshot sizes: the simulator reports them as 0, so the delta/memory-state
  accounting from `layoutEx` is unit-tested only; confirm the GB figures and the
  `Sessions.View` privilege for sessions against a real vCenter.
- Host clock skew: `QueryDateTime` per host and the `config.dateTimeInfo`/
  `config.service` fields `check_host_time` reads — the simulator does not model
  NTP state or a drifting clock, so the classification is unit-tested only.
  Confirm the exact NTP service key (`ntpd` vs `chronyd`) and the skew at which
  your AD auth breaks.
- Datastore over-provisioning and APD/PDL: `summary.uncommitted` for thin space,
  and a host mount that is `mounted` but `accessible: false` with an
  `inaccessibleReason`. The simulator does not model either, so `check_datastores`
  is unit-tested only; confirm the exact `inaccessibleReason` values your arrays
  raise.
- Resource limits: a VM's `config.cpuAllocation.limit` / `memoryAllocation.limit`
  are read on the simulator, but confirm that a linked clone made from a template
  with a limit actually inherits it (the clone-inheritance note in
  `find_resource_limits` rests on that).
- `run_in_guest`: the simulator does not implement guest operations, so the
  guest-command path is unit-tested only (command shaping, the `*`-host transfer
  URL). Confirm against a real vCenter: the guest-operation privileges the
  account needs, that output capture via a redirected temp file and
  `InitiateFileTransferFromGuest` works for your Windows and Linux guests, and
  that the credentials behave as expected. `run_in_guest` is the one tool that
  changes a VM; keep its credentials scoped accordingly.
- That a guest reboot in your fleet logs a reset or guest-reboot event (so
  uptime is measured from the reboot, not power-on); if some reboots are
  silent to vCenter, pass `rebooted_at` from your orchestrator. The simulator
  cannot exercise this — the logic is covered by unit tests only.
- The `dcPath` for a datacenter that sits inside a folder, and a datastore
  name shared across two datacenters. The simulator has one flat datacenter,
  so these paths (full datacenter inventory path, datastore identity by moref)
  are correct by construction but unverified live.
- Whether `/folder` honours a suffix `Range` request; when it does not, a log
  larger than `VSPHERE_MAX_DOWNLOAD_BYTES` is reported as un-tailable rather
  than pulled whole.

## Releasing to PyPI

`.github/workflows/release.yml` publishes with **PyPI Trusted Publishing** — no
token lives in the repo. One-time setup at
[pypi.org/manage/account/publishing](https://pypi.org/manage/account/publishing):
add a publisher for project `vsphere-triage`, owner `Heknon`, repository
`vsphere-triage`, workflow `release.yml`, environment `pypi` (and the same on
test.pypi.org if you use the `testpypi` dispatch). Reserve the name first by
publishing `0.0.0`, since PyPI names are first-come.

Then releasing is a version bump:

1. raise `version` in `pyproject.toml`, commit, merge to `main`;
2. the workflow sees the new version has no `vX.Y.Z` tag, builds the sdist +
   wheel, verifies the wheel installs and imports, publishes to PyPI, then tags
   the commit and makes the GitHub release.

A merge that does not change the version stops at the gate. Tagging by hand
(`git tag v0.2.0 && git push origin v0.2.0`) still works, and
`workflow_dispatch` can publish the current branch to TestPyPI first.

Both workflows are Linux-only and single-job by design — a pure-Python package
needs no cross-platform matrix, which keeps the Actions bill small. The
Docker-backed integration suite is never on the per-commit path; dispatch it
when you want it.
