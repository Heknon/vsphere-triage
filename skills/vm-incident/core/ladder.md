# The ladder

Four rungs, from the orchestrator down to vROps. Each one narrows what the next
has to explain. Start at the rung SKILL.md points you to and work down; fill in
the verdict (`core/verdict.md`) as you go.

## Rung 1: the orchestrator. What failed, where, when

From your orchestrator or monitoring:

1. If more than a few tests failed, group the failures first. A Tools error
   across several environments points at infrastructure; one confined to a
   single environment points at that environment.
2. From the failing step and its logs, take **the vCenter, the machine name,
   the environment id and the reboot time**. The lower rungs need nothing
   else. Write them on the verdict's Identity line.

If the orchestrator is not reachable, ask a person for the vCenter, environment
id, machine and time, and note in the verdict that you started at rung 3 on
their word.

## Rung 2: the creator/runner logs. What it did, how long it waited

In your log store, for that environment id and time window:

1. What the orchestrator asked vCenter to do (create, reboot, destroy), and
   when.
2. What vCenter answered, and any error it logged.
3. **How long the orchestrator waited for the VM before raising the error.**
   This decides whether a slow boot counts as broken. A VM that comes up in
   nine minutes is fine with a fifteen-minute wait and "lost to a timeout" with
   a five-minute one. Write the wait in the verdict.

If the log store is not reachable, say so and continue. The vCenter rungs do
not depend on it, but without the wait you cannot say whether a slow VM timed
out.

## Rung 3: vCenter. The VM and the infrastructure under it

### One VM, from a Tools error

`diagnose_vm(vcenter, env_id=…, vm_name=…)`, or with `moref=` if you have it.
Pass `rebooted_at` when the orchestrator logged the reboot time. It returns
`finding`, `conclusion` (ranked causes with evidence for and against),
`machine`, `environment`, `cpu`, `storage`, `boot`, `serial_console`,
`console`, `snapshots`, `events` and `evidence_gaps`.

Read it in this order:

1. **`machine.state`**: one word; `core/causes.md` says what each means.
   `no_tools` means Tools is not installed, so its absence says nothing: judge
   that VM by CPU, console and boot log.
2. **`environment`**: are the environment's other VMs stuck too, and where are
   the healthy ones? Its `signals` say whether only the stuck VMs share a host,
   datastore or base disk (points at it) or the healthy ones share it too
   (argues against it).
3. **`cpu`** and **`storage`**: `cpu.host` with demand over 100% and a high
   `vm_ready_percent_per_vcpu` is starvation. `storage.where` says whether high
   latency is on the array (device) or the host's own queue.
4. **`conclusion.causes`**: already ranked, strongest first, each with a
   `confidence` and its evidence. Treat it as a draft verdict and check it
   with `core/correlation.md`.
5. **`boot`, `serial_console`, `console`**: how far the boot got
   (`boot.timeline.last_stage`), any stop code, and what the screen shows. Read
   these when CPU and storage are clean, or to confirm a guest cause.
6. **`conclusion.not_checked`** and **`evidence_gaps`**: copy them to Gaps.

### Many VMs, from a fleet question

`scan(vcenters=[…])`. Read `strongest_groups` and `counts_by_state` before the
per-VM list. The strongest group is usually the finding, e.g. "29 of 210 on
datastore vc-04:ds-17, 1.9x the fleet rate". Also read
`hosts_over_cpu_threshold`, `hosts_near_memory_capacity`, `hosts_not_connected`
and `counts_by_flag`; a host or flag common to the stuck VMs is often the
answer.

Then `explain_group(scan_id, dimension, value)` on that group. It compares the
group's abnormal VMs with the healthy VMs beside them and reads host CPU and
datastore latency over their boot window. Then `diagnose_vm` on two or three of
the `representatives` it returns, not on every VM.

### An incident that is over

`diagnose_window(vcenters, since, until)`. vCenter's events outlive the VMs,
so it still shows resets, failed power-ons, and host and datastore pressure in
the window. A destroyed VM's console and `vmware.log` are gone: put that under
Gaps. Each vCenter's result says whether its CPU and storage counters for the
window could be read; when they could not, that is not evidence of no
pressure.

## Rung 4: vROps. Was this window unusual

The VMs are too short-lived for vROps, but hosts, clusters and datastores are
not. Use it to ask whether the pressure is normal for this time of day:

1. `vrops_find_resource(name, kind)` for the host, cluster or datastore rung 3
   pointed at. It returns the id and suggests stat keys.
2. `vrops_compare_window(resource_id, stat_keys, since, until,
   baseline_days=7)`: the incident window against the same hours on previous
   days. Latency that spikes at 02:10 every night is a scheduled job, not this
   environment; a host at 120% only tonight is new.
3. `vrops_get_alerts` on the resource for the window.

If vROps is not configured, say the history check was not possible. The rung 3
finding stands, but you cannot say whether it recurs.

## Then write the verdict

`core/verdict.md`. If every rung is clean (the VM was busy, host and storage
were healthy, the boot reached the drivers), the cause is in the guest: say so,
and point at the console, the serial console and the guest probes as the
remaining evidence.
