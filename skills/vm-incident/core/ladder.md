# The ladder

Four rungs, top to bottom. Each one narrows what the next has to explain. You
climb from wherever you entered (SKILL.md says where); you never start at the
bottom.

The verdict you are building is in `core/verdict.md`. Fill it in as you climb.

## Rung 1 — Sahara: what failed, which environment, when

The Sahara MCP holds the test results. From the VMware Tools error:

1. `summarize_failures` on the cycle when more than a few tests failed: it
   groups them, so you read the handful of distinct problems. A Tools error
   spanning several environments is an infrastructure problem; one confined to
   one environment is that environment's.
2. From the failing step and its logs, read **the vCenter, the machine name and
   the environment id** out of the error's extra data, and **the time of the
   reboot**. These three plus the time are the whole of what the lower rungs
   need. Write them into the verdict's *identity* line.

If Sahara is not reachable, a person gives you the vCenter, env id, machine and
time; say you are starting at rung 3 on their word.

## Rung 2 — Sims / Twix: what Sims did, and how long it waited

In Elastic, for that environment id and time window:

1. What Sims asked the vCenter to do (create, reboot, destroy) and when.
2. What the vCenter answered, and any error Sims logged.
3. **How long Sims or Sahara waited for the machine before giving up.** This is
   the number that turns a slow boot into a Tools error. Write it into the
   verdict; a VM that comes up in nine minutes is not broken if the wait was
   fifteen, and is "lost to a timeout" if the wait was five.

If Elastic is not reachable, say so and climb on; the vCenter rungs do not
depend on it, but the "slow vs timed out" judgement is weaker without the wait.

## Rung 3 — vCenter: the machine, and the infrastructure under it

This is the rung the `vsphere-mcp` server was built for. Pick the entry that
matches how you came in.

### From a Sahara error — one machine

`diagnose_vm(vcenter, env_id=…, vm_name=…)`. One call runs every check in a
fixed order and returns a `finding`, a `conclusion` (causes with evidence for
and against), the `machine` state, the `environment` (the rest of its VMs), the
`cpu` and `storage` checks, the `boot` timeline from `vmware.log`, the
`serial_console`, and the `console`.

Read it in this order, which is invariants 2–5 made concrete:

1. **`machine.state`** — the one-word state. `core/causes.md` maps each to what
   it means. `no_tools` means Tools is not installed, so its absence says
   nothing: judge by CPU, console and boot log, not by Tools.
2. **`environment`** — are the other VMs of this environment stuck too, and
   where are the healthy ones? The `signals` list says whether only the stuck
   VMs share a host, datastore or base disk (points at it) or the healthy ones
   do too (argues against it).
3. **`cpu`** and **`storage`** — the two recurring causes. `cpu.host` over 100%
   demand with the VM's `vm_ready_percent_per_vcpu` high is starvation.
   `storage.where` says device (the array / PowerFlex) or the host's own queue.
4. **`conclusion.causes`** — already weighed, strongest first, each with
   `confidence` and the evidence lists. This is your draft verdict; do not
   discard it, but check it against `core/correlation.md` before you trust it.
5. **`boot`, `serial_console`, `console`** — only if CPU and storage are clean,
   or to confirm a guest cause. How far the boot got, the stop code if there is
   a serial console, what the screen shows.

### From a fleet question — many machines

`scan(vcenters=[…])` first. Read its `strongest_groups` and `counts_by_state`,
not the per-VM list. The strongest group is the finding: "29 of 210 on
datastore X, 1.9× the fleet rate". Then `explain_group(scan_id, dimension,
value)` on that group: it compares the stuck VMs with the healthy ones beside
them and runs the CPU and storage checks. Then `diagnose_vm` on two or three of
the group's `representatives` (the scan picked them) — not every VM.

Also read the scan's `hosts_over_cpu_threshold`, `hosts_near_memory_capacity`,
`hosts_not_connected` and `counts_by_flag`: a host or a flag common to the
stuck VMs is often the whole answer.

### An incident already over — the VMs are gone

`diagnose_window(vcenters, since, until)`. vCenter's events outlive the VMs, so
this still shows the resets, failed power-ons, and host and datastore pressure
in the window. It cannot show a destroyed VM's console or `vmware.log`; the
verdict's *gaps* line says so.

## Rung 4 — vROps: was this window unusual

The VMs are too short-lived for vROps, but the hosts, clusters and datastores
are not. Use it to answer "is this normal for this time of day?":

1. `vrops_find_resource(name, kind)` for the host, cluster or datastore the
   rung-3 checks named. It returns the id and suggests stat keys.
2. `vrops_compare_window(resource_id, stat_keys, since, until, baseline_days=7)`
   — the incident window against the same clock window on previous days. A
   datastore whose latency spikes every night at 02:10 is a scheduled job, not
   this environment; a host at 120% only tonight is new.
3. `vrops_get_alerts` on the resource and its parents for the window.

If vROps is not configured, say the history check could not be run; the rung-3
finding stands without it, only less sure whether it is recurring.

## Then write the verdict

`core/verdict.md`. If every rung came back clean — the VM was busy, the host
and storage healthy, the boot reached the drivers — the cause is in the guest,
and the verdict says so and points at the console and the serial log as the
only remaining evidence.
