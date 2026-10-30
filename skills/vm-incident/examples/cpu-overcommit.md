# Worked example: the Tools error was a timeout on a starved VM

Copy the order of the rungs and the shape of the verdict. This is the CPU case:
the VM was not broken, it was booting slowly on an overloaded host, and the
Tools error was a timeout.

## The ask

> Sahara says the reboot step failed for web-01 in env-8812 on vc-04 with a
> VMware Tools error at 02:14. Why?

## Rungs

1. **Sahara.** `summarize_failures` on the cycle: the Tools error is in three
   environments tonight, all on vc-04. The error's extra data gives vCenter
   `vc-04`, machine `web-01`, env `env-8812`, reboot at 02:14:02Z. → identity
   written.

2. **Sims/Twix (Elastic).** Sims asked vc-04 to reboot the environment at
   02:13:40 and waited **5 minutes** for Tools before raising the error. No
   error from the vCenter itself. → the Sims wait is 5 min; hold that.

3. **vCenter.** `diagnose_vm(vcenter="vc-04", env_id="env-8812",
   vm_name="web-01")`:
   - `machine.state` = `busy_not_up`: booted 14 min ago, Tools not running, CPU
     at 89% of its 2 vCPUs.
   - `environment`: 4 of 6 VMs in env-8812 are busy_not_up, all on hosts
     esx-31 and esx-32; the 2 healthy ones are on esx-40. Signal:
     `only_abnormal_on host`.
   - `cpu`: `vm_ready_percent_per_vcpu` peaked at 38%; `cpu.host` esx-31 at
     118% demand, overcommitted. `storage`: latency normal.
   - `conclusion.causes[0]`: CPU starvation, high confidence; "the VM is busy,
     so it is more likely booting slowly than hung".
   - `console` (one capture, the sim has none on a real vCenter take two): on a
     real run, changing.

4. **vROps.** `vrops_find_resource("esx-31", "HostSystem")`, then
   `vrops_compare_window` on `cpu|demandPct` for 02:00–02:30 against 7 days:
   tonight's 118% is above every previous night's peak for that window. New,
   not nightly.

## Check (core/correlation.md)

- Mechanism: ready time *during the boot window*, not just the same hour. Yes.
- Healthy neighbours: the 2 healthy VMs are on esx-40, not the overcommitted
  hosts. They escaped it. Strong.
- Slow vs hung: CPU busy, console changing, boot-to-Tools past 9 min while the
  Sims wait was 5 min → booting slowly, lost to the timeout.

## Verdict

> **Symptom** Sahara VMware Tools error on the reboot step, web-01 and 3 other
> VMs in env-8812 (and two more environments on vc-04), 02:14Z.
> **Identity** vc-04 / vm-2231 (web-01), env-8812 at /DC0/vm/environments/env-8812; reboot 02:14:02Z.
> **Cause** Booting slowly under ESXi CPU overcommit, not hung — medium-high.
> for: hosts esx-31 and esx-32 at 118% demand; ready time 38% per vCPU during
> boot; console changing; the environment's healthy VMs are on esx-40.
> against: nothing rules out an additionally slow guest, but no sign of one.
> The Sims wait was 5 min and boot-to-Tools was past 9 min, so the error is a
> timeout on VMs that would likely have come up.
> **Ruled out** Storage: datastore latency normal, healthy VMs share the
> datastore. Guest hang: CPU busy, console changing.
> **Gaps** boot-to-Tools history is from this run only; no fleet baseline yet.
> **Next** re-capture web-01's console in 3 min — at the logon screen? Action
> for a person: the overcommit on esx-31/32 (placement, or what else runs
> there), or raise the Sims reboot timeout above the boot time these hosts give.

Notice what the verdict does not say: it does not say web-01 is broken. The
fix is a host's load or a timeout, and it is for a person.
