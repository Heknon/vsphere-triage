# Checking that a correlation is a cause

`diagnose_vm` and `explain_group` rank causes for you. Check the ranking before
you write the verdict: the most common mistake is calling a coincidence a
cause.

## Three questions

For the leading cause in `conclusion.causes`:

1. **Is there a mechanism, or only a matching time?** "The datastore was slow
   and the VM reads its disk to boot, and the boot stalled at the minute the
   latency peaked" is a mechanism. "The datastore was slow and the VM is stuck"
   is a coincidence until you find the link. The boot timeline and the
   `vmkernel` log show it.

2. **Did the healthy VMs avoid it?** If every VM on the slow datastore is stuck
   and every VM elsewhere is fine, the datastore is the cause. If healthy VMs
   sit on the same datastore, it is not the cause, or not the only one. The
   `environment` signals in `diagnose_vm` and the comparison in
   `explain_group` compute this; read the `against` evidence as well as `for`.

3. **What single check would separate the two leading causes?** Put it on the
   verdict's Next line even when you are fairly sure:

   | Two causes | Check that separates them |
   | --- | --- |
   | Starved vs hung | two console captures; boot-to-Tools time |
   | This datastore vs a bad template | does the same base disk boot on another datastore now? |
   | One host vs the whole cluster | are the stuck VMs on one host or spread out? (`explain_group` on `host`, then `cluster`) |
   | Storage vs the guest | datastore latency in the boot window vs how far the boot got |
   | New tonight vs every night | `vrops_compare_window` against previous days |
   | A host failure vs separate hangs | `cluster_events`: did HA restart these VMs? |

## Clocks

Results are in UTC with their source named, but the sources are different
clocks. A reset time comes from a vCenter event (vCenter's clock), latency from
a host counter (the host's clock), and the orchestrator's reboot time from the
runner (a third clock).

If they agree within one sample interval (20 s for realtime counters, 5 min for
historical), trust the correlation. If the orchestrator's reboot time and
vCenter's power-on event differ by minutes, say so and widen the window rather
than trusting either to the second.

## Signals that look like causes

- **One black screenshot** is not a hang: it can be early boot, a splash screen
  or a blanked display. Two captures, or the CPU counter, decide. `diagnose_vm`
  takes two; with only one, call the console reading inconclusive.
- **One reset event** is not a boot loop; it is usually the reboot you are
  investigating. Three or more in 30 minutes set the `boot_loop` flag.
- **A red vCenter alarm** names a symptom vCenter noticed. Read what it is on;
  it often repeats what the counters already say.
- **"Tools not running" on a `no_tools` VM** is not a fault; Tools is not
  installed.
- **An unclean-shutdown event after a `hard_reset`** is the reset itself, not a
  crash.

## When the ranking and your reading disagree

If `conclusion.causes` leads with a cause but the three questions do not
support it (no mechanism, or healthy VMs share what it blames), write both:
"the server ranks X highest, but healthy VMs share that datastore, so the
window check is needed before X can be confirmed." The ranking is a draft; the
mechanism and the healthy-neighbour test are the check on it.
