# Is the correlation a cause

The server weighs causes for you. This file is how you check that weighing
before you trust it, because the one mistake that makes a whole investigation
wrong is calling a coincidence a cause.

## The three questions

For the leading cause in `conclusion.causes`, ask:

1. **Is there a mechanism, or only a timestamp?** "The datastore was slow and
   the VM reads its disk to boot" is a mechanism. "The datastore was slow and
   the VM is stuck" with nothing between them is a coincidence until you find
   the read. The boot timeline and the `vmkernel` log are where the mechanism
   shows: the boot stalled *at* the minute the latency peaked, not merely in
   the same hour.

2. **Did the healthy VMs escape it?** This is invariant 4, and it is the
   strongest single test. If every VM on the slow datastore is stuck and every
   VM elsewhere is fine, the datastore is the cause. If healthy VMs sit on the
   same datastore, it is not — or not alone. `diagnose_vm`'s `environment`
   signals and `explain_group`'s comparison already compute this; read the
   `against` evidence, not only the `for`.

3. **What one check would separate the two leading causes?** Write it in the
   verdict's *next check* line even when you are fairly sure. The common ones:

   | Two causes | The check that splits them |
   | --- | --- |
   | Starved vs hung | the console across two captures; boot-to-Tools time |
   | This datastore vs a bad template | does the same base disk boot fine on another datastore right now? |
   | This host vs the whole cluster | are the stuck VMs only on one host, or spread? (`explain_group` on `host` vs `cluster`) |
   | Storage vs the guest | datastore latency in the boot window vs the boot timeline reaching the drivers |
   | New tonight vs every night | `vrops_compare_window` against previous days |

## Clock alignment

Every timestamp is UTC with its source named, but the sources are different
clocks. Before you say "the latency spike at 02:13 caused the reset at 02:13":

- The reset time comes from a vCenter event (vCenter's clock). The latency
  comes from a host counter (the host's clock). The Sahara reboot time comes
  from the runner (another clock).
- If they agree to within a sample interval (20 s realtime, 5 min historical),
  trust the correlation. If the reboot time from Sahara and the power-on event
  from vCenter disagree by minutes, say so and widen the window rather than
  trusting either to the second.

## Weak evidence, named as weak

Some signals look like causes and are not:

- **A single black screenshot** is not a hang: it could be early boot before
  the display, a splash screen, or a blanked display. Two captures, or the CPU
  counter, decide. The server takes two; if you only have one, say the console
  reading is inconclusive.
- **A reset event** is not a boot loop: one reset is the reboot you are
  investigating. Three or more in the window (`boot_loop` flag) is a loop.
- **A red vCenter alarm** names a symptom vCenter noticed, not a cause. Read
  what it is on; it often repeats what the counters already said.
- **"Tools not running"** on a `no_tools` VM is not a fault at all — Tools is
  not installed. Invariant: do not count it as stuck.

## When the server and your reading disagree

If `conclusion.causes` leads with a cause but the three questions above do not
support it — the mechanism is missing, or the healthy VMs share the blamed
thing — trust your reading and say both: "the server weighs X highest, but
healthy VMs share that datastore, so the window check is needed before X can be
confirmed". The server's weighing is a draft; the healthy-neighbour test and
the mechanism are the check on it.
