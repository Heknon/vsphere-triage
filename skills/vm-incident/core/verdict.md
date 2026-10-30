# The verdict

End every investigation with these six headings. Write `none` under a heading
with nothing to say. Do not add a cause the evidence does not support.

```
## Symptom
<what was reported, quoted: the VMware Tools error, which tests, when; or the fleet question asked>

## Identity
<each VM as vcenter / moref, with its name beside it; the environment id and folder path;
 the reboot time. Never a name without a moref.>

## Cause
<the cause from core/causes.md and its confidence, then:
 for:     <each piece of evidence, with its number>
 against: <each piece that argues the other way, including healthy neighbours that share the blamed thing>
 For busy_not_up, say whether it was booting slowly (and whether slower than the orchestrator's wait) or hung.>

## Ruled out
<each competing cause you considered, with the one fact that ruled it out>

## Gaps
<what could not be read: a destroyed VM, no console endpoint, counters not kept, vROps or
 PowerFlex not configured, no guest access, the log store unreachable, clocks that disagreed;
 and how to enable each missing source>

## Next
<the one check that would raise confidence or separate the two leading causes
 (core/correlation.md); and, when the evidence calls for one, the action for a person
 (answer the question, fix the host, change the timeout, keep the VM before it is destroyed).
 List any acting tool you ran (run_in_guest, reboot_guest, hard_reset, a guest probe) and why.>
```

## What a good verdict has

- **The cause names a layer, not the VM.** "CPU starvation on hosts esx-31 and
  esx-32" is something a person can act on. "web-01 is slow" restates the
  symptom.
- **Every "for" line has a number.** "Ready time peaked at 38% per vCPU",
  "datastore write latency 180 ms for 6 minutes", not "high" or "slow".
- **The "against" line is filled in.** A real cause has something that could
  have argued against it and did not. If you checked nothing against it, it is
  a guess.
- **A shared cause gives the count.** For a host or datastore cause, say how
  many VMs and environments it affects, from `scan` or `explain_group`. That
  turns many tickets into one fix.

## Two examples

**Shared infrastructure (the common case):**

> Cause: storage saturation on the pool behind datastore ds-17, high
> confidence. for: 29 of 33 stuck VMs are on ds-17; device latency peaked at
> 170 ms on four hosts from 02:09 to 02:17; all 29 rebooted in that window;
> their boot timelines stop after the firmware. against: the four healthy VMs
> on ds-17 rebooted before the window. Next: `vrops_compare_window` on ds-17
> to see whether 02:10 is a nightly spike. Action for the storage team: what
> runs against that pool at 02:10.

**Slow, not broken:**

> Cause: the VM was booting slowly under CPU starvation, not hung, medium
> confidence. for: host esx-31 at 118% CPU demand; ready time 38% per vCPU;
> the console was changing. against: a slow guest is not ruled out as well.
> The orchestrator waited 5 min (rung 2) and boot-to-Tools here was over 9 min,
> so the Tools error is a timeout on a VM that would probably have come up.
> Next: capture the console again in 3 min to see whether it reached the logon
> screen. Action for a person: reduce the load on esx-31, or raise the
> orchestrator's timeout.

## When no cause is supported

If the rungs you could reach support no cause (the vCenter tools are missing,
the environment was destroyed and the events show nothing, every counter came
back "not kept"), write the Symptom, Identity and Gaps, and say what you would
need to go further. That is a complete answer.
