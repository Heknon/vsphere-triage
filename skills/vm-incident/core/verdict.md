# The verdict

End every investigation with these headings, each with `none` when empty. They
are the whole of what you say; no cause the evidence does not carry.

```
## Symptom
<what was seen, copied: the Sahara Tools error, which tests, when; or the fleet question asked>

## Identity
<the machine(s) as vcenter + moref, the environment id and its folder path, the vCenter,
 and the reboot time. Names only beside a moref, never alone.>

## Cause
<the likely cause from core/causes.md, with its confidence, and:
 for:     <each piece of evidence, with the number it rests on>
 against: <each piece that argues the other way, including healthy neighbours sharing the blamed thing>
 If busy_not_up: say explicitly whether it is booting slowly (and whether past the Sims timeout) or hung.>

## Ruled out
<the competing causes you weighed and dropped, each with the one fact that dropped it>

## Gaps
<what no tool could read: destroyed VM, no console endpoint, counters not kept, vROps not
 configured, Elastic unreachable, clocks that disagreed. Each is a gap, not a clean result.>

## Next
<the one check that would raise the confidence or separate the two leading causes
 (core/correlation.md), and — when the evidence calls for it — the action for a person
 (answer the question, reset, hold the VM before destroy). You do not take it.>
```

## What makes a verdict good

- **The cause names the layer, not the VM.** "CPU starvation on hosts esx-31
  and esx-32" is a cause someone can act on; "web-01 is slow" is a restatement
  of the symptom.
- **Every "for" line carries a number.** "ready time peaked at 38% per vCPU",
  "datastore write latency 180 ms for 6 minutes", not "high" and "slow".
- **The "against" is not empty for a real cause.** A cause worth writing has
  something that could have argued against it and did not. If you checked
  nothing against it, you have a guess.
- **A shared cause points at the population.** If it is the host or the
  datastore, the verdict says how many environments it is taking down, from the
  scan or `explain_group` — that is what turns one ticket into one fix.

## Two shapes of verdict, worked

**Shared infrastructure (the common case):**

> Cause: PowerFlex storage saturation on the pool behind datastore ds-17, high
> confidence. for: 29 of 33 stuck VMs are on ds-17; device latency peaked at
> 170 ms on four hosts from 02:09–02:17; all 29 rebooted in that window; boot
> timeline stops after the firmware. against: the four healthy VMs on ds-17
> rebooted before the window. Next: vrops_compare_window on ds-17 — is 02:10 a
> nightly spike? Action for storage: check what runs against that pool at 02:10.

**Slow, not broken:**

> Cause: the VM is booting slowly under CPU starvation, not hung, medium
> confidence. for: host esx-31 at 118% demand; ready time 38% per vCPU; the
> console is changing. against: nothing rules out a slow guest as well. The
> Sims wait was 5 min (rung 2) and boot-to-Tools here is past 9 min, so the
> Tools error is a timeout on a VM that would likely have come up. Next:
> re-capture the console in 3 min — is it at the logon screen? Action: none in
> vCenter; the fix is the host's load or the Sims timeout, for a person.

## Stop and ask, not a weak verdict

When the rungs you could reach do not support any cause — the vСenter tools are
missing, the environment is destroyed and events show nothing, every counter
came back "not kept" — write the symptom, the identity, and the gaps, and say
what you would need to go further. That is a complete answer. A cause asserted
past the evidence is not.
