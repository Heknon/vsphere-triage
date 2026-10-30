---
name: vm-incident
description: Diagnose why a Sahara test environment's machines are stuck or unreachable, from the symptom to a named cause, across the four layers Sahara, Sims/Twix, vCenter and vROps. Use when Sahara reports VMware Tools errors, a machine is stuck on boot or after a reboot, hung mid-run, slow to come up, an environment will not come up, a test hangs waiting for its environment, a machine is blocked on a VM question or wedged by a virtual device (a disconnected adapter, a stuck ISO), or someone asks to find stuck, hung or leftover VMs across the vCenters and understand why. Also when the vCenter API itself is failing - SSL EOF errors, connection resets or timeouts, often connection or session exhaustion. Covers the recurring causes seen here - ESXi CPU overcommit and PowerFlex storage saturation - and tells a VM that is booting slowly from one that is hung. It reads; it changes nothing. Written so the answer comes from a ladder and a cause table, not from judgment.
---

# VM incident

An environment's machines are stuck — not booting, not coming back after a
reboot, hung mid-run, or unreachable — or the vCenters themselves are refusing
connections. This skill is the fixed route from that symptom to a cause you can
name, with the evidence for it and the evidence against. You follow a ladder
and read a table; you do not diagnose from principles.

"Stuck" is not only "stuck after a reboot": a machine that never finished its
first boot, one that hangs hours into a run, one slow to come up, one blocked
on a VM question, and one wedged by a disconnected adapter or a stuck ISO are
all this skill's work. So is a vCenter that is throwing SSL EOF errors or
resetting connections — see "When the vCenter is the problem" below.

The machines are short-lived (minutes to a day), their names are reused by the
next environment, and they are spread by load across nine vCenters. So the
first rule is the one that everything else rests on: **carry the identity, not
the name.** A VM is its vCenter and its moref. A name means something only
inside its environment folder.

Read this file, then load only the file the step names. Every path ends in a
**verdict** you write down (`core/verdict.md`), or in **stop and ask**, which
means you write what is missing and ask a person.

This skill does not act. Every tool it calls reads. It never powers, resets,
answers a question, or changes a VM: that is Sims' job and a person's decision.
When the evidence says an action is needed, the verdict says which, and stops.

## The four layers, and the tools for each

| Layer | Holds | Reached by |
| --- | --- | --- |
| **Sahara** | the failing tests, the environment id, the machine names, the reboot time, the VMware Tools error | the Sahara MCP |
| **Sims / Twix** | what Sims asked the vCenter and when, its errors, how long it waited | their logs in Elastic |
| **vCenter** (×9) | live VM state, console, `vmware.log`, events, host and datastore counters | the `vsphere-mcp` server (read-only) |
| **vROps** | days of host, cluster and datastore history; alerts | `vsphere-mcp`'s `vrops_*` tools |

If the `vsphere-mcp` tools are not present, stop and ask: this skill cannot
reach vCenter without them. If the Sahara MCP or Elastic is not present, say
which rungs of the ladder you cannot climb, and work the ones you can.

## The two ways in

| You have | Start at |
| --- | --- |
| A Sahara VMware Tools error (it names the vCenter, the env id, the machine) | `core/ladder.md`, rung 3: `diagnose_vm` |
| A question about the fleet ("anything stuck on these vCenters?") | `core/ladder.md`, rung 3: `scan`, then `explain_group` |
| An incident from earlier, the environment now gone | `core/ladder.md`, rung 3: `diagnose_window` |
| "Which environments have lived too long?" | `find_old_environments`; this is a cleanup question, not an incident — read `core/ladder.md` only if the old ones are also stuck |

Climb the whole ladder from where you enter. Do not start at the bottom: a
VM's counters mean nothing without the time and the symptom from the top.

## When the vCenter is the problem, not a VM

Sometimes the symptom is the vCenter API itself: SSL EOF errors, connection
resets, or timeouts, hitting Sims, Sahara and this server alike. That is not a
stuck VM — it is usually the vCenter at its connection or session limit, and no
amount of looking at one machine explains it.

Start with **`check_vcenters`** for the counts, then **`vcenter_sessions`** on
the vCenter that is throwing errors: it groups the open sessions by user, source
IP and client and flags the one leaking them (many sessions from one client,
many idle past the timeout). A high or climbing count is the symptom; the
grouping names the culprit. The verdict
then names the vCenter and its session pressure, and the action — shedding
sessions, raising the limit — is for the bare-metal team, not something this
server does. If the session count is not visible (the read-only account may not
be allowed the global list, and `check_vcenters` says so), the login time and
the pattern of resets across callers are still the signal, and vROps' vCenter
session metrics are the history.

A VM diagnosis that keeps failing with a dropped-connection error is the same
story from below: run `check_vcenters` before trusting any one VM's result.

SSL / handshake errors have a second root that is not exhaustion: a host whose
**clock has drifted**. Skew breaks TLS, and past about 300 s it breaks
Kerberos/Active Directory auth outright, so it reads as the same SSL errors
fleet-wide. When `check_vcenters` shows the session count healthy but the errors
persist, run **`check_host_time`**: it reports each host's NTP configuration and
its clock skew from vCenter, and names the hosts that have drifted.

## When a read cannot answer: run_in_guest

Every tool above reads. One does not: **`run_in_guest`** executes a command
inside the guest OS through VMware Tools. Reach for it only when the read-only
evidence leaves a real gap a command would close — "is the guest actually
responsive, or just painting a static console?", reading a file or a service
state from inside the guest — and the guest has Tools running (without Tools
there is no guest-ops channel; fall back to the console, serial and boot log).
It needs guest credentials, it is the one tool that acts on the VM rather than
observing it, and it runs exactly the command given — so prefer a read first,
keep the command a diagnostic (not a change), and record what you ran in the
verdict. It is not a substitute for the shared-cause checks: a responsive guest
on a starved host is still starved.

## The steps

| Step | Load |
| --- | --- |
| The ladder, rung by rung, top to bottom | `core/ladder.md` |
| What each cause looks like, and what rules it out | `core/causes.md` |
| Whether a correlation is a cause | `core/correlation.md` |
| What you write at the end | `core/verdict.md` |

## Invariants

1. **Identity is `(vcenter, moref)`.** Carry it from the first tool call to
   the last. Never look a machine up by name outside its environment folder;
   the next environment reused the name. A follow-up on a VM that no longer
   exists says *destroyed* — that is an answer, not a retry with a different VM.

2. **Population before individual.** Before explaining one stuck VM, find how
   many are stuck like it and what they share (`explain_group`, or the
   environment view inside `diagnose_vm`). One stuck VM is an anecdote; 29 of 33
   on one datastore in six minutes is a cause.

3. **Shared cause before guest cause.** Read the host and the storage before
   blaming the guest. Both recurring causes here are shared infrastructure:
   ESXi CPU overcommit and PowerFlex storage saturation.

4. **A healthy neighbour is evidence.** Before blaming a host, datastore or
   base disk, check whether the *healthy* VMs beside the stuck ones share it.
   If they do, it argues against that cause. `diagnose_vm` and `explain_group`
   report this; read it.

5. **Starved is not hung.** A VM busy on CPU with a changing console is booting
   slowly, not hung; the Tools error is then a timeout in Sims or Sahara, not a
   dead VM. `core/causes.md` has the split. Say which in the verdict.

6. **A shared timestamp is not a cause.** Name the evidence for each claim, the
   competing explanation, and the one check that would separate them
   (`core/correlation.md`).

7. **Missing data is not "nothing happened".** A tool that says "no events in
   window", "counters not kept at this statistics level", "console endpoint
   404", "PowerFlex not configured" or "VM destroyed" has told you what it could
   not see. Record it as a gap; do not read it as a clean result.

8. **Clocks differ.** Sahara, Sims, each ESXi host, vCenter and vROps keep their
   own clocks, and every result is in UTC with its source's clock named. A
   correlation across layers is only as good as the alignment; when two clocks
   disagree by more than the window, say so.

9. **Never act.** No reset, no answering a VM question, no power change. When
   the evidence calls for one, the verdict names it and hands it to a person.

## What you say when you finish

The headings in `core/verdict.md`, each with `none` when empty: the symptom,
the identity, the likely cause with its evidence for and against, the competing
causes ruled out, the gaps in what you could read, and the next check or the
action for a person. Nothing more; no cause the data does not support.

## The environment these facts rest on

The `vsphere-triage` tool names, result shapes and thresholds in this skill are
those of the server in this repository (the README is the reference).
The recurring causes — host CPU demand past 100%, PowerFlex datastore latency
in the hundreds of milliseconds — are the two incidents this fleet has seen;
`core/causes.md` carries the rest. When a tool's result shape here and the
server disagree, the server is right and this skill is stale: say so.

`glossary.md` fixes the words. Use them and no synonyms.
