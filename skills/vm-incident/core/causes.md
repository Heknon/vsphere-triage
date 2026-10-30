# The causes, and what rules each out

Every state a `diagnose_vm` or `scan` returns, and every cause the conclusion
weighs, is here with the evidence for it and the evidence against. Read the row
for the state you got, then confirm the cause against its "against" column
before you write it into the verdict. A cause with no "against" checked is a
guess, not a diagnosis.

## The machine states

One VM has exactly one state. The state is the symptom; the cause is below it.

| State | What it means | First thing to read |
| --- | --- | --- |
| `hung` | booted long ago, Tools never up, almost no CPU | the console (frozen?) and `vmware.log` (how far?) |
| `busy_not_up` | booted long ago, Tools never up, burning CPU | CPU starvation, or Windows still working — see below |
| `booted_not_up` | booted long ago, Tools never up, CPU in between | the boot timeline; Tools stuck starting its scripts |
| `blocked_on_question` | waiting on a VM question | the question text; this *is* the cause |
| `paused` | powered on, hypervisor not running it | why it was paused; this is the cause |
| `no_tools` | Tools not installed | **do not call this stuck**; judge by CPU, console, boot log |
| `lost_heartbeat` | Tools was up, heartbeat red | the guest or Tools died after boot |
| `inaccessible` | vCenter cannot reach it | the host's connection state |
| `no_boot_time` | powered on, no boot time reported | fall back to the console and events |
| `suspended`, `off` | as named | whether Sims did it (rung 2) |

## The causes

| Cause | Evidence for | Evidence against (check before you write it) |
| --- | --- | --- |
| **ESXi CPU overcommit** | affected VMs on hosts past 100% demand; `vm_ready_percent_per_vcpu` high during boot; CPU busy, console changing; Windows clock-watchdog `0x101` or Linux soft lockup | host below capacity; ready time low; the VM uses almost no CPU |
| **A configured CPU limit (not the host)** | `diagnose_vm` / `scan` flags `cpu_limited`, or `find_resource_limits` lists it: a CPU limit (MHz) is set, so the VM is capped below full speed — the same symptom as starvation. A linked clone inherits it from its template | no CPU limit set; the host itself is overcommitted (then it is starvation, not a config cap) |
| **PowerFlex / storage saturation** | affected VMs share datastores on one pool; device latency and IOPS high in the boot window; a rebuild or a noisy volume; Windows `0x7A`/`0x77`/`0xF4`/`0x7B`; `vmkernel` path or latency warnings | latency normal; the healthy VMs boot fine from the same datastore |
| **Datastore full, over-provisioned, or APD/PDL** | `check_datastores`: the datastore is nearly full (a thin disk then stalls on write), thin disks are provisioned past capacity, or a host has it mounted but unreachable (all-paths-down / permanent-device-loss) — every VM on it there wedges at once. A datastore holding a template's base disk takes every clone down | the datastore has room, is under capacity, and every host reaches it |
| **Linked-clone boot storm** | many clones of one base disk stuck together, while clones of other bases are fine; the shared datastore slow | clones of the same base booted fine at the same time |
| **Host memory pressure** | the VM's host near memory capacity; the VM ballooned, swapped or compressed (`memory_reclaimed` flag) | host memory healthy; nothing reclaimed |
| **A configured memory limit** | `memory_limited` flag, or `find_resource_limits`: a memory limit is set below the VM's RAM, so the host must balloon or swap it even when the host has memory to spare — reclamation that is configured, not host pressure. Inherited by a clone from its template | no memory limit, or a limit at or above the VM's RAM (which caps nothing) |
| **Pending VM question** | `runtime.question` set, with its choices | no question |
| **A virtual device blocks the boot** | `get_vm_hardware` / `diagnose_vm`'s hardware findings: a disconnected boot NIC (PXE/DHCP fails), a stale ISO mounted on the CD-ROM, a device in an error state | every device connected and healthy |
| **Snapshots filling the datastore / slowing I/O** | `find_vms_by_snapshot` or `diagnose_vm`'s snapshots block: a large or old snapshot, a deep redo chain, or consolidation-needed (a delete that left growing delta disks) | no snapshots, or small and recent |
| **The vCenter is exhausted** (not a VM) | SSL EOF / resets / timeouts across callers; `check_vcenters` shows a high or climbing session count or a slow login | the vCenter's sessions and login are normal |
| **A host's clock has drifted** (not a VM) | `check_host_time`: a host with NTP off / no servers, or a clock skewed from vCenter — skew breaks TLS handshakes and, past ~300 s, Kerberos/AD auth, so it reads as SSL/handshake errors fleet-wide, the same symptom as exhaustion but a different fix | NTP running with a tight clock on every host; the session count is what is high |
| **Windows crashed (stop error)** | a stop code on the EMS serial console, or a blue screen on the console | the console shows the logon screen |
| **Windows still working (slow, not hung)** | CPU busy; the console changes; on screen: updates, "Getting devices ready", a disk check | the console is frozen; CPU near zero |
| **Guest hung early in boot** | near-zero CPU; console black and unchanged across two captures; `vmware.log` stops after the firmware or the first disk I/O; host and storage healthy | the console changes; the boot reached the drivers or Tools |
| **Guest booted, Tools did not start** | a logon prompt or a guest IP reported; Tools not running; host and storage healthy | Tools running |
| **The host fell off vCenter** | `host_not_connected` flag; many VMs on that host inaccessible at once | the host is connected |
| **Something reset or moved it** | HA, migration or reset events not from Sims (rung 2) in the window | no such event |

## Starved versus hung — the split that matters most here

A `busy_not_up` VM is the ambiguous one, and the one your fleet hits. Use three
readings, in order:

1. **Boot-to-Tools time, if the sweeper or history has it.** If the fleet
   median is ~70 s and this VM has been booting nine minutes but its CPU is
   working, it is slow, not dead. The rung-2 wait decides whether "slow" is
   also "a Tools error": slow past the timeout raises the error even on a VM
   that will come up.
2. **The console across two captures.** Changing → the guest is doing something
   (slow). Frozen and black → hung.
3. **Ready time and host demand.** High → starved by the host, which is a
   *shared* cause: look at the host's other VMs, not this one.

Write the split explicitly: "booting slowly under CPU starvation, would have
come up after the Sims timeout" is a different verdict, and a different fix,
from "hung in early boot".

## The stop codes worth knowing

When a serial console (EMS) or the console OCR gives a Windows stop code, the
server already maps it to a layer. Trust the mapping as a hint, not a cause:
`0x7A`/`0x77` (paging I/O failed or timed out) and `0x7B`/`0xF4` point at
storage; `0x101` (clock watchdog) and `0x133` (DPC watchdog) point at CPU
starvation. A storage stop code on a VM whose datastore also shows high latency
is two pieces of evidence for one cause; on a VM whose datastore is clean it is
one piece pointing somewhere the infrastructure checks did not look — say so
and do not force it.

## When nothing matches

Every state booting normally, host and storage clean, boot reached Tools, no
question, no reset: then the environment is fine and the Tools error was
transient or upstream. Say that. "No cause stands out from what could be read"
is an honest verdict; a forced cause is not.
