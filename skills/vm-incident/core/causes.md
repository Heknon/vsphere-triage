# States and causes

Find the row for the state you got, then the cause. Before you write a cause
in the verdict, check its "against" column: a cause you did not test against
anything is a guess.

## VM states

Each VM has exactly one state. The state is the symptom; the cause is below.

| State | Meaning | Read first |
| --- | --- | --- |
| `hung` | booted over 10 min ago, Tools not running, CPU at or below 100 MHz | the console (frozen?) and `vmware.log` (how far did the boot get?) |
| `busy_not_up` | booted over 10 min ago, Tools not running, CPU at or above half its vCPUs | CPU starvation, or Windows still working: see "Starved or hung" |
| `booted_not_up` | booted over 10 min ago, Tools not running, CPU in between | the boot timeline; Tools may be stuck running its startup scripts |
| `blocked_on_question` | a VM question is pending | the question text; often caused by a full datastore or lost storage paths |
| `paused` | powered on but not running | why it was paused; a full thin datastore pauses VMs |
| `no_tools` | Tools not installed | **not stuck by itself**; judge by CPU, console and boot log |
| `lost_heartbeat` | Tools was running, heartbeat now red | the guest or Tools died after boot |
| `inaccessible` | vCenter cannot reach the VM | the host's connection state; the datastore's reachability |
| `no_boot_time` | powered on, no boot time reported | the console and the events |
| `booting` | booted under 10 min ago | nothing yet; normal |
| `suspended`, `off` | as named | whether the orchestrator did it (rung 2) |

## Causes

| Cause | Evidence for | Evidence against |
| --- | --- | --- |
| **ESXi CPU overcommit** | stuck VMs on hosts over 100% CPU demand; `vm_ready_percent_per_vcpu` high during the boot; VM CPU busy, console changing; Windows `0x101` or a Linux soft lockup | host under capacity; ready time low; the VM uses almost no CPU |
| **A configured CPU limit** | the `cpu_limited` flag, or `find_resource_limits` lists the VM: a limit caps it below full speed, which looks like starvation. A linked clone inherits its template's limit | no limit; or the host itself is overcommitted |
| **Storage saturation** | stuck VMs share datastores on one pool or array; device latency and IOPS high in the boot window; Windows `0x7A`, `0x77`, `0xF4` or `0x7B`; `vmkernel` path or latency warnings | latency normal; healthy VMs boot fine from the same datastore |
| **Datastore full, over-provisioned or unreachable** | `check_datastores`: the datastore is nearly full (a thin disk stalls on write), thin disks provisioned past capacity, or a host has it mounted but cannot reach it (APD/PDL). VMs on it stall, pause or wait on a question together. A datastore holding a template's base disk takes every clone with it | the datastore has space, is within capacity, and every host reaches it |
| **PowerFlex backend trouble** | `powerflex_health` shows a failed SDS or device, a rebuild or rebalance, or failed capacity; or `powerflex_protection_domains` shows the datastore's domain carrying most of the IOPS. `powerflex_affected_vms` lists the VMs on it | the backend is healthy and traffic is spread out |
| **Linked-clone boot storm** | many clones of one base disk stuck together, clones of other bases fine, the shared datastore slow | clones of the same base booted fine at the same time |
| **Host memory pressure** | the host near memory capacity; the VM ballooned, swapped or compressed (`memory_reclaimed`) | host memory fine; nothing reclaimed |
| **A configured memory limit** | the `memory_limited` flag, or `find_resource_limits`: a limit below the VM's RAM forces ballooning or swapping even when the host has memory | no limit, or a limit at or above the VM's RAM |
| **A failing host** | `get_host_health` shows a red hardware sensor (power supply, fan, temperature, memory); or `cluster_events` shows the host failed, was isolated or lost its connection | sensors green; the host connected throughout |
| **HA restarted the VMs** | `cluster_events` shows vSphere HA restarted them after a host failed; the VMs rebooting is expected | no HA restart in the window |
| **Pending VM question** | `runtime.question` is set, with its choices | no question |
| **A virtual device blocks the boot** | `get_vm_hardware` or `diagnose_vm`: a disconnected boot NIC (PXE/DHCP fails), an ISO left mounted, a device in error | every device connected and healthy |
| **Snapshots filling the datastore or slowing I/O** | `find_vms_by_snapshot` or `diagnose_vm`: a large or old snapshot, a deep redo chain, or consolidation needed | no snapshots, or small and recent |
| **vCenter session exhaustion** (not a VM) | SSL EOF, resets or timeouts across callers; `check_vcenters` shows a high or climbing session count | sessions and login time normal |
| **A host clock has drifted** (not a VM) | `check_host_time`: NTP off or without servers, or a clock skewed from vCenter. Skew breaks TLS, and past about 300 s Kerberos/AD auth, so it looks like exhaustion | NTP running and clocks tight on every host |
| **Windows crashed** | a stop code on the serial console (EMS), a blue screen on the console, or a bugcheck from `investigate_windows_boot` | the console shows the logon screen |
| **Windows still working (slow, not hung)** | CPU busy; the console changes; the screen shows updates, "Getting devices ready" or a disk check | the console is frozen; CPU near zero |
| **Guest hung early in boot** | near-zero CPU; console black and unchanged across two captures; `vmware.log` stops after the firmware or the first disk I/O; host and storage healthy | the console changes; the boot reached the drivers or Tools |
| **Guest booted, Tools did not start** | a logon or login prompt on the console, or a guest IP reported; Tools not running; host and storage healthy | Tools running |
| **Something reset or moved the VM** | HA, migration or reset events not ordered by the orchestrator (rung 2) in the window | no such event |

## Starved or hung

`busy_not_up` is the ambiguous state and the common one. Decide with three
readings, in this order:

1. **Boot-to-Tools time.** If the usual time is about 70 s and this VM has been
   booting for nine minutes with its CPU working, it is slow, not dead. The
   orchestrator wait (rung 2) decides whether slow also produced a Tools error:
   a VM slower than the wait raises the error even if it would have come up.
2. **The console across two captures.** Changing: the guest is working. Frozen
   and black: hung. Frozen with text (a login prompt): it booted and Tools did
   not start.
3. **Ready time and host demand.** High means the host is starving it, which is
   a shared cause: look at the host's other VMs.

Write the result explicitly. "Booting slowly under CPU starvation, would have
come up after the orchestrator's timeout" and "hung in early boot" are
different verdicts with different fixes.

## Stop codes

When the serial console, the console OCR or `investigate_windows_boot` gives a
Windows stop code, the server maps it to a layer. Treat the layer as a hint:

- `0x7A`, `0x77` (paging I/O failed or timed out), `0x7B`, `0xF4`: storage.
- `0x101` (clock watchdog), `0x133` (DPC watchdog): CPU starvation.

A storage stop code on a VM whose datastore also shows high latency is two
pieces of evidence for one cause. On a VM whose datastore is clean, it points
somewhere the infrastructure checks did not look: say so rather than forcing
it to fit.

## When nothing matches

All VMs booting normally, host and storage clean, the boot reached Tools, no
question, no reset: the environment is fine and the Tools error was transient
or upstream. "No cause stands out from what could be read" is a valid verdict.
