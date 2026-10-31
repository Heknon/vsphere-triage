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
| `booted_not_up` | booted over 10 min ago, Tools not running, CPU in between, **or CPU not reported** (then CPU is a gap, not a reading) | the boot timeline; Tools may be stuck running its startup scripts |
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
| **A configured CPU limit** | the `cpu_limited` flag, or `find_resource_limits` lists the VM: a limit caps it below full speed, which looks like starvation. A linked clone inherits its template's limit. A limit on the VM's resource pool or vApp caps all its VMs together; `find_resource_limits` names the pool | no limit; or the host itself is overcommitted |
| **Storage saturation** | stuck VMs share datastores on one pool or array; device latency and IOPS high in the boot window; Windows `0x7A`, `0x77`, `0xF4` or `0x7B`; `vmkernel` path or latency warnings | latency normal; healthy VMs boot fine from the same datastore |
| **Datastore full, over-provisioned or unreachable** | `check_datastores`: the datastore is nearly full (a thin disk stalls on write), thin disks provisioned past capacity, or a host has it mounted but cannot reach it (APD/PDL). VMs on it stall, pause or wait on a question together. A datastore holding a template's base disk takes every clone with it | the datastore has space, is within capacity, and every host reaches it |
| **PowerFlex backend trouble** | `powerflex_health` shows a failed SDS or device, a rebuild or rebalance, or failed capacity; or `powerflex_protection_domains` shows the datastore's domain carrying most of the IOPS. `powerflex_affected_vms` lists the VMs on it | the backend is healthy and traffic is spread out |
| **Linked-clone boot storm** | many clones of one base disk stuck together, clones of other bases fine, the shared datastore slow | clones of the same base booted fine at the same time |
| **Host memory pressure** | the host near memory capacity; the VM ballooned, swapped or compressed (`memory_reclaimed`) | host memory fine; nothing reclaimed |
| **A configured memory limit** | the `memory_limited` flag, or `find_resource_limits`: a limit below the VM's RAM forces ballooning or swapping even when the host has memory | no limit, or a limit at or above the VM's RAM |
| **A failing host** | `scan`'s `hosts_with_hardware_problems`, `diagnose_vm`'s `host_hardware` or `get_host_health` shows a red hardware sensor (power supply, fan, temperature, memory): an overheating or power-limited host throttles its VMs while its CPU numbers look normal; or `cluster_events` shows the host failed, was isolated or lost its connection | sensors green; the host connected throughout |
| **HA restarted the VMs** | `cluster_events` shows vSphere HA restarted them after a host failed; the VMs rebooting is expected | no HA restart in the window |
| **Pending VM question** | `diagnose_vm`'s `machine.question` is set, with its choices (a scan row shows it in `verdict.values.question`) | no question |
| **A virtual device blocks the boot** | `get_vm_hardware` or `diagnose_vm`: a disconnected boot NIC (PXE/DHCP fails), an ISO left mounted, a device in error | every device connected and healthy |
| **Snapshots filling the datastore or slowing I/O** | `find_vms_by_snapshot` or `diagnose_vm`: a large or old snapshot, a deep redo chain, or consolidation needed | no snapshots, or small and recent |
| **vCenter session exhaustion** (not a VM) | SSL EOF, resets or timeouts across callers; `check_vcenters` shows a high or climbing session count | sessions and login time normal |
| **vCenter at its configured session cap** (not a VM) | `check_vcenters` shows `limit_finding`: the count at or near `session_limit`; `vcenter_sessions` names who holds them | the count well under the cap, or no cap set and the count modest |
| **vCenter appliance unhealthy or restarted** (not a VM) | `vcenter_appliance_health`: a health area orange or red, an uptime matching the failure time, or vpxd / envoy / the reverse proxy up but unhealthy | every area green, uptime long, services healthy |
| **Guest file transfers fail on the host path** (not a VM, not vCenter) | the errors name `guestFile`, or `run_in_guest` says its output could not be downloaded; `check_host_tls` shows hosts unanswered, refused, reset or with a bad certificate at the address the URL carries; `search_host_logs` finds the failures on those hosts | every host reachable with a good handshake from where the failing client runs, and no matching hostd lines |
| **A host clock has drifted** (not a VM) | `check_host_time`: NTP off or without servers, or a clock skewed from vCenter. Skew breaks TLS, and past about 300 s Kerberos/AD auth, so it looks like exhaustion | NTP running and clocks tight on every host |
| **Windows crashed** | a stop code on the serial console (EMS), a blue screen on the console, or a bugcheck from `investigate_windows_boot` | the console shows the logon screen |
| **Windows still working (slow, not hung)** | CPU busy; the console changes; the screen shows updates, "Getting devices ready" or a disk check | the console is frozen; CPU near zero |
| **Guest hung early in boot** | near-zero CPU; console black and unchanged across two captures; `vmware.log` stops after the firmware or the first disk I/O; host and storage healthy | the console changes; the boot reached the drivers or Tools |
| **Guest booted, Tools did not start** | a logon or login prompt on the console, or a guest IP reported; Tools not running; host and storage healthy | Tools running |
| **Something reset or moved the VM** | HA, migration or reset events not ordered by the orchestrator (rung 2) in the window | no such event |
| **A boot loop** | the `boot_loop` flag: several resets or guest reboots in a short window; `vmware.log` shows "Guest-initiated reset" for the guest's own. Each boot stopping early is one turn of the loop, not a separate hang | the resets were ordered by the orchestrator or a person (rung 2, `cluster_events`) |
| **The guest kernel reported an error** | a Linux panic, soft lockup, hung task, I/O or filesystem error on the serial console; its `points_at` names the layer (a soft lockup: CPU; a hung `jbd2` task or I/O error: storage) | the finding is from an earlier boot (`linux_findings_earlier_boots`) |
| **The guest cannot boot** | the console shows Automatic Repair, a boot-manager error, "no boot device", a Linux emergency shell or a panic screen: the guest itself refuses, whatever the host does | the console shows progress past it |
| **The virtual machine faulted** | `vmware.log` reports a VMX fault during the boot: the hypervisor's process for this VM failed, not the guest | no fault line in the log |
| **Tools flapping** | Tools runs but its heartbeat is intermittent (yellow), or several Tools state changes in `vmware.log`: Tools is crashing or restarting in a running guest | heartbeat green and steady |
| **vCenter cannot reach the VM / its host is not connected / it is paused** | the `inaccessible` or `paused` state, the `host_not_connected` flag: the VM's host or its storage is out of vCenter's reach, or the hypervisor paused it (a full thin datastore pauses VMs) | the host connected, the datastore reachable, the VM running |

### Cause names in `diagnose_vm` results

`conclusion.causes[].cause` uses these exact names; each maps to a row above.

| `cause` | Row |
| --- | --- |
| CPU starvation (ESXi overcommit) | ESXi CPU overcommit |
| throttled by a configured CPU limit (not host starvation) | A configured CPU limit |
| storage latency (datastore / PowerFlex) | Storage saturation, or PowerFlex backend trouble |
| its datastore is full or unreachable (APD/PDL) | Datastore full, over-provisioned or unreachable |
| linked-clone boot storm on a shared base disk | Linked-clone boot storm |
| memory pressure (the host ballooning or swapping the VM) | Host memory pressure |
| a configured memory limit is forcing reclamation | A configured memory limit |
| its ESXi host reports failing hardware | A failing host |
| a pending VM question blocks it | Pending VM question |
| a virtual device is blocking or breaking the boot | A virtual device blocks the boot |
| snapshots are consuming disk and slowing I/O | Snapshots filling the datastore or slowing I/O |
| Windows crashed (stop error) | Windows crashed |
| Windows still working through boot (slow, not hung) | Windows still working (slow, not hung) |
| the guest hung early in boot | Guest hung early in boot |
| the guest booted; Tools did not start | Guest booted, Tools did not start |
| the VM is in a boot loop (it keeps resetting) | A boot loop |
| the guest kernel reported an error | The guest kernel reported an error |
| the guest cannot boot | The guest cannot boot |
| the virtual machine faulted | The virtual machine faulted |
| Tools flapping | Tools flapping |
| vCenter cannot reach the VM | vCenter cannot reach the VM / its host is not connected / it is paused |
| its ESXi host is not connected to vCenter | vCenter cannot reach the VM / its host is not connected / it is paused |
| the VM is paused | vCenter cannot reach the VM / its host is not connected / it is paused |

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

- `0x7A`, `0x77` (paging I/O failed or timed out), `0x7B` (boot disk not
  reachable), `0xF4`, `0x24` (NTFS), `0xED` (boot volume will not mount): storage.
- `0x101` (clock watchdog): CPU starvation.
- `0x133` (DPC watchdog): CPU **or** storage: a deferred call ran too long,
  which a starved vCPU or a stalled disk can each cause. Check both.

A storage stop code on a VM whose datastore also shows high latency is two
pieces of evidence for one cause. On a VM whose datastore is clean, it points
somewhere the infrastructure checks did not look: say so rather than forcing
it to fit.

## When nothing matches

All VMs booting normally, host and storage clean, the boot reached Tools, no
question, no reset: the environment is fine and the Tools error was transient
or upstream. "No cause stands out from what could be read" is a valid verdict.
