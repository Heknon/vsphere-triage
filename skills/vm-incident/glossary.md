# Glossary

Use these terms as defined here.

| Term | Meaning |
| --- | --- |
| environment | A set of short-lived VMs the orchestrator creates for one test run. On vCenter it is a VM folder named by its environment id, under a parent such as `environments/` or `projects/`. |
| environment id | The orchestrator's id for an environment; it links a Tools error to a vCenter folder. |
| identity | A VM's vCenter and moref (`vc-04` / `vm-1234`). The only reliable way to name a VM, since VM names are reused. |
| moref | vCenter's managed-object id for a VM. It stays the same for the VM's life and is unique only within one vCenter. |
| the ladder | The order of sources: orchestrator, creator/runner logs, vCenter, vROps (`core/ladder.md`). |
| rung | One step of the ladder. |
| state | The one-word condition the server assigns each VM, such as `hung`, `busy_not_up`, `booting`, `no_tools` (`core/causes.md`). |
| flag | An extra signal next to the state, such as `memory_reclaimed`, `vcenter_alarm`, `long_running`. A VM can have several. |
| cause | The condition that, if removed, would make the symptom go away. Written in the verdict with evidence for and against. |
| shared cause | A cause in infrastructure many VMs use (a host, a datastore, a base disk), as opposed to a problem inside one guest. The common case. |
| starved | Booting slowly because the host cannot give it enough CPU. CPU busy, console changing; it may still come up. |
| hung | Stopped. CPU near zero, console frozen; it will not come up on its own. |
| orchestrator wait | How long the orchestrator waits for a VM before raising a Tools error. It decides whether a slow VM counts as failed. |
| boot-to-Tools time | Time from a boot or reboot until VMware Tools reports running. |
| boot timeline | How far a boot got (power-on, firmware, first disk I/O, drivers, Tools), read from `vmware.log`. `vmware.log` is written by the hypervisor, not the guest. |
| serial console | A file a VM's serial port writes to, carrying Windows EMS or a Linux kernel console: the guest's own boot messages, when the VM has one. |
| healthy neighbour | A VM in the same environment or group that is fine. Whether it shares the stuck VMs' host, datastore or base disk is evidence for or against a cause. |
| fleet rate | The share of powered-on VMs that are abnormal across a scan. A group is interesting when its rate is well above it. |
| group | Abnormal VMs that share one value of a dimension (vCenter, cluster, host, datastore, environment folder, base disk, OS). |
| representative | A VM `scan` or `explain_group` picks from a group (earliest, middle and latest boot), so you diagnose two or three instead of all. |
| gap | Something no tool could read (a destroyed VM, a missing counter, an unconfigured source). Recorded in the verdict, never treated as a clean result. |
| acting tool | One of the seven tools that change a VM or run code in it: `run_in_guest`, `reboot_guest`, `hard_reset`, `check_ems`, `investigate_windows_boot`, `investigate_linux_boot`, `read_crash_dump`. Every other tool only reads. |
