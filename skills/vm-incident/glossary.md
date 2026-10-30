# Glossary

One sentence per term. Use these words and no synonyms.

| Term | Meaning |
| --- | --- |
| environment | A set of short-lived VMs Sims/Twix creates for a test run; on a vCenter it is the folder its VMs sit in, named by its Twix id, under a projects or environments parent. |
| environment id | The Twix id of an environment; the anchor that ties a Sahara error to a vCenter folder. |
| identity | A machine as its vCenter and its moref (`vm-1234`); the only safe way to name it, since names are reused. |
| moref | A vCenter managed-object id, stable for the life of one VM and unique on its vCenter. |
| the ladder | The fixed route Sahara → Sims/Twix → vCenter → vROps, each rung narrowing what the next explains (`core/ladder.md`). |
| rung | One layer of the ladder; you climb from where you entered, never from the bottom. |
| state | The one word for what a VM is doing, from the bulk read: hung, busy_not_up, booting, no_tools, and the rest (`core/causes.md`). |
| flag | A signal beside the state (memory_reclaimed, vcenter_alarm, long_running); several may apply at once. |
| cause | The layer or condition that, removed, makes the symptom go away; named in the verdict with evidence for and against. |
| shared cause | A cause in infrastructure many VMs share — a host, a datastore, a base disk — rather than in one guest; the common case here. |
| starved | Booting slowly because the host cannot give it CPU; busy on CPU, console changing, may still come up. |
| hung | Stopped; near-zero CPU, console frozen, will not come up on its own. |
| the Sims wait | How long Sims or Sahara waits for a machine before raising a Tools error; the line between "slow" and "lost to a timeout". |
| boot-to-Tools time | How long from a reboot until VMware Tools reports running; the number that tells slow from stuck. |
| boot timeline | How far a boot got (power-on, firmware, disk, drivers, Tools), read from `vmware.log`, which is the hypervisor's log, not the guest's. |
| serial console | A file a VM's serial port writes to, carrying Windows EMS or a Linux kernel console; the guest's own words, when a template has one. |
| healthy neighbour | A VM in the same environment, or the same group, that is fine; its sharing or not sharing a host/datastore/base disk is evidence for or against a cause. |
| the fleet rate | The share of powered-on VMs that are abnormal across the scan; a group is interesting when its rate is well above this. |
| group | A set of abnormal VMs that share a dimension (vCenter, host, datastore, base disk, environment); `explain_group` says why they are abnormal. |
| representative | A VM the scan picked from a group to diagnose, so you examine two or three rather than forty. |
| gap | Something no tool could read (a destroyed VM, a missing counter, an unreachable layer); recorded in the verdict, never read as a clean result. |
| read-only | This skill and the `vsphere-mcp` server only read; no reset, no answer, no power change — the verdict hands those to a person. |
