# Worked example: the shared datastore, found from the fleet

The storage case, entered from a fleet question rather than one error. It shows
population-before-individual and the linked-clone base disk.

## The ask

> We're getting VMware Tools errors across lots of environments on vc-04 since
> about 02:10. Find what's stuck and why.

## Rungs

1. **Sahara.** The errors span ~12 environments on vc-04, all after a reboot
   around 02:10. No single environment; this is infrastructure. Skip to the
   fleet entry.

2. **vCenter — scan.** `scan(vcenters=["vc-04"])`:
   - `counts_by_state`: 33 `hung`, the rest healthy or booting.
   - `strongest_groups[0]`: datastore `vc-04:ds-17`, 29 of 210 abnormal, 1.9×
     the fleet rate. `strongest_groups[1]`: base_disk
     `vc-04:[ds-17] base-win10/base-win10.vmdk`, 3× the fleet rate.
   - `storage_findings`: "datastore ds-17 write latency peaked at 180 ms".

   The finding is the group, not any VM.

3. **vCenter — explain_group.** `explain_group(scan_id, "datastore",
   "vc-04:ds-17")`:
   - the 29 abnormal VMs rebooted between 02:10 and 02:16; the healthy VMs on
     ds-17 rebooted before 02:09.
   - `infrastructure`: device latency on ds-17 over 150 ms on four hosts
     02:09–02:17; host CPU normal. So it is the array, not the hosts, and not
     per-host queue.
   - representatives: web-01, db-01, app-01.

4. **vCenter — diagnose_vm on a representative.** `diagnose_vm(... moref of
   web-01)`: `machine.state` hung; `boot.timeline.last_stage` = firmware, then
   nothing; `storage.datastores[ds-17].write_latency_ms.max` = 180 at 02:13.
   The boot stalled at the minute the latency peaked — the mechanism.

5. **vROps.** `vrops_compare_window` on ds-17 latency, 02:00–02:30 vs 7 days:
   a spike at 02:10 every night this week. So the latency is recurring, likely
   a scheduled job on that PowerFlex pool — not these environments.

## Check (core/correlation.md)

- Mechanism: the boot stalled at the latency peak, not merely the same hour.
- Healthy neighbours: VMs on ds-17 that rebooted *outside* 02:10–02:16 are
  fine — it is the window, not the datastore as such.
- Base disk: the win10 base is on ds-17; its clones elsewhere (if any) would
  test template vs datastore. Here all win10 clones are on ds-17, so the next
  check is whether that base boots fine on another datastore.

## Verdict

> **Symptom** VMware Tools errors across ~12 environments on vc-04 after
> reboots near 02:10.
> **Identity** 29 VMs across those environments, all on vc-04 datastore ds-17;
> representatives vc-04/vm-… (web-01, db-01, app-01).
> **Cause** PowerFlex/storage saturation on the pool behind ds-17 — high.
> for: 29 of 33 stuck VMs on ds-17; device latency >150 ms on four hosts
> 02:09–02:17; all 29 rebooted in that window; boot timeline stops after the
> firmware; vROps shows the spike recurs nightly at 02:10. against: VMs on
> ds-17 that rebooted outside the window are healthy — so the datastore is only
> a cause *during the spike*.
> **Ruled out** CPU: host demand normal in the window. Bad template: the stall
> is storage-timed, not boot-stage-specific.
> **Gaps** PowerFlex pool internals not read (adapter not configured) — which
> volume or rebuild drove the IOPS is unknown from vCenter alone.
> **Next** does the win10 base boot fine on another datastore right now? And
> for storage: what runs against that PowerFlex pool at 02:10 nightly. Action:
> none in vCenter; move the reboot off the spike, or the load off the pool.

One ticket, one fix, 12 environments: that is what population-before-individual
buys.
