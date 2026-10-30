# Live evals: a model driving the real tools

`skills/vm-incident/evals/evals.json` describes table-top scenarios (a model
given fixed tool results). These evals are live: a model calls the real tool
surface against the integration scenario's two simulated vCenters, picks its
own tools, and writes a verdict. They measure what the table-top ones cannot:
which tools a model reaches for, how much it reads, and whether a weak model
(Haiku) still lands on the right cause.

Needs Docker, like the integration suite. Not on any CI path.

## Run

```sh
uv run python evals/live/world.py        # builds vc-a and vc-b in vcsim; leave it running
```

It writes `tools.md` (the server instructions and every tool description, as an
MCP client receives them) and serves `POST /call` on 127.0.0.1:8765.

Give the model a directory holding `tools.md`, `call.py` and a copy of
`skills/vm-incident/` without its `evals/`, and tell it to call tools with
`python3 call.py <run-id> <tool> '<json>'`. One run per scenario in
`scenarios.json`, each with its own run id. Then:

```sh
python3 evals/live/report.py             # calls, characters read, traps hit, per run
```

Grade each verdict against the scenario's `must` / `must_not`. The report
flags the forbidden tools (anything that acts on a VM) and the piece tools
called on a VM `diagnose_vm` already covered.

## Results (Haiku, 2026-10-30)

Round 1 found and round 2 checked:

- `diagnose_vm` never ranked a boot loop as a cause, so loop-01's headline was a
  low-confidence disconnected NIC. A boot loop is now a cause.
- A device finding the healthy siblings share (vcsim gives every VM a
  disconnected NIC) still counted for the VM, which sent the model calling
  `get_vm_hardware` on neighbour after neighbour. It now argues against itself.
- `scan(states=[...])` called whatever it was asked for "abnormal", so a scan
  for healthy VMs reported "3 of 3 on base disk X are abnormal".
- `scan` sent about 48k characters for a 24-VM vCenter. Its rows no longer repeat
  the state and flag legend, and the default `limit` is 10, which halves it.
- The scenario's storage storm had slow datastores but healthy VM disks; the
  stuck clones' own disks now read slow too, and every VM's CPU series now
  matches what vcsim says it is using (it was a flat 200 MHz for all).
- A model wanting every abnormal VM re-ran `scan` with a high `limit`; the VMs
  past the limit are now named in `more_abnormal_vms`, one line each.

Each verdict is graded against its scenario's `must` / `must_not` in
`scenarios.json`. Characters are what the model read from tool results.

| scenario | round 1 | round 2 | round 4 | round 5 (final code) |
|---|---|---|---|---|
| storage-storm | **fail** (blamed the base image), 16 calls, 163k | pass, 7 calls, 86k | pass, 19 calls, 254k | pass, 11 calls, 130k |
| cpu-starvation | pass, 6 calls, 129k | pass, 5 calls, 69k | pass, 1 call, 21k | pass, 4 calls, 71k |
| fleet | pass, 15 calls, 191k | pass, 5 calls, 125k | pass, 5 calls, 92k | pass, 4 calls, 86k |
| boot-loop | partial (server led with a NIC), 3 calls | pass, 2 calls | pass, 4 calls | pass, 2 calls |
| stop-code | pass, 1 call | pass, 1 call | pass, 2 calls | pass, 1 call |
| question | pass, 1 call | pass, 1 call | pass, 1 call | pass, 1 call |

Round 3 re-ran three scenarios mid-way (all pass). Round 4 found one more
cost: a datastore's latency series pools every mounting host, so two slow
hosts of seven read as "max 95, mean 28" and the model re-read
`get_datastore_health` seven times hunting for the slow path. Each datastore
now names `slow_from_hosts`; round 5 is the final code.

Across rounds the model kept doubting latency "peaks" whose time moved between
tools: on a flat series the first sample is the peak. A series that does not
move is now marked `steady`, and its datastore finding says "held at".

One run per scenario per round, on a simulator: evidence of direction, not a
benchmark. vcsim gives every VM 32 MB of RAM and a disconnected NIC, which a
careful model sometimes notes; both are simulator defaults.

### Rounds 6 to 8: twelve scenarios

Six more scenarios cover a configured CPU limit, a Linux kernel console, a VM
without Tools, leftover environments, an ambiguous VM name and snapshots across
a template's clones. Each surfaced something:

- A healthy VM's CPU and memory limits were no cause at all unless it was
  stuck; then the CPU limit was "capped below full speed" even at 400 of 600
  MHz, which Haiku rightly called not binding. The cause now says the usage
  against the limit and weighs it by whether the VM is at the limit.
- Snapshot sizes vCenter did not report read as 0.0 GB; they are null now.
- A busy Linux guest was offered "Windows still working through boot".
- `diagnose_vm` with a bare name said only which arguments it wanted; it now
  says why a name is not enough and how to find the env id.

Round 7 ran all twelve on the code after an independent review of the skill
(nine contradictions with the server, fixed): **12 of 12 pass**. Round 8 re-ran
the four scenarios the last change touched: **4 of 4 pass**.

| scenario | round 7 | round 8 (final code) |
|---|---|---|
| storage-storm | pass, 9 calls | pass, 4 calls |
| cpu-starvation | pass, 3 calls | |
| fleet | pass, 11 calls | pass, 4 calls |
| boot-loop | pass, 1 call | |
| stop-code | pass, 1 call | |
| question | pass, 1 call | |
| cpu-limit | pass, 4 calls | pass, 3 calls |
| linux-console | pass, 2 calls | pass, 1 call |
| no-tools | pass, 1 call | |
| old-environments | pass, 2 calls | |
| ambiguous-name | pass, 5 calls | |
| template-snapshots | pass, 1 call | |

No run, in any round, called a tool that acts on a VM.
