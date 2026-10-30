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

| scenario | round 1 | round 2 | round 3 |
|---|---|---|---|
| storage-storm | wrong cause, 16 calls, 163k chars | right, 7 calls, 86k | right, 7 calls, 103k |
| cpu-starvation | right, 6 calls, 129k | right, 5 calls, 69k | right, 2 calls, 29k |
| fleet | right, 15 calls, 191k | right, 5 calls, 125k | right, 6 calls, 114k, one scan |
| boot-loop | hedged (server led with a NIC), 3 calls | right, 2 calls | |
| stop-code | right, 1 call | right, 1 call | |
| question | right, 1 call | right, 1 call | |

Round 3 ran the multi-call scenarios after `more_abnormal_vms` and the CPU fix.
Across rounds the model kept doubting latency "peaks" whose time moved between
tools: on a flat series the first sample is the peak. A series that does not
move is now marked `steady`, and its datastore finding says "held at".

No run, in any round, called a tool that acts on a VM.
