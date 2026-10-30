"""Summarise the calls each run made: tools in order, characters read, and the traps hit.

python report.py [run-id ...]      # all runs when none named
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = json.loads((HERE / "scenarios.json").read_text())
forbidden = set(spec["forbidden_tools"])
redundant = set(spec["redundant_after_diagnose_vm"])
names = sys.argv[1:] or sorted(path.stem for path in (HERE / "runs").glob("*.jsonl"))
for name in names:
    calls = [json.loads(line) for line in (HERE / "runs" / f"{name}.jsonl").read_text().splitlines()]
    diagnosed: set[str] = set()
    repeats = []
    for row in calls:
        if row["tool"] == "diagnose_vm" and not row["error"]:
            diagnosed.add(row.get("moref"))
        elif row["tool"] in redundant and row.get("moref") in diagnosed:
            repeats.append(row["tool"])
    read = sum(row["characters"] for row in calls)
    print(
        f"{name}: {len(calls)} calls, {read} chars (~{read // 3} tokens), "
        f"errors {sum(row['error'] for row in calls)}, "
        f"forbidden {[row['tool'] for row in calls if row['tool'] in forbidden]}, "
        f"re-read after diagnose_vm {repeats}"
    )
    print("   ", " > ".join(row["tool"] + ("!" if row["error"] else "") for row in calls))
