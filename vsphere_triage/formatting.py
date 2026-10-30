"""Turning results into JSON a context window can hold."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from typing import Any

MAX_RESPONSE_CHARACTERS = 120_000
# How far a list is cut, in turn, when a response is too large.
LIST_CUTS = (200, 80, 30, 10, 3)


def jsonable(value: Any) -> Any:  # noqa: PLR0911 - one walk over every JSON shape
    """A result with datetimes as UTC ISO strings and everything else JSON-ready."""
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=UTC)
        return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items() if not str(key).startswith("_")}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [jsonable(item) for item in value]
    if is_dataclass(value) and not isinstance(value, type):
        return jsonable(asdict(value))
    if isinstance(value, float):
        return round(value, 3)
    if value is None or isinstance(value, (str, int, bool)):
        return value
    return str(value)


def _cut(value: Any, keep: int) -> Any:
    if isinstance(value, dict):
        return {key: _cut(item, keep) for key, item in value.items()}
    if isinstance(value, list):
        if len(value) > keep:
            return [*(_cut(item, keep) for item in value[:keep]), f"... {len(value) - keep} more not shown"]
        return [_cut(item, keep) for item in value]
    if isinstance(value, str) and len(value) > keep * 40:
        return value[: keep * 40] + " ... (cut)"
    return value


def bounded(result: dict[str, Any]) -> dict[str, Any]:
    """The result, JSON-ready, with long lists cut until it fits; said when cut."""
    ready = jsonable(result)
    if len(json.dumps(ready)) <= MAX_RESPONSE_CHARACTERS:
        return ready
    for keep in LIST_CUTS:
        cut = _cut(ready, keep)
        if len(json.dumps(cut)) <= MAX_RESPONSE_CHARACTERS:
            cut["truncated"] = f"lists cut to {keep} items to fit the response budget"
            return cut
    return {
        "truncated": "the result was too large to return even cut down",
        "findings": ready.get("findings") or ready.get("finding"),
    }
