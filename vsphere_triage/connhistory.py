"""Reading a vCenter's session/login events over a past window.

`check_vcenters` probes a vCenter *now*: if an SSL EOF at 2pm had cleared by
5pm, the live probe says "healthy" and the 2pm failure is invisible to it. The
one vCenter-native record that reaches back is its event stream, so this reads
the session events over a window and looks for the shape of session or
connection exhaustion: a surge of logins, a spike of failed logins, many
sessions opened from one source.

It is not as good as vROps, which keeps the actual session-count and
availability curves — so when vROps is not configured the tool says so and names
it as the better source. The summary here is pure and tested; the event read is
in the tool.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

# The session/connection events worth reading. Filtered server-side so a busy
# vCenter's full event stream is never pulled.
SESSION_EVENT_TYPES = (
    "UserLoginSessionEvent",
    "UserLogoutSessionEvent",
    "BadUsernameSessionEvent",
    "NoAccessUserEvent",
    "ServerStartedSessionEvent",
    "SessionTerminatedEvent",
    "AlreadyAuthenticatedSessionEvent",
    # vCenter 6.5+ logs SSO login failures as an EventEx with this type id.
    "com.vmware.sso.LoginFailure",
)
_FAILED = {"BadUsernameSessionEvent", "NoAccessUserEvent", "com.vmware.sso.LoginFailure"}
_LOGIN = "UserLoginSessionEvent"
# Sources that are vCenter itself (its own services), never a leaking client.
LOCAL_SOURCES = frozenset({"127.0.0.1", "::1", "localhost", None, ""})


def summarize_session_events(
    rows: list[dict[str, Any]],
    *,
    now: datetime,
    window_minutes: float,
    bucket_minutes: float = 10.0,
) -> dict[str, Any]:
    """Counts, failed logins, the busiest sources, and a login histogram over the window.

    `rows` are plain dicts: {type, time (UTC datetime), user, source}. The
    histogram buckets logins so a churn spike (the sign of a client that opens
    sessions and never closes them) shows up as a peak.
    """
    begin = now - timedelta(minutes=window_minutes)
    by_type: dict[str, int] = {}
    by_user: dict[str, int] = {}
    by_source: dict[str, int] = {}
    bucket_count = max(1, int(window_minutes / bucket_minutes) + 1)
    buckets = [0] * bucket_count
    failed = 0
    logins = 0
    for row in rows:
        kind = str(row.get("type", "unknown"))
        by_type[kind] = by_type.get(kind, 0) + 1
        if kind in _FAILED:
            failed += 1
        if kind == _LOGIN:
            logins += 1
            user = row.get("user") or "unknown"
            source = row.get("source") or "unknown"
            by_user[user] = by_user.get(user, 0) + 1
            by_source[source] = by_source.get(source, 0) + 1
            moment = row.get("time")
            if isinstance(moment, datetime):
                index = min(
                    bucket_count - 1, max(0, int((moment - begin).total_seconds() // (bucket_minutes * 60)))
                )
                buckets[index] += 1
    peak = max(range(bucket_count), key=buckets.__getitem__) if logins else 0
    peak_start = begin + timedelta(minutes=bucket_minutes * peak)
    findings = []
    if logins:
        findings.append(
            f"{logins} logins in the window; busiest {bucket_minutes:.0f}-minute bucket had "
            f"{buckets[peak]}, starting {peak_start.isoformat()}"
        )
    if failed:
        findings.append(
            f"{failed} failed login(s) (bad username / no access) — often a client with stale "
            "credentials, or someone guessing; see by_type and top_sources"
        )
    # vCenter's own services log in from loopback all the time; that is not a client.
    external = {source: count for source, count in by_source.items() if source not in LOCAL_SOURCES}
    top_source = max(external.items(), key=lambda item: item[1], default=None)
    if top_source and top_source[1] >= max(5, logins // 2):
        findings.append(
            f"{top_source[1]} of {logins} logins came from {top_source[0]} — one client may be churning"
        )
    if not rows:
        findings.append("no session events in the window — the vCenter recorded none, or they have aged out")
    return {
        "window_minutes": window_minutes,
        "total_events": len(rows),
        "logins": logins,
        "failed_logins": failed,
        "by_type": dict(sorted(by_type.items(), key=lambda item: -item[1])),
        "top_users": dict(sorted(by_user.items(), key=lambda item: -item[1])[:5]),
        "top_sources": dict(sorted(by_source.items(), key=lambda item: -item[1])[:5]),
        "login_histogram": {"bucket_minutes": bucket_minutes, "buckets": buckets, "peak_bucket": peak},
        "findings": findings,
    }
