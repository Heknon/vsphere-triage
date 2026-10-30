"""The read-only guarantee, enforced in code rather than left to the account.

The accounts this server may run with can change things. So every vSphere call
goes through `ReadOnlyStub`, which refuses any method that is not on
`ALLOWED_METHODS` before a byte is sent, and every HTTP request goes through
`ensure_read_request`, which refuses anything but GET and HEAD.

The one exception, enabled deliberately by the operator, is `run_in_guest`: it
executes a command inside a guest OS for diagnostics, so it cannot be read-only.
It does NOT go through `ReadOnlyStub` — it uses the session's raw stub on purpose
(see `VCenterSession.run_in_guest`), and it is the only path in the whole server
that can change anything. Everything else, proven by the sweep test below, only
reads.

What is on the list reads, or creates something that lives only in this
session and changes nothing anyone else can see (a container view, a task
history collector). Nothing on it powers, answers, migrates, reconfigures,
creates, deletes or writes a datastore file. `SearchDatastore_Task` is a task,
but it only lists files.

A test drives every tool against a simulated vCenter and asserts that the
methods it saw are a subset of this list, so a new call is noticed when it is
written, not when it reaches a real vCenter.
"""

from __future__ import annotations

import threading
from typing import Any

from pyVmomi.SoapAdapter import StubAdapterBase

ALLOWED_METHODS = frozenset(
    {
        # The session itself.
        "RetrieveServiceContent",
        "Login",
        "Logout",
        "CurrentTime",
        # Reading properties. "Fetch" is how pyVmomi reads one property of one
        # object (`vm.name`); it goes through the property collector too.
        "Fetch",
        "RetrievePropertiesEx",
        "ContinueRetrievePropertiesEx",
        # Session-scoped views over the inventory, destroyed after use.
        "CreateContainerView",
        "DestroyView",
        # Events.
        "QueryEvents",
        # Performance counters.
        "QueryPerf",
        # Host logs, and which ones a host offers.
        "QueryDescriptions",
        "BrowseDiagnosticLog",
        # A host's own clock, to measure skew against vCenter's.
        "QueryDateTime",
        # The configured session idle-timeout, read to judge the session count.
        "QueryOptions",
        # Listing a datastore folder: a task, but one that only reads.
        "SearchDatastore_Task",
    }
)

ALLOWED_HTTP_METHODS = frozenset({"GET", "HEAD"})


class ReadOnlyViolationError(PermissionError):
    """A call that could change vSphere was attempted and refused."""


class ReadOnlyStub(StubAdapterBase):
    """A pyVmomi stub that sends only the methods on `ALLOWED_METHODS`.

    Every managed object reached through it carries it as its stub, so a method
    called on any of them, however it was obtained, is checked here.
    """

    def __init__(self, inner: Any) -> None:
        """Wrap the SOAP stub a session was logged in on."""
        StubAdapterBase.__init__(self, version=inner.version)
        self.inner = inner
        self.seen: set[str] = set()
        self._lock = threading.Lock()

    @property
    def cookie(self) -> str:
        """The session cookie, for the HTTP endpoints that share the session."""
        return self.inner.cookie

    def InvokeMethod(self, mo: Any, info: Any, args: Any) -> Any:  # noqa: N802 - pyVmomi's interface
        """Refuse a method off the list; send one on it and unwrap the result."""
        name = info.wsdlName
        if name not in ALLOWED_METHODS:
            msg = f"Refused {name}: this server only reads from vSphere"
            raise ReadOnlyViolationError(msg)
        with self._lock:
            self.seen.add(name)
        status, result = self.inner.InvokeMethod(mo, info, args, self)
        if status == 200:  # noqa: PLR2004 - the SOAP success status
            return result
        if isinstance(result, BaseException):
            raise result
        msg = f"{name} failed with HTTP status {status}"
        raise RuntimeError(msg)


def ensure_read_request(method: str) -> None:
    """Refuse an HTTP method that could write a datastore file or anything else."""
    if method.upper() not in ALLOWED_HTTP_METHODS:
        msg = f"Refused HTTP {method}: this server only reads from vSphere"
        raise ReadOnlyViolationError(msg)
