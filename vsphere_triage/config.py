"""Configuration: which vCenters to read, how, and what counts as abnormal.

Every setting is one `VSPHERE_`-prefixed environment variable, resolved by
pydantic's `BaseSettings`, so a value is parsed and validated where it is
declared and the field is the documentation of the variable.

Nothing here names a folder path, a log field or a naming pattern. The layout of
a vCenter is discovered from the vCenter; what the configuration may add are
hints that make discovery faster, never requirements that make it brittle.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = logging.getLogger(__name__)

ENV_PREFIX = "VSPHERE_"


def _not_a_boolean(value: object) -> object:
    """Refuse a boolean where a number is meant: `True` is an `int` in Python."""
    if isinstance(value, bool):
        msg = "must be a number, not a boolean"
        raise ValueError(msg)  # noqa: TRY004 - pydantic reports ValueError by variable
    return value


PositiveInt = Annotated[int, BeforeValidator(_not_a_boolean), Field(gt=0)]
PositiveFloat = Annotated[float, BeforeValidator(_not_a_boolean), Field(gt=0, allow_inf_nan=False)]
Fraction = Annotated[float, BeforeValidator(_not_a_boolean), Field(gt=0, le=1, allow_inf_nan=False)]


class VCenter(BaseModel):
    """One vCenter: where it is, and the other names it goes by."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1)
    """What tools and results call this vCenter."""

    host: str = Field(min_length=1)
    port: PositiveInt = 443

    aliases: tuple[str, ...] = ()
    """Other spellings the upstream systems use for it.

    An upstream system's log may name a vCenter by its short name, its FQDN or
    something else again. The host and the first label of the host are matched
    without being listed; anything else goes here.
    """

    username: str | None = None
    password: str | None = Field(default=None, repr=False)
    """Per-vCenter credentials, when they differ from the shared ones."""

    def answers_to(self, spelling: str) -> bool:
        """Whether a name an upstream system used refers to this vCenter.

        A full name (exact match against the configured name, host or an alias)
        always counts. A bare first label (``vcsa``) also matches the host's
        first label — but only when the spelling given is itself a bare label,
        so ``vcsa.site1.corp`` does not match a host ``vcsa.site2.corp`` and two
        vCenters that share a first label stay distinct.
        """
        wanted = spelling.strip().lower().rstrip(".")
        if not wanted:
            return False
        for known in (self.name, self.host, *self.aliases):
            if wanted == known.lower():
                return True
        if "." not in wanted:
            for known in (self.name, self.host, *self.aliases):
                if wanted == known.lower().split(".", 1)[0]:
                    return True
        return False


class Thresholds(BaseModel):
    """What the checks call abnormal. Defaults, not truths: tune them on incidents.

    Every check that judges against one of these also returns the raw value it
    judged, so a reader can disagree with the threshold without re-running.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    booted_not_up_minutes: PositiveFloat = 10.0
    """A powered-on VM booted this long ago with Tools still not running is stuck."""

    hung_cpu_mhz: PositiveFloat = 100.0
    """At or below this CPU use, a VM that is not up is doing nothing: hung."""

    busy_cpu_fraction: Fraction = 0.5
    """At or above this share of its vCPUs, a VM that is not up is busy."""

    vm_ready_percent: PositiveFloat = 10.0
    """CPU ready time per vCPU, as a percent of the sample: starvation above this."""

    vm_costop_percent: PositiveFloat = 3.0
    """Co-stop per vCPU, as a percent of the sample."""

    host_cpu_demand_percent: PositiveFloat = 100.0
    """Host CPU demand against its capacity; above 100 the host is overcommitted."""

    datastore_latency_ms: PositiveFloat = 50.0
    """Datastore read or write latency that a booting guest will stall on."""

    device_latency_ms: PositiveFloat = 50.0
    """Device latency on the host's storage device: the array's side."""

    queue_latency_ms: PositiveFloat = 10.0
    """Kernel queue latency: the host's own queue is full."""

    boot_loop_resets: PositiveInt = 3
    """This many resets or guest reboots inside the window is a boot loop."""

    boot_loop_window_minutes: PositiveFloat = 30.0

    long_running_hours: PositiveFloat = 24.0
    """A VM older than this is flagged long-running: past the longest environment's life."""

    host_memory_percent: PositiveFloat = 95.0
    """Host memory in use at or over this is pressure: its VMs balloon and swap."""

    snapshot_warn_gb: PositiveFloat = 20.0
    """Snapshots using at least this many GB on a VM are worth flagging (datastore fill, slow I/O)."""

    snapshot_old_hours: PositiveFloat = 24.0
    """A snapshot older than this is a forgotten one that keeps growing."""

    snapshot_deep_chain: PositiveInt = 4
    """A redo chain at least this deep slows every read through it."""

    clock_skew_seconds: PositiveFloat = 60.0
    """A host clock this many seconds from vCenter is worth flagging.

    Small drift is normal; this is the "look at it" line. Auth breaks harder
    further out: Kerberos / Active Directory reject a ticket past about 300 s of
    skew, which is a frequent root of the TLS/handshake errors seen fleet-wide.
    """

    datastore_full_percent: PositiveFloat = 5.0
    """At or below this percent free, a datastore is nearly full: a thin disk on it stalls."""

    datastore_overprovision_ratio: PositiveFloat = 2.0
    """Provisioned (committed + thin, unallocated) over capacity, above which over-provisioning is flagged.

    A ratio over 1.0 means thin disks could grow past the datastore's capacity;
    this is the stronger line, where that risk is worth acting on.
    """

    cpu_limit_warn_percent: PositiveFloat = 90.0
    """A CPU limit at or below this percent of the VM's full speed is throttling it meaningfully."""

    console_black_fraction: Fraction = 0.98
    """A screenshot with at least this share of near-black pixels is black."""

    console_frozen_difference: PositiveFloat = 0.5
    """Mean absolute pixel difference (0-255) below which two captures are the same."""


def _json_list(value: object) -> object:
    """Accept a list given as JSON text, the only shape an environment holds."""
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            return json.loads(text)
        return [part.strip() for part in text.split(",") if part.strip()]
    return value


def _json_object(value: object) -> object:
    if isinstance(value, str):
        text = value.strip()
        return json.loads(text) if text else {}
    return value


class Settings(BaseSettings):
    """How to reach the vCenters (and vROps), and how much to hand back at once."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        extra="ignore",
        frozen=True,
    )

    vcenters: Annotated[tuple[VCenter, ...], NoDecode, BeforeValidator(_json_list)] = ()
    """`VSPHERE_VCENTERS`: a JSON list of `{"name", "host", "port", "aliases"}`."""

    username: str | None = None
    password: str | None = Field(default=None, repr=False)
    """Shared credentials, used for every vCenter that does not carry its own."""

    tls_verify: bool = True
    """Verify vCenter certificates. Turn off only for a simulator; it is warned about."""

    ca_bundle: str | None = None
    """A PEM bundle to verify against, for an internal CA."""

    env_parent_hints: Annotated[tuple[str, ...], NoDecode, BeforeValidator(_json_list)] = ()
    """Folder names to look under first when finding an environment.

    Only an ordering: an environment not found under them is looked for
    everywhere, and the result says so. Leave empty to search everywhere.
    """

    thresholds: Annotated[Thresholds, NoDecode, BeforeValidator(_json_object)] = Field(
        default_factory=Thresholds
    )
    """`VSPHERE_THRESHOLDS`: a JSON object overriding any of `Thresholds`."""

    scan_base_disks: bool = True
    """Read every VM's disk chain during a scan, to group linked clones by base disk.

    The device list is the heaviest property a scan reads. Turn off if a scan of
    a large vCenter is too slow; base-disk groups are then missing and said so.
    """

    timeout_seconds: PositiveFloat = 60.0
    max_concurrent_tools: PositiveInt = 4
    max_concurrent_per_vcenter: PositiveInt = 4
    max_log_bytes: PositiveInt = 4 * 1024 * 1024
    """How much of the end of a log file is read; older lines are said to be cut."""

    max_download_bytes: PositiveInt = 128 * 1024 * 1024
    """Absolute ceiling on bytes pulled for one datastore file when vCenter ignores a Range request.

    A tail read first asks vCenter for only the last `max_log_bytes` with a Range
    request. A vCenter that honors it transfers that much and no more. One that
    ignores Range would otherwise stream the whole file to keep its end; this
    caps that transfer, and a file past the cap is reported as un-tailable rather
    than pulled whole.
    """

    max_log_lines: PositiveInt = 400
    """The most log lines one result returns."""

    max_screenshot_bytes: PositiveInt = 16 * 1024 * 1024
    max_scans_kept: PositiveInt = 8

    guest_username: str | None = None
    guest_password: str | None = Field(default=None, repr=False)
    """Default guest-OS credentials for `run_in_guest`, used when a call gives none.

    This is the ONE capability that is not read-only: `run_in_guest` executes a
    command inside a guest through VMware Tools. It needs guest credentials, and
    the guest must have Tools running. Leave unset to require them per call.
    """

    guest_exec_timeout_seconds: PositiveFloat = 30.0
    """How long `run_in_guest` waits for a command to finish before giving up on its exit code."""

    guest_exec_max_output_bytes: PositiveInt = 1 * 1024 * 1024
    """The most command output `run_in_guest` returns; more is truncated."""

    vrops_url: str | None = None
    """`VSPHERE_VROPS_URL`: vROps (Aria / VCF Operations), e.g. `https://vrops.example`."""

    vrops_username: str | None = None
    vrops_password: str | None = Field(default=None, repr=False)
    vrops_auth_source: str | None = None
    """The vROps authentication source for the user, when it is not local."""

    @field_validator("vrops_url")
    @classmethod
    def _a_base(cls, value: str | None) -> str | None:
        return value.rstrip("/") if value else None

    @model_validator(mode="after")
    def _coherent(self) -> Settings:
        names = [vcenter.name.lower() for vcenter in self.vcenters]
        if len(set(names)) != len(names):
            msg = "vCenter names must be unique"
            raise ValueError(msg)
        for vcenter in self.vcenters:
            if not (vcenter.username or self.username):
                msg = (
                    f"vCenter {vcenter.name!r} in VSPHERE_VCENTERS has no username, "
                    "and VSPHERE_USERNAME is not set"
                )
                raise ValueError(msg)
        if bool(self.vrops_username) != bool(self.vrops_password):
            msg = "vrops_username and vrops_password must be configured together"
            raise ValueError(msg)
        if self.vrops_url and not self.vrops_username:
            msg = "vrops_url needs vrops_username and vrops_password"
            raise ValueError(msg)
        return self

    def credentials_for(self, vcenter: VCenter) -> tuple[str, str]:
        """The username and password a vCenter is logged into with."""
        return (
            vcenter.username or self.username or "",
            vcenter.password or self.password or "",
        )

    def vcenter(self, spelling: str) -> VCenter:
        """The configured vCenter a name refers to, by any of its spellings."""
        matches = [vcenter for vcenter in self.vcenters if vcenter.answers_to(spelling)]
        if len(matches) == 1:
            return matches[0]
        configured = ", ".join(vcenter.name for vcenter in self.vcenters) or "none"
        if not matches:
            msg = f"No configured vCenter answers to {spelling!r}; configured: {configured}"
        else:
            names = ", ".join(vcenter.name for vcenter in matches)
            msg = f"{spelling!r} matches more than one vCenter ({names}); use its name"
        raise LookupError(msg)

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> Settings:
        """Read the settings from the process environment or a given mapping."""
        try:
            if environment is None:
                settings = cls()
            else:
                declared: dict[str, Any] = {
                    name: environment[f"{ENV_PREFIX}{name.upper()}"]
                    for name in cls.model_fields
                    if environment.get(f"{ENV_PREFIX}{name.upper()}")
                }
                settings = cls(**declared)
        except ValidationError as invalid:
            raise ValueError(_naming_the_variables(invalid)) from invalid
        if not settings.tls_verify:
            logger.warning(
                "VSPHERE_TLS_VERIFY is off: vCenter certificates are not checked. "
                "Use this against a simulator only."
            )
        return settings


def _naming_the_variables(invalid: ValidationError) -> str:
    problems = []
    for problem in invalid.errors():
        field = str(problem["loc"][0]) if problem["loc"] else ""
        message = str(problem["msg"]).removeprefix("Value error, ")
        problems.append(f"{ENV_PREFIX}{field.upper()}: {message}" if field else message)
    return "; ".join(problems)
