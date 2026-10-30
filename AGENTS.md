# CI policy for coding agents

CI cost matters here. The workflows are deliberately **Linux-only and
single-job**, because this is a pure-Python package that needs no
cross-platform matrix. Keep them that way unless a real portability bug forces
otherwise.

## The per-commit gate

`.github/workflows/ci.yml` runs on every push and pull request: one job that
lints (`ruff check`, `select = ["ALL"]`), checks formatting
(`ruff format --check`), type-checks the package (`ty check vsphere_triage`),
and runs the **unit** suite (`pytest -m "not integration"`). That is the whole
required gate. Do not add an OS matrix, extra Python versions, or more jobs to
it to chase a single failure — a change that makes CI slower or costlier needs
a reason beyond convenience.

Type checking (`ty`) is scoped to the `vsphere_triage` package; the tests are
not type-checked (fixtures use loose typing on purpose). pyVmomi ships no types
and builds its `vim.*` classes dynamically, so a handful of lines at that
boundary carry `# ty: ignore[...]` with a reason — suppress at the line, do not
disable a rule globally, and keep `ty check vsphere_triage` at zero.

## The integration suite is not free, and not per-commit

`tests/integration/` builds **two simulated vCenters** with `vmware/vcsim` and
`vmware/govc` (two image pulls, ~90 s of work). It is marked with the
`integration` pytest marker and is **never** on the per-commit path. Run it:

- locally: `uv run python -m pytest` (needs a running Docker), or
- on CI by hand: Actions → CI → Run workflow → `integration = true`.

Dispatch it before a release, or when you change anything that touches the
vCenter session layer, the read-only guard, or the scenario fixtures. Do not
wire it into `ci.yml`'s automatic triggers.

## Local iteration

- `uv run python -m pytest -m "not integration" -q` — the fast gate
  (no Docker, ~1 s).
- `uv run python -m pytest -q` — everything, Docker required.
- `pytest --lf` / `pytest --ff` — re-run last failures first while iterating;
  don't delete `.pytest_cache` mid-investigation.

## Releasing

`.github/workflows/release.yml` publishes to PyPI via **Trusted Publishing**
(OIDC) — there is **no token** in the repo, and none should be added. Release
is a version bump: raise `version` in `pyproject.toml` (and the matching version
and `vsphere-triage==X.Y.Z` pin in `.claude-plugin/plugin.json`; a unit test
checks they agree), merge to `main`, and the workflow runs the `ci.yml` gate,
builds, verifies the wheel, publishes, tags, and makes the GitHub
release. A merge that does not change the version stops at the gate. Never
commit a PyPI token, and never weaken the version/tag consistency checks in
`build` — they are the guard against publishing the wrong artifact under a
version PyPI will not let you reclaim.

## The read-only guarantee

Every tool reads only, with the marked exceptions that act on a VM through the
session's raw (unguarded) stub: `run_in_guest`, the two power operations
`reboot_guest` / `hard_reset`, and the guest-reading `check_ems` /
`investigate_windows_boot` / `investigate_linux_boot` / `read_crash_dump` (which
reach the raw stub only when they run a command in the guest). The optional vROps and PowerFlex
clients are separate GET-only HTTP clients, not vSphere stubs. A test sweeps every read-only tool and asserts the
vSphere methods sent are a subset of `readonly.ALLOWED_METHODS`; others assert
that guest exec and the power operations never dirty that guarded surface, and
that the PowerFlex client issues only GET requests (its own read-only proof,
via a mock transport). If
you add a tool or a vSphere call, keep those tests passing — do not add a method
to the allowlist to silence the sweep without understanding why it is being
sent, and route any new non-read-only operation through the raw stub, never by
widening the allowlist.
