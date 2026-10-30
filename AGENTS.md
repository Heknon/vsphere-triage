# CI policy for coding agents

CI cost matters here. The workflows are deliberately **Linux-only and
single-job**, because this is a pure-Python package that needs no
cross-platform matrix. Keep them that way unless a real portability bug forces
otherwise.

## The per-commit gate

`.github/workflows/ci.yml` runs on every push and pull request: one job that
lints (`ruff check`), checks formatting (`ruff format --check`), and runs the
**unit** suite (`pytest -m "not integration"`). That is the whole required
gate. Do not add an OS matrix, extra Python versions, or more jobs to it to
chase a single failure — a change that makes CI slower or costlier needs a
reason beyond convenience.

## The integration suite is not free, and not per-commit

`tests/integration/` builds **two simulated vCenters** with `vmware/vcsim` and
`vmware/govc` (two image pulls, ~90 s of work). It is marked with the
`integration` pytest marker and is **never** on the per-commit path. Run it:

- locally: `uv run --extra dev python -m pytest` (needs a running Docker), or
- on CI by hand: Actions → CI → Run workflow → `integration = true`.

Dispatch it before a release, or when you change anything that touches the
vCenter session layer, the read-only guard, or the scenario fixtures. Do not
wire it into `ci.yml`'s automatic triggers.

## Local iteration

- `uv run --extra dev python -m pytest -m "not integration" -q` — the fast gate
  (no Docker, ~1 s).
- `uv run --extra dev python -m pytest -q` — everything, Docker required.
- `pytest --lf` / `pytest --ff` — re-run last failures first while iterating;
  don't delete `.pytest_cache` mid-investigation.

## Releasing

`.github/workflows/release.yml` publishes to PyPI via **Trusted Publishing**
(OIDC) — there is **no token** in the repo, and none should be added. Release
is a version bump: raise `version` in `pyproject.toml`, merge to `main`, and the
workflow builds, verifies the wheel, publishes, tags, and makes the GitHub
release. A merge that does not change the version stops at the gate. Never
commit a PyPI token, and never weaken the version/tag consistency checks in
`build` — they are the guard against publishing the wrong artifact under a
version PyPI will not let you reclaim.

## The read-only guarantee

Every tool reads only, with one marked exception (`run_in_guest`). A test sweeps
every read-only tool and asserts the vSphere methods sent are a subset of
`readonly.ALLOWED_METHODS`; another asserts guest exec never dirties that
surface. If you add a tool or a vSphere call, keep both tests passing — do not
add a method to the allowlist to silence the sweep without understanding why it
is being sent.
