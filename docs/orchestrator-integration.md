# Using it with an orchestrator (e.g. Sahara)

The server is generic: it discovers each vCenter's layout and never hard-codes a
folder path, a naming pattern or a product. Nothing below is required to run it.
This page is how to make it fit a platform that creates short-lived VMs in
per-environment folders and raises VMware Tools errors when one does not come
up — Sahara is the example it was first built for, but any orchestrator with the
same shape fits the same way.

The integration is two things: **configuration** (so the server speaks your
layout's vocabulary) and **a skill** (so the model follows your incident
procedure). Neither changes the server's code.

## 1. Configuration

The server already identifies a VM by `(vcenter, moref)` and discovers the
environment folders. Three settings make it line up with an orchestrator's
conventions:

- `VSPHERE_VCENTERS` — the vCenters, each with the `aliases` your logs use for
  it. The server matches a vCenter by its name, host, the host's first label and
  any alias, so whatever spelling an upstream error carries resolves to the
  right vCenter.
- `VSPHERE_ENV_PARENT_HINTS` — the folder names that group environments, e.g.
  `environments,projects`. This is only a search ordering: an environment not
  found under a hinted parent is still found anywhere, and the result says where.
- `VSPHERE_GUEST_USERNAME` / `VSPHERE_GUEST_PASSWORD` — default guest-OS
  credentials for `run_in_guest`, if you use it. Omit them to require credentials
  per call.

When an orchestrator's error names the vCenter, the machine and the environment,
that maps straight onto `diagnose_vm(vcenter, env_id=..., vm_name=...)`. When the
orchestrator knows *when* it rebooted or powered on a VM, pass that as
`rebooted_at` — a guest reboot does not move vCenter's power-on time, so without
it a warm-rebooted VM can look up for days.

## 2. The incident skill

The server answers questions; the *procedure* for an incident — which layer to
look at first, what rules a cause out, what to write at the end — lives in a
Claude Code skill, not in the server. A skill is delivered through your plugin /
skills channel, not `pip install`.

An orchestrator-specific skill names the layers above vCenter that the server
cannot see (the orchestrator's own logs, the system that waited for Tools, your
metrics store) and threads them into the diagnosis the server produces. The
`vm-incident` skill in this repository is such a procedure written for the
Sahara stack (its orchestrator, its creator/runner, its metrics). Treat it as a
template: keep the rungs that read this server's tools, and swap the top rungs
for your own platform's logs and timeouts.

## What stays generic

Everything the server itself does is vendor-neutral: the states and flags, the
scan grouping, the CPU/storage/boot/console/serial checks, the host-time,
resource-limit, snapshot, datastore and template (base-disk) views, and the
read-only guarantee. The only platform-specific parts are the configuration
values above and the wording of the incident skill — both outside the code.
