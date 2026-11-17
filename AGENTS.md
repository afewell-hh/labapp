# Hedgehog Lab Appliance – Agent Entrypoint

Short entrypoint for all dev/CI agents (Codex, Claude). Read this, then the
shared workflow: [docs/contributing/agent-workflow.md](docs/contributing/agent-workflow.md).
Codex does not document an import mechanism, so this file uses plain links;
`CLAUDE.md` imports this file for Claude Code.

## Mission snapshot

- **Product:** A pre-configured GCP VM image with a working Hedgehog VLAB
  environment. It is already a production image, used for Hedgehog LMS lab
  exercises at hedgehog.cloud/learn and for demos. Students run the VM
  alongside course content in a separate terminal/window; it is not embedded
  in the LMS.
- **Published image:** built with a partly automated (cloud-init,
  `cloud-config.yaml`) and partly manual process documented in
  [docs/runbooks/manual-image-build.md](docs/runbooks/manual-image-build.md).
  A separate native GCP candidate-image recipe is in `build/packer-gcp/`,
  `build/ansible/` and `build/releases/`. Candidate status and promotion gates
  are in #588; adding this recipe does not publish an image.
- **Current priority:** efficient, reproducible, automated VM builds for
  multiple platforms, with GCP as the current production delivery. The lead
  selects tools based on source-backed research and measured fit, using a
  lead / Claude worker / independent-reviewer workflow (see
  [review routing](docs/contributing/agent-workflow.md#independent-review-routing)). Same-code provisioning
  modules and container checks live in `build/provision/`; the native GCP recipe
  now builds private candidates. Additional platform priorities and CPU
  scope are open; compatibility requires validation. GCP Marketplace publication
  is not the primary objective (decisions in #136 and #137).
- **Longer-term:** an installer for fresh Ubuntu 24.04 VMs and ongoing course,
  GitOps and observability updates.
- **Status and plans:** GitHub only. The current lead handoff is #518; R0 build
  and course evidence is in #588. #145 is historical context. Do not add plan
  or status files.
- **Hedgehog docs:** https://docs.hedgehog.cloud/latest/vlab/overview/

## Lead takeover or crash recovery

A replacement lead starts with this file and
[Lead takeover and crash recovery](docs/contributing/agent-workflow.md#lead-takeover-and-crash-recovery),
then finds the current handoff #518 and R0 record #588 on GitHub. Current facts live
there, not in the repo.

## Read before editing

1. Your task issue and cited sources, using the shared workflow’s scoped parent-reading rules; newer lead comments supersede.
2. [docs/contributing/agent-workflow.md](docs/contributing/agent-workflow.md): roles, testing, evidence, handoff and [raw GitHub reading recipes](docs/contributing/agent-workflow.md#raw-github-reading-recipes).
3. `README.md`, `STUDENT_QUICK_START.md`, and the code/docs you will change.

## Where things are

- `cloud-config.yaml`, `gcp_vm_launch_command.txt`: base system setup and historical VM launch recipes
- `build/gcp/`: access bootstrap, fixed lifecycle runner and offline collector ([README](build/gcp/README.md))
- `build/provision/`: Packer-ready modules and tests ([README](build/provision/README.md))
- `build/packer-gcp/`, `build/ansible/`, `build/releases/`: native private GCP
  candidate-image recipe and pinned guest configuration ([README](build/packer-gcp/README.md));
  it has separate lifecycle ownership from `build/gcp/` and `build/packer-qemu/`
- `build/packer-qemu/`: stock Packer/QEMU VM experiment with separately scoped VM execution;
  fixed non-VM Docker `probe`, `hcl-check` and `runtime-check` tasks require separately
  scoped lead execution ([README](build/packer-qemu/README.md)). The fixed `sentinel`
  VM mode pins an accepted runtime identity (#266); each actual trial still requires
  separate lead scope and reconciled shared-ledger admission. Runtime preparation
  artifacts and tool checks alone do not authorize VM execution. `runtime/Dockerfile`
  describes the separately gated preparation recipe. Fixed hosted preparation hooks
  (`runtime-prepare.sh`, `runtime_prepare.py`) build no VM and require separately
  scoped lead execution. The fixed `sentinel-expiry` failure-only VM proof has a concrete pinned
  runtime identity; actual execution still requires separately scoped lead authorization.
  The fixed `fixture` mode stages the unchanged pinned hhfab installer and archive,
  verifies two installs and isolated refusals, and also requires separately scoped
  lead execution. The fixed `qemu-fixture` mode (#292) and non-VM `control-build` mode (#299)
  are the only modes with ordinary outbound Docker bridge networking (not allowlisted egress);
  `qemu-fixture` runs the unchanged QEMU network installer twice and the KVM witness,
  `control-build` measures the unchanged official hhfab control-installer build (no KVM), and
  their source activation likewise needs separately scoped lead execution. Results and remaining
  gates live in GitHub.
- `docs/runbooks/`: manual image build and troubleshooting
- `docs/`: other docs ([index](docs/README.md)); `STUDENT_QUICK_START.md`: student guide
- `_archive/`, `archive2/`: archived, not part of the current project

## Hard rules

- No cloud commands, production access, or image builds unless the task
  explicitly authorizes them. Delete any test VMs you create. For native R0,
  read #518 and #588 for current operational holds before a paid run.
- Authorized build/test work allows at most three VM slots, including stopped
  and cleanup-pending resources; default to one job. Required runtime limits
  and verified child-resource cleanup are in the
  [GCP access runbook](docs/runbooks/gcp-build-access.md). The existing
  `build/gcp/` lifecycle requires its reviewed gates (#153); native R0 uses
  the separately reviewed ownership and cleanup recorded in #588.
- Build/test work uses `teched-473722`, which also holds the published image;
  protect that image and every preexisting resource. Builder IAM is a separate
  review, and no broad project Compute/storage administration is approved.
- For `build/gcp/` operations, use the fixed trusted-main workflows for
  authorized metadata reads and serial bounded lifecycle pilots (the WIF-pinned
  `labapp-lifecycle-inspect.yml` path
  selects the fixed disposable canonical Ubuntu trial); see the [GCP access runbook](docs/runbooks/gcp-build-access.md).
  Never give general worker jobs cloud credentials. Access setup and lifecycle
  pilots do not authorize routine Packer builds or guest recovery. Native R0
  operations follow the separately scoped path in #588.
- Independent reviews are lead-routed to Copilot (explicit model, or the distinct
  built-in review); native Codex review only on explicit owner request. See
  [review routing](docs/contributing/agent-workflow.md#independent-review-routing).
- Never commit secrets. Do not merge or close issues; the lead accepts work.
- A failed, denied or unrun check is not passing evidence; report it exactly.
- Update this file and the workflow doc when the workflow changes.
