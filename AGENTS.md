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
- **Current build:** partly automated (cloud-init, `cloud-config.yaml`) and
  partly manual. The documented process is
  [docs/runbooks/manual-image-build.md](docs/runbooks/manual-image-build.md).
- **Current priority:** an efficient, reproducible, automated Packer image
  build using a lead / Claude worker / Codex reviewer workflow. No complete
  Packer automation exists yet; only the pinned k3d module pilot in
  `build/provision/`. GCP Marketplace publication is not the primary
  objective (decisions in #136 and #137).
- **Longer-term:** an installer for fresh Ubuntu 24.04 VMs; an EMC GitOps and
  observability stack (ArgoCD, Gitea, Prometheus, Grafana).
- **Status and plans:** GitHub only. Parent issue #145 and its children hold
  current status, the CI baseline and known gaps. Do not add plan or status files.
- **Hedgehog docs:** https://docs.hedgehog.cloud/latest/vlab/overview/

## Read before editing

1. Your task issue (and cited issues; newer lead comments supersede).
2. [docs/contributing/agent-workflow.md](docs/contributing/agent-workflow.md): roles, testing, evidence, handoff.
3. `README.md`, `STUDENT_QUICK_START.md`, and the code/docs you will change.

## Where things are

- `cloud-config.yaml`, `gcp_vm_launch_command.sh`: base system setup and VM launch
- `build/gcp/`: access bootstrap and offline VM lease primitives ([README](build/gcp/README.md))
- `build/provision/`: Packer-ready modules and tests ([README](build/provision/README.md))
- `docs/runbooks/`: manual image build and troubleshooting
- `docs/`: other docs ([index](docs/README.md)); `STUDENT_QUICK_START.md`: student guide
- `_archive/`, `archive2/`: archived, not part of the current project

## Hard rules

- No cloud commands, production access, or image builds unless the task
  explicitly authorizes them. Delete any test VMs you create.
- Authorized build/test work allows at most three VM slots, including stopped
  and cleanup-pending resources; default to one job. Required runtime limits
  and verified child-resource cleanup are in the
  [GCP access runbook](docs/runbooks/gcp-build-access.md). No VM launches until
  those lifecycle gates are implemented, reviewed and tested (#153).
- Build/test work uses `teched-473722`, which also holds the published image;
  protect that image and every preexisting resource. Builder IAM is a separate
  review, and no broad project Compute/storage administration is approved.
- Use the trusted metadata workflow for cloud reads; never give general worker
  jobs cloud credentials. Access setup is separate from build authorization.
- Never commit secrets. Do not merge or close issues; the lead accepts work.
- A failed, denied or unrun check is not passing evidence; report it exactly.
- Update this file and the workflow doc when the workflow changes.
