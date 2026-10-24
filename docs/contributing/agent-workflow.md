# Agent and contributor workflow

Stable process for the lead, ephemeral workers and independent reviewers.
Temporary plans, status, experiments and evidence live only in GitHub issues
and PRs, never in repo files. Current status and dependencies are in the parent
issue (#145) and its children; this document describes only stable rules.

## Roles

| Role | Owns | Does not |
|---|---|---|
| **Lead** (human owner plus any orchestrating session) | Scope, task dispatch, dependencies, issue status, cost/cloud authorization, evidence review, acceptance, merge | Delegate acceptance or merge to a worker or reviewer |
| **Worker** (ephemeral Claude run) | Scoped execution of one task, its docs, its evidence, an explicit handoff | Expand scope, run unauthorized cloud/production actions, merge, close issues, mark its own work accepted |
| **Reviewer** (independent, e.g. Codex PR review) | Judging the change against the task's acceptance criteria *and* significant defects | Rubber-stamp: a default bug-focused review alone does not show every criterion was assessed |

Workers start with no memory. Everything they need must be in the issue, this
document, or files it links.

## Required onboarding (before editing)

1. Read the task issue fully, including its dependencies and acceptance criteria.
2. Read [`AGENTS.md`](../../AGENTS.md) (entrypoint) and this file.
3. Read the parent issue #145 and any issue the task cites for the latest lead
   corrections. Newer lead comments supersede older issue text.
4. Read the repo docs and code the task touches (see
   [documentation map](../README.md)). Inspect existing docs before adding files.
5. For research or external behavior, read current official sources (below).
6. Verify your own access (issue reads, web fetch, test commands) early. If
   something required is denied, say exactly which command, and stop or mark
   conclusions provisional. Do not substitute memory for sources.

## Research and sources

- Use current primary sources: official docs, maintainer repos/release pages,
  the Hedgehog docs (`https://docs.hedgehog.cloud/latest/vlab/overview/`).
- For each consequential claim record URL, access date and version scope
  (e.g. docs say cloud-init 26.2; Ubuntu 24.04 ships its own version).
- Separate verified current behavior, historical reports and unknowns.
- A page that 404'd or was only partly read is stated as such.
- A command described in docs but not executed is "documented", not "tested".

## Active CI checks

CI uses Ubuntu 24.04 distribution packages for Bash/ShellCheck, yamllint and
cloud-init schema validation. It checks every tracked active `.sh` file
(excluding `_archive/` and `archive2/`), active YAML and the embedded
`write_files` shell scripts in `cloud-config.yaml` without executing them.
The schema check validates configuration structure, not installation or boot.
The YAML rules permit indentless sequences, the cloud-config header and long
embedded commands; syntax, duplicate keys and whitespace are still checked.

From the repository root, after installing `shellcheck`, `yamllint`,
`cloud-init` and `python3-yaml` through apt:

```bash
git ls-files -z '*.sh' ':(exclude)_archive/**' ':(exclude)archive2/**' > /tmp/labapp-active-shell
mapfile -d '' -t scripts < /tmp/labapp-active-shell
for script in "${scripts[@]}"; do bash -n "$script" || exit 1; done
shellcheck -x "${scripts[@]}"
yamllint .yamllint.yml .github marketplace cloud-config.yaml wiringd.yaml
cloud-init --version
cloud-init schema --config-file cloud-config.yaml --annotate
```

A separate 10-minute CI job runs the existing k3d install/failure suite in two
fresh Ubuntu containers, with an eight-minute command timeout. It mounts only
`build/provision` read-only and gives guests no Docker socket or credentials.
It verifies installation, not a Docker daemon, cluster or appliance boot.
Historical launch recipes are `gcp_vm_launch_command.txt`, not a runnable script.

New lifecycle/controller code must add its actual offline test command to CI
in the same PR that introduces it; shell checks alone cannot cover lifecycle
invariants. Do not add placeholder test steps that pass when tests are absent.

## Testing: cheapest representative first

Choose the cheapest layer that can catch the failure class, and say what it
cannot prove. Full VM builds are not required for every change.

| Layer | Examples | Cannot prove |
|---|---|---|
| 1. Offline | `bash -n`, `shellcheck`, YAML parse, `cloud-init schema --config-file F --annotate` | Packages/URLs exist, script behavior, boot |
| 2. Disposable container | Real module run twice in `ubuntu:24.04`, no Docker socket or host credentials | systemd, kernel, running Docker, cloud-init, KVM |
| 3. Disposable VM / cloud-init runtime | Full module sequence twice on a fresh Ubuntu 24.04 VM, then a verification script | Nested KVM/VLAB, GCP image boot (unless nested virt VM) |
| 4. Full image build, boot and reboot | Build image, boot from it, health script, reboot | Student experience |
| 5. Student/demo acceptance | Course exercises by a human | Anything not exercised |

- Escalate a layer when an assumption fails (e.g. the failure depends on
  systemd) or when the change touches what a lower layer cannot prove.
- Final gates for an image release: a clean build from pinned inputs, boot and
  reboot checks, and student/demo acceptance. Intermediate work is not done
  because a lower layer passed.
- Cache or reuse a checkpoint only if its key includes base image identity,
  resolved versions, package sources, configuration and scripts. Keep clean
  release builds.
- cloud-init schema validation checks structure and known keys only; it does
  not run script bodies.
- **A failed, denied, skipped or unrun check is not passing evidence.** Record
  the exact command and outcome. A passing run must say what environment it ran
  in (image digest, versions, timing).

## Same-code execution contract

Provisioning logic is written once and run unchanged in development tests, and
later in Packer. Each module must state, in its header and tests:

- **Interpreter**: `#!/usr/bin/env bash` with `set -euo pipefail`; invoked as
  `bash path`, not relying on the executable bit.
- **User/privilege**: who runs it (root vs `ubuntu`), and what needs `sudo`.
- **Environment**: overrides it reads (with defaults), noninteractive, no TTY.
  Packer's shell provisioner does not give your login environment; pass
  needed variables explicitly.
- **Working directory**: does not depend on the caller's cwd.
- **Dependencies**: tools it needs, checked up front with a clear error;
  pinned versions and verified checksums for downloads.
- **Idempotent** on rerun, and failures leave existing good state intact.

Reference: [`build/provision/README.md`](../../build/provision/README.md).

## Bounded iterations and escalation

- A worker makes at most two focused revision rounds after review findings on
  the same PR. Unresolved disagreement or a blocker goes to the lead as a
  compact blocker report (what was tried, exact error/denial, options).
- Do not loop on a failing check by weakening it. Do not regenerate a long
  document after tool/context failure; report the blocker.
- Slices should be coherent and independently verifiable: neither tiny blind
  full-build increments nor unbounded batches.

## Documentation placement and update duties

| Content | Home |
|---|---|
| Entry points for agents | `AGENTS.md` (short); `CLAUDE.md` is a thin pointer |
| Process, roles, testing, execution contract | this file |
| Operational runbooks (manual image build, troubleshooting) | `docs/runbooks/` |
| Module usage/tests | `build/provision/README.md` next to the code |
| Student/demo instructions | `STUDENT_QUICK_START.md`, `docs/` |
| Task plans, status, CI baseline, source/image gaps, evidence | GitHub issues and PRs only |

Every component change records, in the PR: sources and compatibility/version
scope; checks performed and their limits; docs updated (or why none); and the
reviewer handoff. Update the doc nearest the change; do not copy long context
into task issues or new files.

## Preserve production and user work

Labapp is a production GCP image used for Hedgehog LMS labs and demos.
Do not touch production resources, create images or cloud resources, or run
deployment scripts unless the task explicitly authorizes it. Don't rewrite
`_archive/` or `archive2/` unless asked. Never commit secrets.

## Authorized cloud work

Use the [GCP access runbook](../runbooks/gcp-build-access.md) for the trusted
keyless runner boundary. For explicitly authorized scope, the lead may dispatch
`labapp-cloud.yml` for fixed image metadata reads, or the fixed
`labapp-lifecycle-inspect.yml` and `labapp-lifecycle-cleanup.yml` for serial
lifecycle pilots, all on `main` with no inputs. The cleanup workflow also handles
validated completed creator runs and scheduled due-lease reconciliation; see
[runner behavior](../../build/gcp/README.md#fixed-lifecycle-runner).
No arbitrary commands, refs, PR code or triggering-run artifacts enter these
workflows. Lifecycle creator and cleanup use separate identities; cloud
credentials stay out of general worker jobs. Use the existing Labapp
project `teched-473722`; protect its published/source image and all preexisting
resources. Builder IAM requires separate review and must preserve those assets;
no broad project Compute/storage administration is implied.

For explicitly authorized build/test tasks, maximum three project VM slots
includes stopped, reserved and cleanup-pending resources; default to one job.
Reuse requires confirmed deletion of the VM and owned temporary children.
Default VM bounds: 60 minutes for component/inspection work, 120 minutes for a
full build, no silent extension. Require cloud-side bounds at creation,
normal/cancelled/failed-job cleanup and independent expiry cleanup, with exact
ownership and immutable IDs. Check quotas before launch; do not increase them
implicitly. The fixed serial lifecycle uses its CAS ledger and project census
for admission, an immutable cloud deadline, and verified VM/both-disk cleanup.
New cloud behavior still requires reviewed/tested lifecycle gates and separately
reviewed IAM before launch; routine Packer builds and guest recovery are separate
scope. Overall acceptance and live evidence remain in #153/#161. No production
changes or broad IAM are implied by build/test authorization.

## Dispatch, tool access and handoff operations

Current status, permission and CI baselines, and evidence live in GitHub, not
here: see #145 (parent), #139 and #140.

- **Dispatch.** The lead dispatches work with an explicit `@claude` or
  `@codex review` comment on the issue or PR. Issue and PR templates must not
  contain live mentions, because the workflow triggers on `@claude` in newly
  opened issues.
- **Check capabilities first.** Before work that depends on a tool (shell
  checks, `docker`, web fetch, `gh` subcommands, PR creation), the worker
  checks what it is actually allowed to run. The authority is the current
  `--allowedTools` in `.github/workflows/claude.yml` plus what the run
  permits, not memory or older comments.
- **Denied means handoff, not pass.** If a command is denied, the worker does
  not substitute a claim. It records the exact command and denial, supplies
  the correct command for someone else to run, and marks the dependent
  conclusion unverified.
- **Lead arranges verification.** The lead runs or assigns denied or
  independent checks and reviews, and records results in the issue or PR.
- **Confirm bot handoffs.** Tag mode may limit a worker to one comment, and
  bot-to-bot triggering is not assumed. Treat a handoff or review request as
  delivered only after an actual acknowledgement or run appears, and state the
  handoff explicitly in the PR comment and body.
- Multi-round automatic review/fix loops and monitoring outside an active
  session are not assumed; see "Lead follow-up" below.

## Lead follow-up

- While an authorized session is active and jobs or reviews are pending, the
  lead checks roughly every 2 minutes and routes results and next work without
  waiting for the owner to ask for status.
- Bring product, scope and budget choices, blockers and meaningful milestones
  to the owner.
- After a turn or session ends, continuous monitoring requires a separately
  verified scheduled-task or event mechanism. Do not claim a timer or webhook
  exists unless one is configured and verified.
- Temporary task status stays in GitHub issues and PRs.

## Worker handoff (end of task)

State: head commit SHA, files changed, acceptance criteria met/unmet, checks
run (exact commands, results, limits), checks denied or not run, doc updates,
open uncertainties. Do not merge or close the issue.
