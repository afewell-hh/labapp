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

## Observed integration behavior (as of 2026-10-23)

Verified from issues #139, #140, #146, #148 and PR #149:

- The Claude worker (GitHub Action, tag mode) can read issues and research
  sources, edit files, push a branch and create PRs, under the scoped
  `--allowedTools` in `.github/workflows/claude.yml`.
- Some test commands (`bash -n`, `shellcheck`, `docker`) were denied to the
  worker. The lead-managed verifier ran them, and that is the evidence of
  record. Check the workflow file for current permissions rather than this list.
- Codex automatic PR review works and runs when a PR is opened or on
  `@codex review`. Lead-managed independent reviewers are also used.
- Tag mode may limit the worker to updating a single comment, so separate
  handoff comments are not guaranteed. Make the handoff explicit in that
  comment and the PR body.
- Not established: automatic bot-to-bot triggering, multi-round automatic
  review/fix loops, or the lead continuously monitoring. The lead dispatches
  and checks each step.
- The workflow triggers on `@claude` in newly opened issues, so issue
  templates must not contain live mentions; the lead dispatches separately.

## Worker handoff (end of task)

State: head commit SHA, files changed, acceptance criteria met/unmet, checks
run (exact commands, results, limits), checks denied or not run, doc updates,
open uncertainties. Do not merge or close the issue.
