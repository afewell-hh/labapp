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
3. Read the parent issue's current checkpoint (for #145, its latest status and
   named corrections) and any issue the task cites for the latest lead
   corrections. Newer lead comments supersede older issue text. The lead may
   replace long parent history with that checkpoint plus named corrections; this
   does not waive any named dependency.
4. Read the repo docs and code the task touches (see
   [documentation map](../README.md)). Inspect existing docs before adding files.
   Product, safety and authorization context (items 1-2 and the task's own
   limits) always stays required.
5. For research or external behavior, read current official sources (below).
6. Read what the task names as consequential: files, sections and comment IDs,
   each with the lead's reason. Prefer exact individual records over large
   collapsed threads. No named reading is silently waived.
7. Verify your own access (issue reads, web fetch, test commands) early. If
   something required is denied, say exactly which command, and stop or mark
   conclusions provisional. Do not substitute memory for sources.

Missing, partial, summarized, truncated or inaccessible required reading lowers
coverage even when the source is accessible to someone else. Continue sound
independent work; conclusions that depend on the gap are provisional. Later
lead or reviewer coverage does not retroactively complete worker onboarding.
Do not guess why a source was skipped; record that it was.
The lead records which criteria received complete independent coverage and which
remain provisional.

### Raw GitHub reading recipes

Use the intended allowed read route (`gh issue view` / `gh pr view` with
`--json` and `--jq`, as listed in the workflow's `allowedTools`). A denied
`gh api` call does not show these routes are unavailable, and a denied command
is never rerun in disguise or answered by widening permissions. Placeholders
below are `<N>`, `<PR>` and `<comment-id>`:

```bash
# Current checkpoint = the BODY up to the first "## " heading (not comments)
gh issue view <N> --repo afewell-hh/labapp --json body --jq '.body | split("\n## ")[0]'
# One exact comment, selected by its full URL
gh issue view <N> --repo afewell-hh/labapp --json comments \
  --jq '.comments[] | select(.url=="https://github.com/afewell-hh/labapp/issues/<N>#issuecomment-<comment-id>") | .body'
# Exact PR head commit
gh pr view <PR> --repo afewell-hh/labapp --json headRefOid
```

- Read the actual output. Record any denial, truncation, pagination or
  summarization; an empty filtered result (for example a mistyped URL) is not
  successful reading.
- The current checkpoint is the body. Partial or stale comment pagination cannot
  establish latest status.
- A PR head check does not show its source was read, and WebFetch summaries are
  not raw source. Omissions by an earlier worker remain omissions.
- These recipes add no approval flow or enforcement and do not make reading
  optional. Exact non-main source and upstream raw-source fetches are not shown
  by them to work (#290 stays limited); verify each route and report the result.

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
A separate bridge IPv4 job runs required Python synthetic tests and the unchanged
runtime helper in a disposable Ubuntu 24.04 network namespace with NET_ADMIN
only and no network access. Package preparation is separate; resource/time
bounds and exact owned cleanup are documented in `build/provision/README.md`.
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

Provisioning logic is written once and run unchanged in development tests and
approved image builders. The goal includes reproducible VM builds for multiple
platforms, with GCP as the current production delivery. The lead selects tools
based on source-backed research and measured fit; Packer is an option.

Shared guest provisioning and verification are separate from provider-specific
builders, lifecycle, access and guest adaptations (boot, drivers, networking,
guest agents and sealing). Each target needs artifact, boot/reboot and functional
VLAB/nested-virtualization validation; format conversion alone proves none of
these. Additional platform priorities and CPU scope remain open. Validate x86
and ARM runtime scope separately before claiming compatibility; existing GCP
work and component checks do not establish another target's support.

Each module must state, in its header and tests:

- **Interpreter**: shell modules use `#!/usr/bin/env bash` with `set -euo pipefail`,
  invoked as `bash path`, not relying on the executable bit. The pinned hhfab
  installer uses Ubuntu 24.04 Python 3.12 stdlib (host tests also support Python
  3.10+), invoked as `python3 path/install-hhfab.py`; keep its sibling
  `hhfab_release.py` available. It never executes the installed binary. The standalone
  bridge runtime artifact uses Ubuntu 24.04 Python 3.12 stdlib, invoked as
  `python3 path`; it is not a provisioning framework or image integration.
- **User/privilege**: who runs it (root vs `ubuntu`), and what needs `sudo`.
- **Environment**: overrides it reads (with defaults), noninteractive, no TTY.
  Packer's shell provisioner does not give your login environment; pass
  needed variables explicitly.
- **Working directory**: does not depend on the caller's cwd.
- **Dependencies**: tools it needs, checked up front with a clear error;
  pinned versions and verified checksums for downloads.
- **Idempotent** on rerun, and failures leave existing good state intact.

Reference: [`build/provision/README.md`](../../build/provision/README.md).

## Calling reviewed helpers

Before invoking an already-authorized reviewed helper, read its contract and
confirm the caller side. Do not invent a dry run or invoke a mutation just to
discover prerequisites. Checklist:

- Exact reviewed source and runtime (commit, interpreter, tool versions).
- Identity, environment and working directory the contract expects.
- Caller-created directories: existence, contents, ownership and modes.
- Input provenance: where each input came from and that it is the reviewed one.
- Output file ownership/mode and the caller's umask.
- Original clocks and watchdog state (intent, deadlines, timers).

**Refusal recovery.** For a caller-prerequisite refusal proven to have created
or changed no intent and sent no API mutation, correct the prerequisite and use
the supported path. If mutation completion is uncertain, do not blindly replay
it; use supported recovery. Read-only verification may overlap a scheduled timer
activation: use bounded completion observations under the original intent and
deadlines. Do not reset deadlines, disable a watchdog to pass a check, apply
blanket retry rules, expand permissions or introduce additional approval steps.

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
bounded lifecycle pilots, all on `main` with no inputs. The creator retains
its legacy filename for WIF but runs fixed Ubuntu `vlab-core` mode; historical
inspector dispatch is retired and existing inspector leases remain cleanable. The cleanup workflow also handles
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
for admission, an immutable cloud deadline, and verified VM/all-intended-disk cleanup.
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
- **Preserve reviewable work.** Check commit/push/PR capabilities early. If edits
  cannot be committed or pushed, deliver the exact unified diff or complete changed
  files through the authorized issue/PR handoff (never secrets), so the lead/local
  fallback can apply and review them. A description of uncommitted edits is not
  a transferable patch. Do not change permissions to bypass a denial.
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

### Offline validation in GitHub workers

The Claude Code Action v1 workflow adds scoped commands through
[`claude_args: --allowedTools`](https://github.com/anthropics/claude-code-action/blob/v1/docs/configuration.md).
It allows only `bash -n ...`, `shellcheck ...` and `git diff --check ...`
as added validation commands, alongside the existing source-research and
issue/PR commands. Run these static checks directly from the repository root.
Direct Python execution, including unittest discovery and `py_compile`, is
not allowed in this credential-bearing worker. Neither general shell
execution nor package installation is added. Missing dependencies and
executable tests require a CI/lead handoff.

For example, the worker can run these portable preparation static checks:

```bash
bash -n build/packer-qemu/guest/guest-build.sh
shellcheck build/packer-qemu/guest/guest-build.sh
git diff --check
```

**Command permissions are not a security sandbox.** Unittest imports and
executes repository code with access to the worker's runner/GitHub authority
and potentially its Claude authentication. Even `python3 -m py_compile` can
execute a repository-shadowed module: Python's
[`-m` lookup includes the current directory](https://docs.python.org/3/using/cmdline.html#cmdoption-m).
Do not run either command here or route test execution through another tool.
Supply exact Python test/compile commands to CI or the lead for verification
in a separately assessed environment. Existing CI is a fallback, not a claim
of credential-free or network-isolated execution. Record what actually ran
and its environment; worker static checks do not replace executable tests.
The task must still authorize any container, builder, VM or cloud execution.
[Claude permissions](https://code.claude.com/docs/en/permissions) distinguish
command approval from OS-level sandboxing. Do not use test code to bypass a
tool denial or the platform's workflow-write restriction.

The workflow's read-scoped `GITHUB_TOKEN` is distinct from the action's
[GitHub App token](https://github.com/anthropics/claude-code-action/blob/v1/src/github/token.ts),
whose default permissions include contents, PR and issue writes. Its existing
`id-token: write` supports the action's App-token exchange; it is not GCP
authorization. Keep both settings unchanged and keep cloud credentials,
private state and trusted lifecycle identities out of worker jobs. GCP access
continues to require the fixed-main workflow/event identities in the
[access runbook](../runbooks/gcp-build-access.md).

After a workflow permission change, the lead must verify a harmless, scoped
worker run and its actual results. A parsed allowlist is not execution evidence;
until verified, retain the CI/lead fallback and report denials exactly.

## Lead follow-up

- While an authorized session is active and jobs or reviews are pending, the
  lead checks roughly every 2 minutes and routes results and next work without
  waiting for the owner to ask for status.
- Consult actual commit-specific review/completion receipts as well as summary
  badges; summaries can lag completed code or security reviews. Resolve a mismatch
  against the exact reviewed commit and actual receipt before acceptance.
- Independent reviews and qualifying test runs use a clean, frozen checkout of
  the exact commit. A new head invalidates affected prior results; finish edits
  before freezing and rerun the affected checks against that head.
- Bring product, scope and budget choices, blockers and meaningful milestones
  to the owner.
- Routine progress and milestones are updates, not reasons to end active work
  or wait for a reply. Continue multiple authorized tasks, using bounded local
  waits and status checks. Ask only for material decisions or required access,
  and continue independent work while an answer is pending.
- After a turn or session ends, continuous monitoring requires a separately
  verified scheduled-task or event mechanism. Do not claim a timer or webhook
  exists unless one is configured and verified.
- Temporary task status stays in GitHub issues and PRs.

## Worker handoff (end of task)

State: exact head commit SHA, files changed, acceptance criteria met/unmet,
checks run (exact commands, results, limits), checks denied or not run, doc
updates, open uncertainties. Also state reading coverage: files and sections
read, comment IDs read, and any source skipped, partial, summarized, truncated
or inaccessible, with the resulting coverage limits. Evidence and references go
in GitHub in sanitized form; raw outputs that may contain sensitive data stay
private and are referenced, not published. Do not merge or close the issue.
