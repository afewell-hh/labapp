# Hedgehog Lab Appliance – Agent Playbook (Updated 2025-11-08)

Read this before touching the repo. It supersedes any prior agent guidance and applies to **all** dev/CI agents.

---

## 1. Mission Snapshot
- **Product:** An OVA that boots into a fully configured Hedgehog VLAB plus External Management Cluster (EMC).
- **Near-Term Objectives:**
  1. Reorder first-boot orchestration and run `hhfab vlab up --controls-restricted=false --ready wait` inside a persistent systemd+tmux service (GitHub Issue #73).
  2. Rebuild the EMC GitOps + observability stack with Hedgehog dashboards and the curriculum repo preloaded (Issue #74).
  3. Stand up the GCP-based nested-virtualization builder workflow and local validation harness (Issue #75).
- **Build Strategy:** Validate everything locally via test harnesses, then run full Packer builds only on the GCP builder (nested KVM, ≥600 GB SSD). Pre-warmed builds stay blocked until the cold build is reliable.
- **Source of Truth:** Hedgehog docs under `docs/docs/vlab/` and curriculum assets in `learn_content_scratchpad/`.

---

## 2. Non-Negotiable Rules
1. **No work without an issue.** Every change must reference a GitHub Issue (`Closes #X`).
2. **Feature branches only.** `main` is protected; do not commit or push to it directly.
3. **TDD mindset.** Update/add tests first so failures guide implementation. CI must pass before merge.
4. **Code review required.** Another maintainer/lead must approve every PR. Never self-merge.
5. **Secrets stay out of git.** Use `.env` / `.env.gcp` (gitignored) for tokens, service-account keys, etc.
6. **No destructive git commands** (`reset --hard`, `rebase -i`, etc.) unless the Team Lead explicitly instructs.

---

## 3. Standard Workflow
```
# Sync + branch
git checkout main
git pull origin main
git checkout -b feature/<issue>-<slug>

# Prep & tests first
make test-lint        # shellcheck/yamllint/etc.
make test-modules     # local harness (add if missing)

# Implement per acceptance criteria
#  - Scripts must be idempotent, logged, and error-checked
#  - Update docs in the same PR

# Verify
make test             # or the specific target required by the issue

# Commit (Conventional Commit)
git commit -m "feat(orchestrator): gate EMC on hhfab service

Closes #73"

# Push + PR
git push origin feature/<issue>-<slug>
gh pr create --fill --base main --head feature/<issue>-<slug>
```

### PR Checklist
- [ ] Conventional commit(s) with `Closes #<issue>`.
- [ ] Tests updated and run locally.
- [ ] Docs (README/BUILD_GUIDE/etc.) updated.
- [ ] CI workflows green (lint + unit/integration).
- [ ] No secrets or debug artifacts.

---

## 4. Testing Expectations
| Layer | Typical Command | Notes |
| --- | --- | --- |
| Lint | `make lint` / `make test-lint` | shellcheck, markdownlint, yamllint, etc. |
| Unit | `make test` or module-specific targets | Use Bats/pytest for orchestrator + EMC logic. |
| Integration | `make test-modules`, bespoke scripts | Should run headless in GitHub Actions without hhfab. |
| Builder Dry-Run | `scripts/launch-gcp-build.sh --dry-run` | Validates env parsing + pre-flight logic. |
| Full Packer | GCP builder only | Capture logs + upload artifacts to GCS. |

Never skip tests because “they’re slow”; improve them instead.

---

## 5. Environment & Secrets
- `.env` already contains GitHub/AWS creds. `source .env` before using `gh`, AWS, etc.
- `.env.gcp` (template committed later) will track GCP project, zone, service account, bucket names. Do **not** commit the real file.
- Provisioning scripts must install hhfab, docker, oras, k3d/k3s as required. Version bumps go into `CHANGELOG.md` + release notes.

---

## 6. Orchestrator, hhfab & EMC Requirements
- VLAB **must** finish initializing (hhfab init + `hhfab vlab inspect`) before any EMC/GitOps code runs. Enforce via explicit dependency order.
- `hhfab vlab up` runs inside a systemd-managed tmux session (`hhfab-vlab`). The session stays detached by default; students can inspect via `tmux ls` and `tmux attach -t hhfab-vlab`.
- EMC stack = single-node k3s/k3d cluster hosting ArgoCD, Gitea, Prometheus, Grafana (with official Hedgehog dashboards). ArgoCD must sync the seeded `student/hedgehog-config` repo to the Hedgehog controller’s host-facing interface.
- Logs belong under `/var/log/hedgehog-lab/` (init + module subdirs). Use consistent log prefixes to simplify troubleshooting.

---

## 7. Build & Release Flow
1. Run local validation targets (`make test-modules`, etc.) on every PR.
2. For full builds, use the GCP builder script/terraform:
   - Launch nested-virt VM (e.g., `n2-standard-32`, 600 GB SSD) with service account scoped to storage + compute.
   - Sync repo, run `make build-standard`, upload `*.ova` + `.sha256` to the designated GCS bucket.
   - Tear down or park the VM to control costs.
3. Attach build logs + artifact links to the tracking issue/PR.
4. Update release notes + checksums before tagging.

Pre-warmed builds (`packer/prewarmed-build.pkr.hcl`) stay blocked until Issues #73–#75 close.

---

## 8. Communication Protocol
- Use GitHub Issues/PRs for updates. If blocked, comment with what you tried, logs, and what you need.
- Document assumptions inside the issue or PR description. Don’t guess silently.
- If a spec changes mid-work, update the relevant doc (this file, build guide, ADR) as part of the same PR.

---

## 9. Quick Reference
```
# Credentials
autoload_env() { [ -f .env ] && source .env; [ -f .env.gcp ] && source .env.gcp; }
autoload_env

# Branch helper (optional)
./scripts/new-branch.sh <issue> <slug>

# Orchestrator unit tests
make test-orchestrator

# EMC integration tests (add target per Issue #74)
make test-emc

# GCP builder dry run
scripts/launch-gcp-build.sh --dry-run
```

Keep this document accurate. If reality changes, update CLAUDE.md (and AGENTS.md) **immediately** alongside your code.
