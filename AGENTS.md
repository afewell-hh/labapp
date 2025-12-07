<!-- # Hedgehog Lab Appliance – Agent Playbook (Updated 2025-12-01)

Read this before touching the repo. It supersedes any prior agent guidance and applies to **all** dev/CI agents.

---

## 1. Mission Snapshot
- **Product:** A BYO (Bring Your Own) Ubuntu VM installer utility that configures a fully functional Hedgehog VLAB plus External Management Cluster (EMC).
- **Distribution Model:** Users provision their own Ubuntu 24.04 VM (GCP n2-standard-32 with nested virtualization recommended) and run the installer script.
- **Near-Term Objectives:**
  1. Complete the installer utility that automates the manual installation process (see `docs/MANUAL_INSTALLATION_GUIDE.md`).
  2. Implement proper VLAB readiness verification before declaring installation complete.
  3. Configure EMC GitOps + observability stack (ArgoCD, Gitea, Prometheus, Grafana with Hedgehog dashboards).
- **Source of Truth:**
  - Manual installation guide: `docs/MANUAL_INSTALLATION_GUIDE.md` (ground truth for what the installer must do)
  - Hedgehog docs: `https://docs.hedgehog.cloud/latest/vlab/overview/`

---

## 2. Project Structure

**Active Components:**
- `installer/modules/` - Installer modules (01-install-base.sh, 20-k3d-observability-init.sh, 30-vlab-init.sh, etc.)
- `installer/modules/hhfab-vlab-runner` - VLAB execution wrapper (runs in tmux session)
- `docs/MANUAL_INSTALLATION_GUIDE.md` - Step-by-step manual process the installer automates
- `tests/` - Unit and integration tests

**Archived (NOT part of current project):**
- `_archive/ova-build/` - OVA Packer templates, GCP OVA builder scripts (Issue #97 pivoted away from OVA)
- `_archive/ova-legacy/` - Pre-warmed OVA components
- `_archive/aws-metal-build/` - AWS metal instance build infrastructure

---

## 3. Non-Negotiable Rules
1. **No work without an issue.** Every change must reference a GitHub Issue (`Closes #X`).
2. **Feature branches only.** `main` is protected; do not commit or push to it directly.
3. **TDD mindset.** Update/add tests first so failures guide implementation. CI must pass before merge.
4. **Code review required.** Another maintainer/lead must approve every PR. Never self-merge.
5. **Secrets stay out of git.** Use `.env` (gitignored) for tokens, credentials, etc.
6. **No destructive git commands** (`reset --hard`, `rebase -i`, etc.) unless the Team Lead explicitly instructs.

---

## 4. Standard Workflow
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
git commit -m "feat(installer): add VLAB readiness verification

Closes #102"

# Push + PR
git push origin feature/<issue>-<slug>
gh pr create --fill --base main --head feature/<issue>-<slug>
```

### PR Checklist
- [ ] Conventional commit(s) with `Closes #<issue>`.
- [ ] Tests updated and run locally.
- [ ] Docs updated if behavior changes.
- [ ] CI workflows green (lint + unit/integration).
- [ ] No secrets or debug artifacts.

---

## 5. Testing Expectations
| Layer | Typical Command | Notes |
| --- | --- | --- |
| Lint | `make lint` / `make test-lint` | shellcheck, markdownlint, yamllint, etc. |
| Unit | `make test` or module-specific targets | Use Bats/pytest for installer module logic. |
| Integration | `make test-modules`, bespoke scripts | Should run headless in GitHub Actions without hhfab. |
| E2E | Manual on GCP VM | Launch Ubuntu 24.04 VM, run installer, verify VLAB comes up. |

Never skip tests because "they're slow"; improve them instead.

---

## 6. E2E Testing on GCP

To test the installer end-to-end:

```bash
# Launch a test VM (Ubuntu 24.04, nested virt enabled)
gcloud compute instances create labapp-test-$(date +%Y%m%d-%H%M%S) \
  --project=YOUR_PROJECT \
  --zone=us-central1-a \
  --machine-type=n2-standard-32 \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=400GB \
  --boot-disk-type=pd-ssd \
  --enable-nested-virtualization \
  --min-cpu-platform="Intel Cascade Lake"

# SSH in and run installer
gcloud compute ssh labapp-test-XXXXX --zone=us-central1-a

# On the VM:
git clone https://github.com/afewell-hh/labapp.git
cd labapp
# Run installer modules or test scripts
```

**Important:** Delete test VMs when done to stay within quota (500GB persistent disk limit).

---

## 7. Installer Architecture

The installer follows the phases documented in `docs/MANUAL_INSTALLATION_GUIDE.md`:

1. **Phase 1-2:** Base system setup (user, packages, Docker, KVM)
2. **Phase 3:** hhfab installation and initialization
3. **Phase 4:** fab.yaml configuration (TLS SANs, Alloy telemetry) - **MUST happen BEFORE vlab up**
4. **Phase 5:** VLAB startup (`hhfab vlab up`)
5. **Phase 6:** VLAB readiness verification
6. **Phase 7-8:** EMC k3d cluster with observability stack
7. **Phase 9-10:** Networking, final verification

**Critical:** fab.yaml patching (Phase 4) MUST complete before `hhfab vlab up` (Phase 5). This enables external access and telemetry from the start.

---

## 8. Orchestrator, hhfab & EMC Requirements
- VLAB **must** finish initializing before any EMC/GitOps code runs. Enforce via explicit dependency order.
- `hhfab vlab up` runs inside a systemd-managed tmux session (`hhfab-vlab`). The session stays detached by default.
- EMC stack = single-node k3d cluster hosting ArgoCD, Gitea, Prometheus, Grafana (with official Hedgehog dashboards).
- Logs belong under `/var/log/hedgehog-lab/` (init + module subdirs). Use consistent log prefixes to simplify troubleshooting.

---

## 9. Communication Protocol
- Use GitHub Issues/PRs for updates. If blocked, comment with what you tried, logs, and what you need.
- Document assumptions inside the issue or PR description. Don't guess silently.
- If a spec changes mid-work, update the relevant doc (this file, etc.) as part of the same PR.

---

## 10. Quick Reference
```
# Credentials
[ -f .env ] && source .env

# Branch helper (optional)
./scripts/new-branch.sh <issue> <slug>

# Run linting
make lint

# Run tests
make test

# Orchestrator unit tests
make test-orchestrator
```

Keep this document accurate. If reality changes, update CLAUDE.md (and AGENTS.md) **immediately** alongside your code. -->
