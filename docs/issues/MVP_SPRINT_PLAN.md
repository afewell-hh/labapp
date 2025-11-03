# MVP Sprint Plan - v0.1.0

This document outlines the sprint structure for MVP development. Create these as GitHub Issues/Milestones.

---

## Milestone: v0.1.0 MVP
**Target Date:** Q4 2025 (8 weeks)
**Goal:** Working standard build with basic functionality

---

## Epic 1: Build Pipeline Infrastructure
**Label:** `kind/epic`, `area/build`
**Estimate:** 2 weeks

### Issues:

#### Issue #1: Set up Packer build environment
**Labels:** `kind/task`, `area/build`, `priority/critical`, `good-first-issue`
**Estimate:** 3 points
**Sprint:** 1

**Description:**
Set up basic Packer configuration and test build environment.

**Acceptance Criteria:**
- [ ] Packer installed and validated
- [ ] Base Ubuntu ISO configured
- [ ] Test build completes successfully
- [ ] Output in OVA format

**Technical Notes:**
- Use Ubuntu 22.04 LTS
- QEMU builder for flexibility
- Document hypervisor requirements

---

#### Issue #2: Create base image provisioning scripts
**Labels:** `kind/task`, `area/build`, `priority/high`
**Estimate:** 5 points
**Sprint:** 1

**Description:**
Create shell scripts for installing base software dependencies.

**Acceptance Criteria:**
- [ ] Script 01-install-base.sh (Ubuntu updates, tools)
- [ ] Script 02-install-k3d.sh (k3d binary)
- [ ] Script 03-install-hhfab.sh (Hedgehog Fabric tools)
- [ ] Script 04-install-tools.sh (kubectl, helm, etc.)
- [ ] All scripts are idempotent
- [ ] Error handling implemented

**Dependencies:**
- Requires #1

---

#### Issue #3: Implement standard build pipeline
**Labels:** `kind/task`, `area/build`, `priority/critical`
**Estimate:** 8 points
**Sprint:** 1

**Description:**
Create complete Packer configuration for standard build.

**Acceptance Criteria:**
- [ ] `packer/standard-build.pkr.hcl` created
- [ ] All provisioning scripts integrated
- [ ] Build completes in <60 minutes
- [ ] Output size <20GB compressed
- [ ] Checksum generation included

**Dependencies:**
- Requires #2

---

#### Issue #4: Set up GitHub Actions CI/CD for standard build
**Labels:** `kind/task`, `area/build`, `area/ci`, `priority/high`
**Estimate:** 5 points
**Sprint:** 2

**Description:**
Automate standard build via GitHub Actions.

**Acceptance Criteria:**
- [ ] Workflow triggers on tag push
- [ ] Validates Packer templates
- [ ] Builds standard OVA
- [ ] Uploads artifacts to releases
- [ ] Posts build status to PRs

**Dependencies:**
- Requires #3

---

## Epic 2: Orchestrator & Initialization System
**Label:** `kind/epic`, `area/orchestrator`
**Estimate:** 3 weeks

### Issues:

#### Issue #5: Design orchestrator architecture
**Labels:** `kind/task`, `area/orchestrator`, `priority/critical`
**Estimate:** 2 points
**Sprint:** 1

**Description:**
Design the orchestrator system that manages lab initialization.

**Acceptance Criteria:**
- [ ] Architecture document created (ADR-002)
- [ ] Component diagram
- [ ] State machine definition
- [ ] File/directory structure defined

**Deliverables:**
- `docs/adr/002-orchestrator-design.md`

---

#### Issue #6: Implement orchestrator main script
**Labels:** `kind/task`, `area/orchestrator`, `priority/critical`
**Estimate:** 8 points
**Sprint:** 2

**Description:**
Create the main orchestrator script that runs on first boot.

**Acceptance Criteria:**
- [ ] `/usr/local/bin/hedgehog-lab-orchestrator` created
- [ ] Build type detection works
- [ ] Initialization lockfile prevents concurrent runs
- [ ] Logging to `/var/log/hedgehog-lab-init.log`
- [ ] Initialized stamp file created on success
- [ ] Error handling and rollback

**Dependencies:**
- Requires #5

---

#### Issue #7: Create systemd service for orchestrator
**Labels:** `kind/task`, `area/orchestrator`, `priority/high`
**Estimate:** 3 points
**Sprint:** 2

**Description:**
Set up systemd service to run orchestrator on boot.

**Acceptance Criteria:**
- [ ] `hedgehog-lab-init.service` created
- [ ] Service runs after network-online.target
- [ ] Proper dependencies configured
- [ ] Logs accessible via journalctl
- [ ] Service enabled by default

---

#### Issue #8: Implement readiness UI (terminal)
**Labels:** `kind/task`, `area/orchestrator`, `area/ui`, `priority/medium`
**Estimate:** 5 points
**Sprint:** 2

**Description:**
Create terminal UI showing initialization progress.

**Acceptance Criteria:**
- [ ] Progress bar showing completion percentage
- [ ] Current step displayed
- [ ] Recent log activity shown
- [ ] Estimated time remaining
- [ ] Clear "READY" banner on completion
- [ ] Works without dialog/whiptail (fallback)

---

#### Issue #9: Create VLAB initialization script
**Labels:** `kind/task`, `area/orchestrator`, `priority/critical`
**Estimate:** 5 points
**Sprint:** 2

**Description:**
Script to initialize Hedgehog VLAB (for standard build first boot).

**Acceptance Criteria:**
- [ ] Starts VLAB with correct parameters
- [ ] Waits for control node ready
- [ ] Applies wiring diagram
- [ ] Waits for all switches to register
- [ ] Verifies fabric health
- [ ] Timeout handling (30 min max)

**Dependencies:**
- Requires #6

---

#### Issue #10: Create k3d-observability setup script
**Labels:** `kind/task`, `area/orchestrator`, `priority/high`
**Estimate:** 5 points
**Sprint:** 2

**Description:**
Script to create and configure k3d-observability cluster.

**Acceptance Criteria:**
- [ ] Creates k3d cluster with correct ports
- [ ] Installs kube-prometheus-stack
- [ ] Installs ArgoCD
- [ ] Installs Gitea
- [ ] Configures Grafana dashboards
- [ ] Verifies all pods running

---

## Epic 3: Lab Management CLI
**Label:** `kind/epic`, `area/cli`
**Estimate:** 1 week

### Issues:

#### Issue #11: Create hh-lab CLI tool
**Labels:** `kind/task`, `area/cli`, `priority/high`
**Estimate:** 5 points
**Sprint:** 3

**Description:**
Command-line tool for lab management.

**Acceptance Criteria:**
- [ ] `/usr/local/bin/hh-lab` executable
- [ ] Subcommands: status, logs, info, help
- [ ] Colored output for better UX
- [ ] Man page or help text
- [ ] Bash completion support

---

#### Issue #12: Implement hh-lab status command
**Labels:** `kind/task`, `area/cli`, `priority/medium`
**Estimate:** 3 points
**Sprint:** 3

**Description:**
Show current lab status including services and resources.

**Acceptance Criteria:**
- [ ] Shows build type
- [ ] Lists service health (k3d, VLAB, ArgoCD, etc.)
- [ ] Shows resource counts (switches, VPCs)
- [ ] Current scenario displayed
- [ ] Color-coded status indicators

---

## Epic 4: Testing & Documentation
**Label:** `kind/epic`, `area/test`, `area/docs`
**Estimate:** 1 week

### Issues:

#### Issue #13: Create installation/usage documentation
**Labels:** `kind/task`, `area/docs`, `priority/high`
**Estimate:** 3 points
**Sprint:** 3

**Description:**
User-facing documentation for installing and using the appliance.

**Acceptance Criteria:**
- [ ] Installation guide (VMware/VirtualBox)
- [ ] Quick start guide
- [ ] Service URLs and credentials documented
- [ ] Troubleshooting guide
- [ ] FAQ section

---

#### Issue #14: Implement build validation tests
**Labels:** `kind/task`, `area/test`, `priority/medium`
**Estimate:** 5 points
**Sprint:** 3

**Description:**
Automated tests to validate built appliances.

**Acceptance Criteria:**
- [ ] Script to boot and test appliance
- [ ] Verifies services start correctly
- [ ] Checks service endpoints
- [ ] Validates VLAB initialization
- [ ] CI integration

---

#### Issue #15: Create release checklist and process
**Labels:** `kind/task`, `area/process`, `priority/medium`
**Estimate:** 2 points
**Sprint:** 3

**Description:**
Define release process and checklist.

**Acceptance Criteria:**
- [ ] Release checklist document
- [ ] Version numbering strategy
- [ ] Changelog format
- [ ] Release notes template
- [ ] Distribution channels documented

---

## Epic 5: MVP Polish & Release
**Label:** `kind/epic`
**Estimate:** 1 week

### Issues:

#### Issue #16: End-to-end testing
**Labels:** `kind/task`, `area/test`, `priority/critical`
**Estimate:** 5 points
**Sprint:** 4

**Description:**
Comprehensive testing of complete appliance workflow.

**Acceptance Criteria:**
- [ ] Test standard build on VMware
- [ ] Test standard build on VirtualBox
- [ ] Verify all services accessible
- [ ] Test VLAB initialization
- [ ] Test GitOps workflow (create VPC via Gitea/ArgoCD)
- [ ] Test observability (Grafana dashboards)

---

#### Issue #17: Performance optimization
**Labels:** `kind/task`, `area/build`, `priority/medium`
**Estimate:** 3 points
**Sprint:** 4

**Description:**
Optimize build and boot times.

**Acceptance Criteria:**
- [ ] Build time <60 minutes
- [ ] Image size <20GB compressed
- [ ] Boot to ready <20 minutes (standard)
- [ ] Memory usage optimized

---

#### Issue #18: Create v0.1.0 release
**Labels:** `kind/task`, `priority/critical`
**Estimate:** 2 points
**Sprint:** 4

**Description:**
Package and release MVP.

**Acceptance Criteria:**
- [ ] Tag v0.1.0 created
- [ ] GitHub Release created
- [ ] Artifacts uploaded
- [ ] Release notes published
- [ ] Announcement prepared

---

## Sprint Breakdown

### Sprint 1 (Week 1-2): Foundation
**Focus:** Build pipeline basics
- Issue #1: Packer setup
- Issue #2: Provisioning scripts
- Issue #3: Standard build pipeline
- Issue #5: Orchestrator design

**Demo:** Show Packer building base Ubuntu image with dependencies

---

### Sprint 2 (Week 3-5): Core Orchestration
**Focus:** Initialization system
- Issue #4: CI/CD setup
- Issue #6: Orchestrator main script
- Issue #7: Systemd service
- Issue #8: Readiness UI
- Issue #9: VLAB init script
- Issue #10: K3d setup script

**Demo:** Show appliance booting and initializing with progress UI

---

### Sprint 3 (Week 6): CLI & Docs
**Focus:** User experience
- Issue #11: hh-lab CLI tool
- Issue #12: Status command
- Issue #13: Documentation
- Issue #14: Validation tests
- Issue #15: Release process

**Demo:** Show hh-lab CLI managing the lab

---

### Sprint 4 (Week 7-8): Polish & Release
**Focus:** Testing and release
- Issue #16: End-to-end testing
- Issue #17: Performance optimization
- Issue #18: v0.1.0 release

**Demo:** Full MVP walkthrough and release celebration 🎉

---

## Definition of Done

An issue is considered "Done" when:
- [ ] Code is written and reviewed
- [ ] Tests pass (if applicable)
- [ ] Documentation is updated
- [ ] PR is merged to main
- [ ] Issue is closed with summary

---

## Team Ceremonies (CNCF Style)

### Sprint Planning (Every 2 weeks)
- Review roadmap and backlog
- Select issues for upcoming sprint
- Estimate and assign work

### Daily Standup (Async via GitHub)
- Comment on assigned issues with progress
- Block issues if stuck
- Request reviews

### Sprint Review (End of each sprint)
- Demo completed work
- Gather feedback
- Update roadmap

### Sprint Retrospective (End of each sprint)
- What went well?
- What can improve?
- Action items for next sprint

---

**Last Updated:** 2025-10-23
