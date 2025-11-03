# Product Backlog

Issues organized by priority for future development.

---

## MVP (v0.1.0) - In Progress
See [MVP_SPRINT_PLAN.md](MVP_SPRINT_PLAN.md) for detailed sprint breakdown.

---

## v0.2.0 - Pre-warmed Build

### Epic: Pre-warmed Build Pipeline
**Priority:** High
**Estimate:** 2 weeks

- [ ] #19: Create pre-warmed Packer configuration
- [ ] #20: Implement VLAB warm-up during build
- [ ] #21: Create manual GitHub Actions workflow
- [ ] #22: Add build type detection logic
- [ ] #23: Test pre-warmed boot performance
- [ ] #24: Document pre-warmed build usage

---

## v0.3.0 - Scenario Management

### Epic: Multi-Scenario Support
**Priority:** High
**Estimate:** 3 weeks

- [ ] #25: Design scenario definition format (YAML)
- [ ] #26: Create scenario management library
- [ ] #27: Implement `hh-lab scenario list`
- [ ] #28: Implement `hh-lab scenario apply <name>`
- [ ] #29: Implement `hh-lab scenario reset`
- [ ] #30: Create 5 pre-defined scenarios
  - module-1-1-fresh-start
  - module-2-1-vpc-exercise
  - module-2-2-attachments
  - module-3-1-observability
  - module-4-1-troubleshooting
- [ ] #31: Add scenario validation
- [ ] #32: Implement Gitea branch switching
- [ ] #33: Document scenario authoring guide

---

## v0.4.0 - Checkpoint System

### Epic: Checkpoint Save/Restore
**Priority:** Medium
**Estimate:** 2 weeks

- [ ] #34: Design checkpoint storage format
- [ ] #35: Implement `hh-lab checkpoint save <name>`
- [ ] #36: Implement `hh-lab checkpoint restore <name>`
- [ ] #37: Implement `hh-lab checkpoint list`
- [ ] #38: Add checkpoint metadata tracking
- [ ] #39: Implement checkpoint compression
- [ ] #40: Add checkpoint export/import
- [ ] #41: Test checkpoint integrity

---

## v1.0.0 - GA Release

### Epic: Web UI
**Priority:** Medium
**Estimate:** 4 weeks

- [ ] #42: Design web UI architecture
- [ ] #43: Create Flask/FastAPI backend
- [ ] #44: Implement lab status dashboard
- [ ] #45: Implement scenario switcher UI
- [ ] #46: Implement checkpoint UI
- [ ] #47: Add service links and credentials
- [ ] #48: Implement web-based readiness indicator

### Epic: Performance & Stability
**Priority:** High
**Estimate:** 2 weeks

- [ ] #49: Optimize boot time (<15 min target)
- [ ] #50: Reduce memory footprint
- [ ] #51: Improve error messages
- [ ] #52: Add crash recovery
- [ ] #53: Implement health monitoring
- [ ] #54: Add diagnostic data collection

### Epic: Testing & Quality
**Priority:** High
**Estimate:** 2 weeks

- [ ] #55: Expand unit test coverage
- [ ] #56: Add integration tests
- [ ] #57: Implement smoke tests
- [ ] #58: Add performance benchmarks
- [ ] #59: Create test automation framework

---

## Future / Post-v1.0

### Enhancements
**Priority:** Low / Nice to Have

- [ ] #60: ARM64 support (Apple Silicon)
- [ ] #61: Hyper-V native format
- [ ] #62: Docker-based lab alternative
- [ ] #63: Cloud-hosted option (AWS/GCP/Azure)
- [ ] #64: Multi-user support
- [ ] #65: LMS integration (Moodle, Canvas)
- [ ] #66: Automated grading system
- [ ] #67: Telemetry and analytics
- [ ] #68: Auto-update mechanism
- [ ] #69: Remote support tooling
- [ ] #70: Instructor dashboard

### Advanced Features
**Priority:** Low

- [ ] #71: Web-based scenario editor
- [ ] #72: Scenario marketplace/sharing
- [ ] #73: Custom topology support
- [ ] #74: Network traffic simulation
- [ ] #75: Integration with CI/CD for testing
- [ ] #76: API for programmatic control
- [ ] #77: Kubernetes operator for cloud deployment

---

## Icebox / Ideas

Ideas that may be considered in the future:

- Remote lab access via VNC/guacamole
- Collaborative labs (multiple students sharing one lab)
- Lab as a service (SaaS offering)
- Mobile app for status monitoring
- Voice-controlled lab management (Alexa/Google Assistant integration)
- AR/VR visualization of network topology
- AI-powered troubleshooting assistant

---

## Labeling Strategy

Issues should be tagged with:

**Type:**
- `kind/bug` - Something broken
- `kind/feature` - New functionality
- `kind/enhancement` - Improvement
- `kind/epic` - Large initiative
- `kind/task` - Development task
- `kind/docs` - Documentation

**Area:**
- `area/build` - Build pipeline
- `area/orchestrator` - Orchestration
- `area/cli` - CLI tools
- `area/ui` - User interface
- `area/test` - Testing
- `area/docs` - Documentation
- `area/ci` - CI/CD

**Priority:**
- `priority/critical` - Blocking
- `priority/high` - Important
- `priority/medium` - Normal
- `priority/low` - Nice to have

**Special:**
- `good-first-issue` - Good for newcomers
- `help-wanted` - Need assistance
- `blocked` - Cannot proceed

---

**Last Updated:** 2025-10-23
