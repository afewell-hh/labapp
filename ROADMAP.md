# Hedgehog Lab Appliance - Roadmap

## Vision

Provide the best learning experience for Hedgehog Fabric through a fully-automated, scenario-driven virtual lab appliance.

---

## Release Timeline

### v0.1.0 - MVP (Target: Q4 2025)
**Goal:** Working standard build with basic functionality

**Key Features:**
- ✅ Standard build pipeline (Packer)
- ✅ Basic orchestrator with readiness UI
- ✅ Single default scenario
- ✅ Core services (k3d, VLAB, GitOps, Observability)
- ✅ Automated CI/CD for standard builds

**Deliverables:**
- Standard OVA (~15-20GB)
- Basic documentation
- GitHub Actions workflow

---

### v0.2.0 - Pre-warmed Build (Target: Q1 2026)
**Goal:** Add pre-warmed build for workshops

**Key Features:**
- ✅ Pre-warmed build pipeline
- ✅ On-demand build workflow
- ✅ Build type detection and handling
- ✅ Workshop distribution tooling

**Deliverables:**
- Pre-warmed OVA (~80-100GB)
- Workshop deployment guide
- Cloud storage integration

---

### v0.3.0 - Scenario Management (Target: Q1 2026)
**Goal:** Multi-scenario support

**Key Features:**
- ✅ Scenario definition framework
- ✅ CLI scenario switching
- ✅ Scenario validation
- ✅ Pre-defined scenarios for course modules

**Deliverables:**
- 5+ pre-defined scenarios
- Scenario authoring guide
- Automated scenario testing

---

### v0.4.0 - Checkpoint System (Target: Q2 2026)
**Goal:** Save and restore lab state

**Key Features:**
- ✅ Checkpoint save/restore
- ✅ Metadata tracking
- ✅ Checkpoint compression
- ✅ Export/import checkpoints

**Deliverables:**
- Checkpoint CLI commands
- Checkpoint storage backend
- User guide

---

### v1.0.0 - GA Release (Target: Q2 2026)
**Goal:** Production-ready appliance

**Key Features:**
- ✅ All core features stable
- ✅ Comprehensive documentation
- ✅ Performance optimization
- ✅ Automated testing suite
- ✅ Web UI for lab management

**Deliverables:**
- Stable API
- Full documentation site
- Certification program ready
- Community support channels

---

## Future Considerations (Post v1.0)

### Advanced Features
- [ ] Web-based scenario editor
- [ ] Multi-user lab environments
- [ ] Cloud-hosted lab option (AWS/GCP/Azure)
- [ ] Integration with LMS platforms
- [ ] Telemetry and usage analytics
- [ ] Automated lab grading
- [ ] Instructor dashboard

### Platform Support
- [ ] ARM64 support (Apple Silicon)
- [ ] Hyper-V native format
- [ ] Docker-based lab (alternative to VM)
- [ ] Kubernetes-in-Kubernetes option

### Operations
- [ ] Automated update mechanism
- [ ] Health monitoring and diagnostics
- [ ] Remote support tooling
- [ ] Crash reporting

---

## Milestone Tracking

| Milestone | Target Date | Status |
|-----------|-------------|--------|
| MVP (v0.1.0) | Q4 2025 | 🚧 In Progress |
| Pre-warmed (v0.2.0) | Q1 2026 | 📋 Planned |
| Scenarios (v0.3.0) | Q1 2026 | 📋 Planned |
| Checkpoints (v0.4.0) | Q2 2026 | 📋 Planned |
| GA (v1.0.0) | Q2 2026 | 📋 Planned |

---

## Decision Log

Major architectural decisions are tracked in `docs/adr/` (Architecture Decision Records).

---

**Last Updated:** 2025-10-23
