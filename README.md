# Hedgehog Lab Appliance

Virtual appliance for Hedgehog Fabric learning and lab exercises.

## Project Status

🚧 **In Development** - MVP in progress

[![Standard Build](https://github.com/example/labapp/workflows/build-standard/badge.svg)](https://github.com/example/labapp/actions)
[![Pre-warmed Build](https://github.com/example/labapp/workflows/build-prewarmed/badge.svg)](https://github.com/example/labapp/actions)

## Overview

The Hedgehog Lab Appliance is a pre-configured virtual machine that provides a complete learning environment for Hedgehog Fabric. It includes:

- Hedgehog Virtual Lab (VLAB) with 7-switch topology
- GitOps stack (ArgoCD, Gitea)
- Observability stack (Prometheus, Grafana, Loki)
- Scenario management system
- Lab orchestration tools

## Quick Start

```bash
# Download the appliance from GCS
gsutil cp gs://hedgehog-lab-artifacts-teched-473722/releases/hedgehog-lab-standard-build-20251110-235348.ova .

# Import into VMware/VirtualBox/GCP (see Installation Guide)

# After first boot, login (hhlab/hhlab) and run setup wizard:
hh-lab setup

# The wizard will:
# 1. Prompt for GitHub credentials (required for GHCR)
# 2. Authenticate with ghcr.io
# 3. Start initialization (15-20 minutes)

# Access services:
# - Grafana: http://localhost:3000 (admin/admin)
# - ArgoCD: http://localhost:8080 (admin/<see /var/lib/hedgehog-lab/argocd-admin-password>)
# - Gitea: http://localhost:3001 (hedgehog/hedgehog)
# - Desktop: RDP to <vm-ip>:3389 or VNC to <vm-ip>:5901
```

## Build Types

### Standard Build (Current)
- **Size:** ~3-4 GB compressed
- **First boot:** Requires GHCR setup, then 15-20 minutes initialization
- **Use case:** Self-paced learning, workshops, training
- **Distribution:** Google Cloud Storage
- **Features:**
  - Ubuntu 24.04 LTS base
  - XFCE desktop with RDP/VNC access
  - VS Code, Firefox pre-installed
  - Hedgehog VLAB (7-switch topology)
  - k3d observability cluster
  - GitOps stack (ArgoCD, Gitea)
  - Prometheus + Grafana monitoring

### Pre-warmed Build (Future)
- **Status:** Coming soon (after Issue #74)
- **Size:** TBD
- **First boot:** 2-3 minutes
- **Use case:** In-person workshops with limited internet
- **Distribution:** USB drives or pre-provisioned cloud instances

## Documentation

### User Documentation
- [Installation Guide](docs/INSTALL.md) - Download and install on VMware/VirtualBox
- [Quick Start Guide](docs/QUICKSTART.md) - First-time setup and usage
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md) - Solutions to common issues
- [FAQ](docs/FAQ.md) - Frequently asked questions

### Developer Documentation
- [Build Guide](docs/build/BUILD_GUIDE.md) - Build the appliance from source
- [Contributing Guide](CONTRIBUTING.md) - Contribution guidelines
- [Roadmap](ROADMAP.md) - Product roadmap and timeline
- [Changelog](CHANGELOG.md) - Version history and changes
- [Release Process](docs/RELEASE_PROCESS.md) - Release guidelines and checklists
- [Architecture Decision Records](docs/adr/) - Design decisions
- [Sprint Planning](docs/issues/MVP_SPRINT_PLAN.md) - Current sprint
- [Observability Remote Write](docs/observability-remote-write.md) - Alloy → Prometheus pipeline details (Issue #96)

## Project Management

- **Issues:** Track work via GitHub Issues with labels
- **Milestones:** Organized by release versions (v0.1.0, v0.2.0, etc.)
- **Projects:** GitHub Projects for sprint planning
- **Process:** CNCF-style agile development

## Getting Started (Contributors)

```bash
# Clone the repository
git clone https://github.com/YOUR_ORG/hedgehog-lab-appliance.git
cd hedgehog-lab-appliance

# Install dependencies (TBD)
make dev-setup

# Run tests (TBD)
make test

# Build locally (TBD)
make build-standard
```

## Community

- **Discussions:** GitHub Discussions for Q&A and ideas
- **Issues:** Bug reports and feature requests
- **Contributing:** See [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

Built with ❤️ for the Hedgehog Fabric community.
