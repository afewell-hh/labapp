# Hedgehog Lab Appliance

Virtual appliance for Hedgehog Fabric learning and lab exercises.

## Project Status

🚧 **In Development** – shifting from OVA to Bring-Your-Own VM installer (Issue #97).

## Overview

Hedgehog Lab now installs onto a fresh Ubuntu 24.04 VM you provide. The installer delivers:

- Hedgehog Virtual Lab (VLAB) with 7-switch topology
- EMC GitOps stack (ArgoCD, Gitea)
- Observability stack (Prometheus, Grafana)
- hh-lab CLI for status/logs/monitoring

## Quick Start (BYO Ubuntu 24.04)

```bash
curl -fsSL https://raw.githubusercontent.com/afewell-hh/labapp/main/scripts/install.sh \
  | sudo bash -s -- --ghcr-user <github_user> --ghcr-token <read:packages_pat>

# Monitor progress
hh-lab status
hh-lab logs -f

# Access services (after completion)
# Grafana:   http://<host-ip>:3000  (admin/prom-operator)
# ArgoCD:    http://<host-ip>:8080  (password from argocd-initial-admin-secret)
# Gitea:     http://<host-ip>:3001  (gitea_admin/admin123)
# Prometheus:http://<host-ip>:9090
```

## Build Types

### BYO Ubuntu Installer (Default)
- **Delivery:** `hh-lab-installer` script (no prebuilt image required)
- **Use case:** Students bring their own Ubuntu 24.04 VM (cloud or local)
- **Flow:** Run installer → orchestrator initializes VLAB + EMC
- **Status:** 🚧 New in Issue #97 (replaces legacy `hh-lab setup`)

### Standard Build (Legacy OVA)
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
