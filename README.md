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
# Download the appliance
# Standard build (15-20GB)
wget https://releases.example.com/hedgehog-lab-standard-latest.ova

# Import into VMware/VirtualBox
# Start the VM and wait for initialization
# Access services at http://localhost:3000 (Grafana), :8080 (ArgoCD), :3001 (Gitea)
```

## Build Types

### Standard Build (Default)
- **Size:** 15-20GB compressed
- **First boot:** 15-20 minutes (one-time initialization)
- **Use case:** Self-paced online learning
- **Distribution:** Direct download

### Pre-warmed Build (On-demand)
- **Size:** 80-100GB compressed
- **First boot:** 2-3 minutes
- **Use case:** In-person workshops, instructor-led training
- **Distribution:** USB drives, local network, cloud storage

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
