# Changelog

All notable changes to the Hedgehog Lab Appliance will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

---

## [0.1.0] - 2025-11-05

### Added
- Standard build pipeline using Packer for Ubuntu 22.04 LTS base (#2, #4)
- Automated orchestrator system with state machine for lab initialization (#7, #8)
- Systemd service for automatic first-boot initialization (#9)
- Terminal-based readiness UI showing real-time initialization progress (#10)
- VLAB initialization with 7-switch Hedgehog Fabric topology (#11)
- K3d cluster setup with observability stack (Prometheus, Grafana, Loki) (#12)
- Lab management CLI tool (hh-lab) with status, logs, and reset commands (#14, #15)
- Comprehensive user documentation including installation, quick start, troubleshooting, and FAQ (#17)
- Automated build validation tests for verifying OVA integrity (#18)
- End-to-end testing framework for validating complete builds (#21)
- Release process documentation with comprehensive checklists and guidelines (#19)
- GitHub Actions CI/CD workflow for standard builds (#5)

### Changed
- Build optimized for GitHub Actions runners with reduced resource allocation

### Fixed
- OVA compliance issues with disk capacity and manifest format
- Packer password hash and network check issues
- Orchestrator error handling and state management improvements
- CLI argument parsing and status detection logic
- VLAB resource counting to use Kubernetes YAML format
- JSON parsing robustness in readiness UI
- Test report generation on early failures

---

## How to Use This Changelog

This changelog documents all notable changes to the Hedgehog Lab Appliance project.

### For Users
- Check the latest version to see what's new
- Review upgrade instructions for breaking changes
- Find bug fixes that may affect you

### For Contributors
- Add entries to "Unreleased" section when making changes
- Use appropriate categories (Added, Changed, Fixed, etc.)
- Include issue numbers: `(#123)`
- Write in present tense: "Add feature" not "Added feature"
- Focus on user-visible changes

### Categories

- **Added** - New features
- **Changed** - Changes to existing functionality
- **Deprecated** - Soon-to-be removed features
- **Removed** - Removed features
- **Fixed** - Bug fixes
- **Security** - Security fixes

---

## Version History

<!-- Future releases will be documented below -->

<!--
Template for new releases:

## [X.Y.Z] - YYYY-MM-DD

### Added
- New feature description (#issue)

### Changed
- Change description (#issue)

### Fixed
- Bug fix description (#issue)

-->
