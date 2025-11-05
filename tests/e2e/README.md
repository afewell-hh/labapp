# End-to-End Testing Guide

This directory contains comprehensive end-to-end (E2E) tests for the Hedgehog Lab Appliance.

## Overview

E2E testing validates the complete appliance workflow from build to deployment to service availability. These tests ensure that users can successfully:

1. Build the appliance OVA
2. Import into VMware/VirtualBox
3. Boot and initialize the appliance
4. Access all services
5. Use the VLAB environment
6. Execute GitOps workflows
7. View observability dashboards

## Test Structure

```
tests/e2e/
├── README.md                       # This file
├── TEST_PLAN.md                    # Comprehensive test plan and procedures
├── scripts/
│   ├── validate-build.sh           # Validates built OVA artifacts
│   ├── validate-services.sh        # Tests service availability inside VM
│   ├── validate-vlab.sh            # Tests VLAB functionality
│   ├── validate-gitops.sh          # Tests GitOps workflow
│   ├── validate-observability.sh   # Tests observability stack
│   └── run-all-tests.sh            # Executes all validation tests
└── results/
    └── .gitkeep                    # Test results are stored here
```

## Test Categories

### 1. Build Validation Tests
- Verifies Packer build completes successfully
- Validates OVA file creation
- Checks checksums
- Confirms file sizes are within expected ranges

**Script:** `scripts/validate-build.sh`

### 2. Service Validation Tests
- Tests all services start correctly
- Validates service endpoints are accessible
- Checks service health and readiness
- Verifies service configurations

**Script:** `scripts/validate-services.sh`

**Services tested:**
- k3d cluster
- VLAB switches
- GitOps stack (ArgoCD, Gitea)
- Observability stack (Prometheus, Grafana, Loki)

### 3. VLAB Validation Tests
- Verifies VLAB initialization completed
- Tests switch containers are running
- Validates network topology
- Checks switch console access

**Script:** `scripts/validate-vlab.sh`

### 4. GitOps Workflow Tests
- Creates test repository in Gitea
- Deploys application via ArgoCD
- Validates GitOps sync
- Tests configuration updates

**Script:** `scripts/validate-gitops.sh`

### 5. Observability Tests
- Validates Prometheus is collecting metrics
- Tests Grafana dashboards are accessible
- Verifies Loki is ingesting logs
- Checks alert rules

**Script:** `scripts/validate-observability.sh`

## Running Tests

### Prerequisites

Tests are designed to run **inside** the deployed appliance VM after initialization completes.

**Requirements:**
- Appliance initialized and running
- SSH access to the VM (or run locally via console)
- Default credentials: `hhlab:hhlab`

### Quick Test

Run all validation tests:

```bash
# SSH into the appliance or use VM console
ssh hhlab@<vm-ip>

# Clone the repository (if not already present)
git clone https://github.com/afewell-hh/labapp.git
cd labapp/tests/e2e

# Run all tests
./scripts/run-all-tests.sh
```

### Individual Tests

Run specific test categories:

```bash
# Test services only
./scripts/validate-services.sh

# Test VLAB only
./scripts/validate-vlab.sh

# Test GitOps workflow
./scripts/validate-gitops.sh

# Test observability stack
./scripts/validate-observability.sh
```

### Build Validation

For build validation (runs on build machine, not in VM):

```bash
# After packer build completes
./scripts/validate-build.sh <output-directory>

# Example:
./scripts/validate-build.sh /path/to/labapp/output-hedgehog-lab-standard
```

## Manual Testing Procedures

For comprehensive manual testing procedures including:
- VMware Workstation/Fusion/ESXi testing
- VirtualBox testing
- Network configuration testing
- Performance testing
- User acceptance testing

See: **[TEST_PLAN.md](TEST_PLAN.md)**

## Test Results

Test scripts generate results in `results/` directory:

```
results/
├── build-validation-YYYYMMDD-HHMMSS.json
├── service-validation-YYYYMMDD-HHMMSS.json
├── vlab-validation-YYYYMMDD-HHMMSS.json
├── gitops-validation-YYYYMMDD-HHMMSS.json
└── observability-validation-YYYYMMDD-HHMMSS.json
```

Results are in JSON format for easy parsing and CI integration.

## CI Integration

These tests are designed for integration with GitHub Actions:

1. **Build Validation:** Runs after Packer build in CI
2. **Service Validation:** Can be run in nested virtualization environment
3. **Manual Validation:** Performed before releases

See `.github/workflows/e2e-tests.yml` (future enhancement).

## Acceptance Criteria

For release v0.1.0 MVP, all tests must pass:

- ✅ Standard build completes on VMware
- ✅ Standard build completes on VirtualBox
- ✅ All services accessible
- ✅ VLAB initialization succeeds
- ✅ GitOps workflow functional
- ✅ Observability dashboards accessible

## Reporting Issues

If tests fail:

1. Check test results in `results/` directory
2. Review appliance logs: `hh-lab logs`
3. Check service-specific logs
4. Create GitHub issue with:
   - Test script that failed
   - Full error output
   - Test result JSON file
   - Appliance logs
   - Environment details (VMware/VirtualBox version, host OS, etc.)

## Future Enhancements

- [ ] Automated VM deployment and testing
- [ ] Performance benchmarking
- [ ] Load testing
- [ ] Security testing
- [ ] Upgrade testing
- [ ] Chaos/resilience testing
- [ ] Pre-warmed build testing
- [ ] Multi-scenario testing

## Contributing

When adding new tests:

1. Follow existing script structure
2. Output results in JSON format
3. Include detailed error messages
4. Update this README
5. Add test to `run-all-tests.sh`
6. Update TEST_PLAN.md if manual procedures are required

## Support

- **Issues:** https://github.com/afewell-hh/labapp/issues
- **Documentation:** https://github.com/afewell-hh/labapp/docs
- **Discussions:** https://github.com/afewell-hh/labapp/discussions
