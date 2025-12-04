# Hedgehog Lab Appliance - Test Suite

This directory contains all testing infrastructure for the Hedgehog Lab Appliance project.

## Test Organization

```
tests/
├── README.md           # This file
└── e2e/               # End-to-end testing
    ├── README.md      # E2E testing guide
    ├── TEST_PLAN.md   # Comprehensive test procedures
    ├── TEST_EXECUTION_TEMPLATE.md  # Test report template
    ├── scripts/       # Automated test scripts
    └── results/       # Test results (gitignored)
```

## Test Types

### End-to-End (E2E) Tests

Located in `e2e/` directory.

**Purpose:** Validate the complete appliance workflow from build to deployment to service availability.

**Documentation:** See [e2e/README.md](e2e/README.md)

**Quick Start:**
```bash
# Inside deployed appliance VM
cd /tmp
git clone https://github.com/afewell-hh/labapp.git
cd labapp/tests/e2e

# Run all tests
./scripts/run-all-tests.sh

# Run individual tests
./scripts/validate-services.sh
./scripts/validate-vlab.sh
./scripts/validate-gitops.sh
./scripts/validate-observability.sh
```

### Future Test Types

- **Unit Tests** (planned for v0.2.0)
  - Shell script unit tests
  - Module-level testing

- **Integration Tests** (planned for v0.2.0)
  - Component integration testing
  - API integration testing

- **Performance Tests** (planned for v0.3.0)
  - Resource usage benchmarks
  - Initialization time benchmarks
  - Service response time tests

- **Security Tests** (planned for v1.0.0)
  - Vulnerability scanning
  - Security configuration validation
  - Credential security tests

## Running Tests

### Prerequisites

Most tests run **inside** the deployed appliance VM. Ensure:
- Appliance is deployed and initialized
- SSH access available (or use VM console)
- Default credentials: `hhlab:hhlab`

### Quick Test Run

```bash
# SSH into appliance
ssh hhlab@<vm-ip>

# Clone repository (if not present)
git clone https://github.com/afewell-hh/labapp.git

# Run tests
cd labapp/tests/e2e
./scripts/run-all-tests.sh
```

### CI/CD Integration

E2E tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions job
test-e2e:
  runs-on: ubuntu-latest
  steps:
    - name: Run E2E tests
      run: |
        # Deploy appliance in nested virtualization
        # Wait for initialization
        # Run test suite
        ./tests/e2e/scripts/run-all-tests.sh
```

See `.github/workflows/` for actual CI implementations.

## Test Results

Test results are stored in `e2e/results/` directory (gitignored):

- JSON format for automation
- Human-readable summaries
- Timestamped for tracking

**Example:**
```
results/
├── build-validation-20251105-120000.json
├── service-validation-20251105-120500.json
├── vlab-validation-20251105-121000.json
└── test-summary-20251105-121500.txt
```

## Contributing Tests

When adding new tests:

1. **Follow the pattern** of existing test scripts
2. **Output JSON results** for automation
3. **Use color-coded logging** for readability
4. **Include error messages** for failures
5. **Update documentation** (README, TEST_PLAN.md)
6. **Add to test suite** (run-all-tests.sh)

### Test Script Template

```bash
#!/bin/bash
# test-name.sh
# Description of what this test validates

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/../results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULT_FILE="${RESULTS_DIR}/test-name-${TIMESTAMP}.json"

# Test tracking
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
FAILURES=()

# Test functions
test_pass() { ((TESTS_RUN++)); ((TESTS_PASSED++)); }
test_fail() { ((TESTS_RUN++)); ((TESTS_FAILED++)); FAILURES+=("$1: $2"); }

# Main logic
main() {
    # Run tests
    # Write results
    # Exit with appropriate code
}

main "$@"
```

## Documentation

- **E2E Testing Guide:** [e2e/README.md](e2e/README.md)
- **Test Plan:** [e2e/TEST_PLAN.md](e2e/TEST_PLAN.md)
- **Test Execution Template:** [e2e/TEST_EXECUTION_TEMPLATE.md](e2e/TEST_EXECUTION_TEMPLATE.md)
- **Project Contributing Guide:** [../CONTRIBUTING.md](../CONTRIBUTING.md)

## Related Issues

- **Issue #21:** End-to-end testing
- **Issue #18:** Implement build validation tests
- **Issue #16:** [EPIC] Testing & Documentation

## Support

- **Issues:** https://github.com/afewell-hh/labapp/issues
- **Discussions:** https://github.com/afewell-hh/labapp/discussions
- **Documentation:** https://github.com/afewell-hh/labapp/docs

---

**Last Updated:** 2025-11-05
**Maintainer:** Hedgehog Lab Team
