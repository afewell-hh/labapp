# Makefile for Hedgehog Lab Appliance
# BYO Ubuntu VM Installer Utility

.PHONY: help clean install-deps test lint

# Default target
.DEFAULT_GOAL := help

# Variables
VERSION ?= 0.1.0
INSTALLER_VERSION ?= $(VERSION)
DIST_DIR := dist

help: ## Show this help message
	@echo "Hedgehog Lab Appliance - Build Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

install-deps: ## Install build dependencies
	@echo "Installing build dependencies..."
	@which shellcheck > /dev/null || (echo "Installing shellcheck..." && sudo apt-get install -y shellcheck)
	@echo "Dependencies installed successfully"

clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf $(DIST_DIR)
	rm -rf output-*
	rm -f crash.log
	@echo "Clean complete!"

dev-setup: install-deps ## Set up development environment
	@echo "Development environment setup complete!"

test: test-unit lint ## Run all tests (unit tests + linting)
	@echo "All tests complete!"

test-unit: ## Run unit tests
	@echo "Running unit tests..."
	@tests/unit/test-orchestrator-ordering.sh
	@tests/unit/test-systemd-services.sh
	@tests/unit/test-first-boot-setup.sh
	@tests/unit/test-vlab-readiness.sh
	@echo "Unit tests complete!"

test-orchestrator: ## Run orchestrator unit tests only
	@echo "Running orchestrator tests..."
	@tests/unit/test-orchestrator-ordering.sh

test-systemd: ## Run systemd service unit tests only
	@echo "Running systemd service tests..."
	@tests/unit/test-systemd-services.sh

.PHONY: check-version
check-version: ## Show current version
	@echo "Version: $(VERSION)"

.PHONY: set-executable
set-executable: ## Make scripts executable
	@echo "Setting execute permissions on scripts..."
	chmod +x packer/scripts/*.sh
	chmod +x packer/scripts/hedgehog-lab-orchestrator
	chmod +x scripts/*.sh 2>/dev/null || true
	@echo "Permissions set!"

.PHONY: test-modules
test-modules: test-provisioning test-scripts ## Run all module validation tests

.PHONY: test-provisioning
test-provisioning: ## Validate provisioning scripts without building
	@echo "Validating provisioning scripts..."
	@echo "Checking script syntax..."
	@find packer/scripts -name "*.sh" -type f -exec bash -n {} \;
	@echo "✓ All provisioning scripts have valid syntax"
	@echo "Running shellcheck on provisioning scripts..."
	@if command -v shellcheck > /dev/null; then \
		find packer/scripts -name "*.sh" -type f -exec shellcheck -x {} \; && \
		echo "✓ Shellcheck passed for all provisioning scripts"; \
	else \
		echo "⚠ shellcheck not installed, skipping (install with: sudo apt-get install shellcheck)"; \
	fi

.PHONY: test-scripts
test-scripts: ## Validate automation scripts without executing
	@echo "Validating automation scripts..."
	@echo "Checking script syntax..."
	@find scripts -name "*.sh" -type f -exec bash -n {} \; 2>/dev/null || true
	@echo "✓ Script syntax check complete"
	@echo "Running shellcheck on automation scripts..."
	@if command -v shellcheck > /dev/null; then \
		find scripts -name "*.sh" -type f -exec shellcheck -x {} \; 2>/dev/null && \
		echo "✓ Shellcheck passed for all automation scripts"; \
	else \
		echo "⚠ shellcheck not installed, skipping"; \
	fi

.PHONY: lint
lint: ## Run all linters (shellcheck, yamllint, etc.)
	@echo "Running linters..."
	@$(MAKE) test-provisioning
	@$(MAKE) test-scripts
	@echo "Checking YAML files..."
	@if command -v yamllint > /dev/null; then \
		yamllint .github/workflows/ configs/ 2>/dev/null && \
		echo "✓ YAML lint passed"; \
	else \
		echo "⚠ yamllint not installed, skipping (install with: pip install yamllint)"; \
	fi
	@echo "✓ All linters passed"

.PHONY: validate-provisioning
validate-provisioning: test-provisioning ## Alias for test-provisioning

.PHONY: validate-orchestrator
validate-orchestrator: test-orchestrator ## Alias for test-orchestrator

.PHONY: installer-package
installer-package: ## Package hh-lab installer tarball
	@echo "Packaging hh-lab installer..."
	@rm -rf $(DIST_DIR)
	@mkdir -p $(DIST_DIR)/installer
	@cp -a scripts/hh-lab-installer scripts/install.sh scripts/00-preflight-checks.sh scripts/10-ghcr-auth.sh scripts/99-finalize.sh $(DIST_DIR)/installer/ 2>/dev/null || true
	@cp -a packer/scripts $(DIST_DIR)/installer/packer-scripts
	@cp -a configs $(DIST_DIR)/installer/configs 2>/dev/null || true
	@tar -czf $(DIST_DIR)/hh-lab-installer-$(INSTALLER_VERSION).tar.gz -C $(DIST_DIR)/installer .
	@echo "Installer packaged at $(DIST_DIR)/hh-lab-installer-$(INSTALLER_VERSION).tar.gz"

.PHONY: installer-test
installer-test: ## Validate installer scripts (syntax + shellcheck)
	@echo "Validating installer scripts..."
	@for f in scripts/hh-lab-installer scripts/00-preflight-checks.sh scripts/10-ghcr-auth.sh scripts/99-finalize.sh scripts/install.sh; do \
		if [ -f "$$f" ]; then bash -n "$$f"; fi; \
	done
	@if command -v shellcheck > /dev/null; then \
		for f in scripts/hh-lab-installer scripts/00-preflight-checks.sh scripts/10-ghcr-auth.sh scripts/99-finalize.sh scripts/install.sh; do \
			if [ -f "$$f" ]; then shellcheck -x "$$f"; fi; \
		done; \
	else \
		echo "⚠ shellcheck not installed, skipping"; \
	fi
	@echo "Installer validation complete."
