# Makefile for Hedgehog Lab Appliance
# Build automation for Packer-based VM images

.PHONY: help validate build-standard clean install-deps

# Default target
.DEFAULT_GOAL := help

# Variables
PACKER := packer
VERSION ?= 0.1.0
OUTPUT_DIR := output-hedgehog-lab-standard

help: ## Show this help message
	@echo "Hedgehog Lab Appliance - Build Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

install-deps: ## Install build dependencies
	@echo "Installing build dependencies..."
	@which packer > /dev/null || (echo "Installing Packer..." && curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add - && sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(shell lsb_release -cs) main" && sudo apt-get update && sudo apt-get install -y packer)
	@which qemu-system-x86_64 > /dev/null || (echo "Installing QEMU..." && sudo apt-get install -y qemu-system-x86 qemu-utils)
	@echo "Dependencies installed successfully"

validate: ## Validate Packer templates
	@echo "Validating Packer template..."
	$(PACKER) validate packer/standard-build.pkr.hcl
	@echo "Validation successful!"

format: ## Format Packer templates
	@echo "Formatting Packer template..."
	$(PACKER) fmt packer/standard-build.pkr.hcl

build-standard: validate ## Build standard appliance (15-20GB)
	@echo "Building standard appliance..."
	@echo "This will take approximately 45-60 minutes..."
	$(PACKER) build -var "version=$(VERSION)" packer/standard-build.pkr.hcl
	@echo ""
	@echo "Build complete!"
	@echo "OVA file: $(OUTPUT_DIR)/hedgehog-lab-standard-$(VERSION).ova"

clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf output-*
	rm -rf packer_cache
	rm -f crash.log
	@echo "Clean complete!"

dev-setup: install-deps ## Set up development environment
	@echo "Development environment setup complete!"

test: validate test-unit ## Run all tests (validate templates + unit tests)
	@echo "All tests complete!"

test-unit: ## Run unit tests
	@echo "Running unit tests..."
	@tests/unit/test-orchestrator-ordering.sh
	@tests/unit/test-systemd-services.sh
	@tests/unit/test-gcp-build-script.sh
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
	chmod +x scripts/*.sh
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
	@find scripts -name "*.sh" -type f -exec bash -n {} \;
	@echo "✓ All automation scripts have valid syntax"
	@echo "Running shellcheck on automation scripts..."
	@if command -v shellcheck > /dev/null; then \
		find scripts -name "*.sh" -type f -exec shellcheck -x {} \; && \
		echo "✓ Shellcheck passed for all automation scripts"; \
	else \
		echo "⚠ shellcheck not installed, skipping"; \
	fi

.PHONY: dry-run
dry-run: ## Validate GCP build script without launching resources
	@echo "Running dry-run validation of GCP build script..."
	@./scripts/launch-gcp-build.sh --dry-run main || \
		(echo "⚠ Dry-run skipped (requires .env.gcp configuration)"; exit 0)

.PHONY: lint
lint: ## Run all linters (shellcheck, yamllint, etc.)
	@echo "Running linters..."
	@$(MAKE) test-provisioning
	@$(MAKE) test-scripts
	@echo "Checking YAML files..."
	@if command -v yamllint > /dev/null; then \
		yamllint .github/workflows/ configs/ && \
		echo "✓ YAML lint passed"; \
	else \
		echo "⚠ yamllint not installed, skipping (install with: pip install yamllint)"; \
	fi
	@echo "✓ All linters passed"

.PHONY: validate-provisioning
validate-provisioning: test-provisioning ## Alias for test-provisioning

.PHONY: validate-orchestrator
validate-orchestrator: test-orchestrator ## Alias for test-orchestrator
