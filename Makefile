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

test: validate ## Run tests (validate templates)
	@echo "Running tests..."
	@echo "Template validation: PASSED"

.PHONY: check-version
check-version: ## Show current version
	@echo "Version: $(VERSION)"

.PHONY: set-executable
set-executable: ## Make scripts executable
	@echo "Setting execute permissions on scripts..."
	chmod +x packer/scripts/*.sh
	chmod +x packer/scripts/hedgehog-lab-orchestrator
	@echo "Permissions set!"
