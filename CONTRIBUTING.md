# Contributing to Hedgehog Lab Appliance

Welcome! We're excited you're interested in contributing.

## Code of Conduct

This project follows the CNCF Code of Conduct. Be respectful and constructive.

## How to Contribute

### Reporting Issues

- Check existing issues first
- Use issue templates
- Provide clear reproduction steps
- Include system information

### Proposing Features

- Open a discussion first for major features
- Create an issue with `enhancement` label
- Link to relevant use cases

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Write/update tests
5. Update documentation
6. Commit with conventional commits: `feat: add scenario reset command`
7. Push and create a PR

### Commit Message Format

We use Conventional Commits:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:** feat, fix, docs, style, refactor, test, chore

**Example:**
```
feat(orchestrator): add checkpoint restore functionality

Implements checkpoint restore capability allowing users to
restore lab state from saved checkpoints.

Closes #42
```

## Development Workflow

### Local Development

```bash
# Clone the repo
git clone https://github.com/example/labapp.git
cd labapp

# Install dependencies
make dev-setup

# Run tests
make test

# Build locally
make build-standard
```

### Validation Requirements

All code must pass validation checks before submitting a PR. These checks run automatically in CI/CD:

#### Shell Script Validation

**Bash Syntax Check** (catches syntax errors):
```bash
# Validate a single script
bash -n path/to/script.sh

# Validate all scripts
find . -name "*.sh" -type f -exec bash -n {} \;
```

**Shellcheck** (static analysis):
```bash
# Install shellcheck
sudo apt-get install shellcheck  # Ubuntu/Debian
brew install shellcheck          # macOS

# Check a single script
shellcheck -x path/to/script.sh

# Check all scripts
find . -name "*.sh" -type f -exec shellcheck -x {} \;
```

#### Terraform Validation

**Format Check**:
```bash
# Check formatting (fails if not formatted)
terraform fmt -check -recursive terraform/

# Auto-fix formatting
terraform fmt -recursive terraform/
```

**Configuration Validation**:
```bash
cd terraform/metal-build/  # or other terraform directory
terraform init -backend=false
terraform validate
```

#### Pre-commit Hooks (Optional but Recommended)

Install pre-commit hooks to automatically validate before each commit:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks for this repo
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

The pre-commit hooks will automatically:
- Check bash syntax with `bash -n`
- Run shellcheck on all shell scripts
- Format and validate Terraform files
- Lint YAML files
- Check for common issues (trailing whitespace, large files, etc.)

### Testing

- Unit tests: `make test-unit`
- Integration tests: `make test-integration`
- Build tests: `make test-build`
- **Validation**: Run validation checks before submitting PR

### Project Structure

```
labapp/
├── .github/          # GitHub workflows, issue templates
├── packer/           # Packer build configurations
├── scripts/          # Build and runtime scripts
├── orchestrator/     # Lab orchestration code
├── configs/          # Configuration files
├── docs/             # Technical documentation
└── tests/            # Test suites
```

## Issue Labels

- `kind/bug` - Something isn't working
- `kind/feature` - New functionality
- `kind/enhancement` - Improvement to existing feature
- `priority/critical` - Urgent, blocking
- `priority/high` - Important, not blocking
- `priority/medium` - Normal priority
- `priority/low` - Nice to have
- `area/build` - Build pipeline related
- `area/orchestrator` - Orchestration logic
- `area/ui` - User interface
- `area/docs` - Documentation
- `good-first-issue` - Good for newcomers
- `help-wanted` - Extra attention needed

## Infrastructure Change Policy

**Critical:** Infrastructure code (Terraform, Packer, deployment scripts) must be tested before merge.

### Testing Infrastructure Changes

Before submitting PRs that modify infrastructure:

1. **Terraform Changes**:
   - Run `terraform init -backend=false` in affected directories
   - Run `terraform validate` to check configuration
   - Run `terraform fmt -check` to verify formatting
   - Run `terraform plan` if safe (no state modification)

2. **Shell Scripts**:
   - Run `bash -n script.sh` to check syntax
   - Run `shellcheck -x script.sh` for static analysis
   - Test script execution in a safe environment if possible

3. **Packer Templates**:
   - Run `packer init template.pkr.hcl`
   - Run `packer validate template.pkr.hcl`
   - Run `packer fmt -check template.pkr.hcl`

**Why:** Infrastructure bugs that reach production can waste money and developer time. The cost of validation (seconds) is far less than the cost of a failed deployment (dollars and hours).

## Review Process

1. Automated checks must pass (CI/CD)
2. At least one maintainer approval required
3. Documentation updated as needed
4. Changelog updated for user-facing changes
5. **Infrastructure changes must include evidence of local testing**

## Release Process

Releases follow semantic versioning (semver):
- `v1.0.0` - Major release
- `v1.1.0` - Minor release (features)
- `v1.0.1` - Patch release (fixes)

For detailed release procedures, see [docs/RELEASE_PROCESS.md](docs/RELEASE_PROCESS.md).

## Getting Help

- GitHub Discussions for questions
- Slack channel for real-time chat
- Weekly office hours for live help

## Recognition

Contributors are recognized in:
- Release notes
- CONTRIBUTORS.md file
- Special thanks in documentation

Thank you for contributing! 🎉
