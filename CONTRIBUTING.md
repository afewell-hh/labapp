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

### Testing

- Unit tests: `make test-unit`
- Integration tests: `make test-integration`
- Build tests: `make test-build`

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

## Review Process

1. Automated checks must pass (CI/CD)
2. At least one maintainer approval required
3. Documentation updated as needed
4. Changelog updated for user-facing changes

## Release Process

Releases follow semantic versioning (semver):
- `v1.0.0` - Major release
- `v1.1.0` - Minor release (features)
- `v1.0.1` - Patch release (fixes)

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
