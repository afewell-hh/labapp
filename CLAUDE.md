# Hedgehog Lab Appliance - Development Guide for AI Agents

This document provides essential context and workflow instructions for AI agents working on this project.

## Project Context

**What:** Virtual appliance for learning Hedgehog Fabric networking
**Goal:** Ship v0.1.0 MVP by December 31, 2025 (8-week sprint)
**Style:** CNCF-compliant agile development with strict PR-based workflow
**Team Lead:** Reviews all PRs, enforces quality standards, manages sprints

## Required Development Workflow

### Step 1: Set Up Your Branch
```bash
# Always start from updated main
git checkout main
git pull origin main

# Create feature branch using issue number
git checkout -b feature/[issue-number]-[brief-description]
# Example: feature/7-orchestrator-architecture
```

### Step 2: Make Your Changes
- Implement the requirements specified in the issue
- Follow acceptance criteria exactly
- Write idempotent code with error handling
- Add comprehensive documentation

### Step 3: Commit Using Conventional Commits
```bash
git add [files]
git commit -m "type(scope): description

Detailed explanation of changes.

Closes #[issue-number]"
```

**Commit Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `test`: Adding tests
- `refactor`: Code restructuring
- `ci`: CI/CD changes

**Example:**
```bash
git commit -m "feat(orchestrator): design orchestrator architecture

Create ADR-002 defining orchestrator system architecture including:
- Component architecture
- State machine definition
- File/directory structure

Closes #7"
```

### Step 4: Push Feature Branch
```bash
# Push to YOUR feature branch (not main!)
git push origin feature/[issue-number]-[description]
```

### Step 5: Create Pull Request
```bash
# Use gh CLI to create PR
gh pr create \
  --title "type(scope): Brief description" \
  --body "Closes #[issue-number]

## Summary
[What you built]

## Acceptance Criteria Met
- [x] Criterion 1
- [x] Criterion 2

## Testing
[How you verified it works]"
```

### Step 6: Wait for Review
- **DO NOT MERGE** your own PR
- Team Lead will review
- Code review service will analyze
- CI/CD must pass
- Address any feedback
- Team Lead approves and merges

## Critical Rules

✅ **ALWAYS create feature branches** for your work
✅ **ALWAYS submit PRs** for review before merging
✅ **ALWAYS link issues** with "Closes #X" in commits/PRs
✅ **ALWAYS wait for approval** before work is merged
✅ **ALWAYS follow conventional commit** format

❌ **NEVER push directly to main branch**
❌ **NEVER merge your own PRs**
❌ **NEVER skip code review**
❌ **NEVER commit without linking an issue**

## Quality Standards

### Code Quality
- Idempotent scripts (can run multiple times safely)
- Comprehensive error handling
- Input validation
- Logging for debugging
- Comments for complex logic

### Documentation
- Update relevant docs with your changes
- Add inline comments for clarity
- Create/update ADRs for architectural decisions
- Write clear commit messages

### Testing
- Verify acceptance criteria are met
- Test error conditions
- Document test procedures in PR

## Repository Structure

```
labapp/
├── .github/
│   ├── ISSUE_TEMPLATE/     # Issue templates
│   └── workflows/          # CI/CD workflows
├── docs/
│   ├── adr/                # Architecture Decision Records
│   ├── build/              # Build documentation
│   └── issues/             # Sprint plans
├── packer/                 # Packer build templates
│   ├── scripts/            # Provisioning scripts
│   └── *.pkr.hcl          # Packer configurations
├── CLAUDE.md               # This file - READ FIRST!
├── CONTRIBUTING.md         # Detailed contribution guide
├── ROADMAP.md              # Product roadmap
└── README.md               # Project overview
```

## Architecture Decisions (ADRs)

When making architectural decisions, create an ADR:
1. Copy format from `docs/adr/001-dual-build-pipeline.md`
2. Document: Status, Context, Decision, Consequences
3. Number sequentially (ADR-001, ADR-002, etc.)
4. Update `docs/adr/README.md` index

## Sprint Planning

**Current Sprint:** Sprint 1 (Week 1-2)
**Milestone:** v0.1.0 - MVP

Check `docs/issues/MVP_SPRINT_PLAN.md` for:
- Sprint goals
- Issue breakdown
- Story point estimates
- Dependencies between issues

## Common Issue Types

### Epic Issues
- Track large initiatives spanning multiple issues
- Remain open until all sub-issues complete
- Provide high-level context

### Task Issues  
- Specific, actionable work items
- Include acceptance criteria
- Estimate in story points
- Link to parent Epic

### Labels Guide
- `kind/*`: Type of work (bug, feature, task, epic, docs)
- `area/*`: Code area (build, orchestrator, cli, ui, test, ci)
- `priority/*`: Urgency (critical, high, medium, low)
- `good-first-issue`: Good for newcomers
- `blocked`: Cannot proceed

## Working with the Team Lead

The Team Lead (AI) will:
- ✅ Review all PRs for quality and standards
- ✅ Verify acceptance criteria are met
- ✅ Ensure documentation is complete
- ✅ Check CI/CD passes
- ✅ Approve and merge after review
- ✅ Track sprint progress
- ✅ Unblock issues

When Team Lead requests changes:
1. Address all feedback in your feature branch
2. Push updates to same branch
3. Comment on PR when ready for re-review
4. Do not create new PRs

## CI/CD Pipeline

**Automated Checks:**
- Shellcheck (bash script linting)
- yamllint (YAML validation)
- Packer validate (template validation)
- Unit tests (when implemented)

**Must Pass Before Merge:**
All CI checks must be green before Team Lead can approve.

## Issue Assignment Workflow

1. **Issue Assigned** - Customer assigns you an issue
2. **Read Issue** - Review acceptance criteria carefully
3. **Check Dependencies** - Ensure prerequisite issues are closed
4. **Create Branch** - Follow naming: `feature/[issue-number]-[description]`
5. **Implement** - Build what's specified in acceptance criteria
6. **Test** - Verify everything works
7. **Document** - Update relevant docs
8. **Commit** - Use conventional commit format with "Closes #X"
9. **Push Branch** - Push feature branch (not main!)
10. **Create PR** - Link issue, describe changes
11. **Wait for Review** - Team Lead and CI will review
12. **Address Feedback** - Make requested changes
13. **Get Approval** - Team Lead approves
14. **Automatic Merge** - Issue closes automatically

## Example Complete Workflow

```bash
# Assignment: Issue #8 - Implement orchestrator main script

# 1. Start fresh
git checkout main
git pull origin main

# 2. Create feature branch
git checkout -b feature/8-orchestrator-main-script

# 3. Build the feature
cat > /usr/local/bin/hedgehog-lab-orchestrator << 'SCRIPT'
#!/bin/bash
# Orchestrator implementation...
SCRIPT

# 4. Test it works
chmod +x /usr/local/bin/hedgehog-lab-orchestrator
/usr/local/bin/hedgehog-lab-orchestrator --help

# 5. Update documentation
echo "## Orchestrator Usage" >> docs/build/BUILD_GUIDE.md

# 6. Commit with proper format
git add /usr/local/bin/hedgehog-lab-orchestrator docs/build/BUILD_GUIDE.md
git commit -m "feat(orchestrator): implement main orchestrator script

Implements core orchestrator with:
- State machine management
- Module execution framework
- Progress tracking
- Error handling with retry logic

All acceptance criteria met.

Closes #8"

# 7. Push feature branch
git push origin feature/8-orchestrator-main-script

# 8. Create PR
gh pr create \
  --title "feat(orchestrator): Implement main orchestrator script" \
  --body "Closes #8

## Summary
Implements the main orchestrator script that manages lab initialization.

## Acceptance Criteria Met
- [x] /usr/local/bin/hedgehog-lab-orchestrator created
- [x] Build type detection works
- [x] Initialization lockfile prevents concurrent runs
- [x] Logging to /var/log/hedgehog-lab-init.log
- [x] Initialized stamp file created on success
- [x] Error handling and rollback

## Testing
Tested on Ubuntu 22.04:
- Standard build initialization
- Lock file prevents concurrent runs
- Proper logging and state tracking"

# 9. Wait for review - DO NOT MERGE
```

## Getting Help

**For Technical Questions:**
- Check existing ADRs in `docs/adr/`
- Review similar implementations in codebase
- Ask Team Lead via PR comments

**For Process Questions:**
- Read `CONTRIBUTING.md`
- Check `docs/issues/MVP_SPRINT_PLAN.md`
- Reference this CLAUDE.md

## Project Goals & Timeline

**Milestone v0.1.0 (MVP)** - Dec 31, 2025
- Standard build pipeline working
- Basic orchestration system
- Lab management CLI
- Complete documentation

**Success Metrics:**
- All acceptance criteria met
- Code review approved
- CI/CD passing
- Documentation complete
- No rework needed

## Remember

This is a **team project** with **quality standards**. Every contribution:
- Goes through code review
- Must pass CI/CD  
- Must meet acceptance criteria
- Must follow conventions
- Must be documented

**Quality over speed.** Take time to do it right the first time.

## Quick Reference

```bash
# Standard workflow for ANY issue:
git checkout main && git pull origin main
git checkout -b feature/[issue-#]-[name]
# ... make changes ...
git add [files]
git commit -m "type(scope): description\n\nCloses #[issue-#]"
git push origin feature/[issue-#]-[name]
gh pr create --title "..." --body "Closes #[issue-#]"
# WAIT for review - DO NOT MERGE
```

---

**Last Updated:** November 4, 2025
**Version:** 1.0
**Team Lead:** AI Team Lead (reviews all PRs)
**Project Phase:** Sprint 1 - MVP Development
