# GitHub Repository Setup Guide

This document explains how to set up the GitHub repository with proper project management.

## Initial Repository Setup

### 1. Create GitHub Repository

```bash
# On GitHub.com
# Create new repository: hedgehog-lab-appliance
# Description: Virtual appliance for Hedgehog Fabric learning and labs
# Public/Private: Choose based on your needs
# Initialize: Don't initialize (we already have content)
```

### 2. Push Local Repository

```bash
cd /home/ubuntu/afewell-hh/labapp

# Add remote
git remote add origin https://github.com/YOUR_ORG/hedgehog-lab-appliance.git

# Push main branch
git branch -M main
git push -u origin main
```

### 3. Enable GitHub Features

On GitHub Settings page:

**Features to Enable:**
- ✅ Issues
- ✅ Projects
- ✅ Discussions
- ✅ Wiki (optional)
- ✅ Sponsorships (optional)

**Branch Protection:**
- Go to Settings → Branches
- Add rule for `main`:
  - ✅ Require pull request reviews (1 approval)
  - ✅ Require status checks to pass (CI)
  - ✅ Require branches to be up to date
  - ✅ Include administrators

### 4. Create GitHub Project Board

**Option A: GitHub Projects (Beta) - Recommended**

1. Go to Projects tab → New Project
2. Choose "Team Planning" template
3. Name: "Hedgehog Lab Appliance - Development"
4. Create the following views:
   - **Backlog:** All issues not in a sprint
   - **Sprint Board:** Current sprint issues (Kanban)
   - **Roadmap:** Timeline view of milestones

**Option B: Classic Projects**

1. Go to Projects (classic) → New Project
2. Choose "Automated kanban with reviews"
3. Name: "MVP Development"
4. Columns: Backlog, To Do, In Progress, Review, Done

### 5. Create Milestones

Go to Issues → Milestones → New Milestone

**Milestone 1: v0.1.0 - MVP**
- Due date: (Set 8 weeks from today)
- Description: Working standard build with basic functionality

**Milestone 2: v0.2.0 - Pre-warmed Build**
- Due date: (Q1 2026)
- Description: Add pre-warmed build for workshops

**Milestone 3: v0.3.0 - Scenarios**
- Due date: (Q1 2026)
- Description: Multi-scenario support

**Milestone 4: v0.4.0 - Checkpoints**
- Due date: (Q2 2026)
- Description: Checkpoint save/restore system

**Milestone 5: v1.0.0 - GA**
- Due date: (Q2 2026)
- Description: Production-ready release

### 6. Create Labels

Go to Issues → Labels → New Label

**Copy these labels:**

```
# Type labels
kind/bug (color: #d73a4a)
kind/feature (color: #a2eeef)
kind/enhancement (color: #84b6eb)
kind/epic (color: #3e4b9e)
kind/task (color: #d4c5f9)
kind/docs (color: #0075ca)

# Area labels
area/build (color: #fbca04)
area/orchestrator (color: #fbca04)
area/cli (color: #fbca04)
area/ui (color: #fbca04)
area/test (color: #fbca04)
area/ci (color: #fbca04)

# Priority labels
priority/critical (color: #b60205)
priority/high (color: #d93f0b)
priority/medium (color: #fbca04)
priority/low (color: #0e8a16)

# Special labels
good-first-issue (color: #7057ff)
help-wanted (color: #008672)
blocked (color: #e99695)
wontfix (color: #ffffff)
duplicate (color: #cfd3d7)
```

### 7. Create Initial Issues

Create issues from `docs/issues/MVP_SPRINT_PLAN.md`:

**Epic Issues (create first):**
- Epic 1: Build Pipeline Infrastructure
- Epic 2: Orchestrator & Initialization System
- Epic 3: Lab Management CLI
- Epic 4: Testing & Documentation
- Epic 5: MVP Polish & Release

**Task Issues (link to epics):**
- Issue #1 through #18 as defined in MVP_SPRINT_PLAN.md

**Tip:** Use GitHub CLI for bulk creation:

```bash
# Install gh CLI
# https://cli.github.com/

# Create epic issue
gh issue create \
  --title "[EPIC] Build Pipeline Infrastructure" \
  --label "kind/epic,area/build" \
  --milestone "v0.1.0" \
  --body-file docs/issues/epic-1-template.md

# Create task issue
gh issue create \
  --title "Set up Packer build environment" \
  --label "kind/task,area/build,priority/critical,good-first-issue" \
  --milestone "v0.1.0" \
  --body-file docs/issues/issue-1-template.md
```

### 8. Set Up Discussions

Go to Discussions → New Discussion

**Create Categories:**
- 📢 Announcements (team to community)
- 💡 Ideas (feature proposals)
- 🙏 Q&A (questions and answers)
- 🗣️ General (general discussion)
- 📚 Show and tell (demos, examples)

**Create Welcome Discussion:**
- Title: "Welcome to Hedgehog Lab Appliance!"
- Pin it
- Introduce the project
- Link to contributing guide

### 9. Configure Notifications

**For Team Members:**
- Watch the repository
- Enable notifications for:
  - Issues assigned to you
  - PRs requesting your review
  - Discussions you're participating in

**For Community:**
- Encourage watching "Releases only" for casual users

### 10. Set Up Integrations (Optional)

**Slack/Discord:**
- GitHub app for notifications
- Channel for CI/CD status
- Channel for PR reviews

**Project Management:**
- Jira (if enterprise)
- Linear (modern alternative)
- Or stick with GitHub Projects

## Project Board Automation

### GitHub Actions for Project Management

Create `.github/workflows/project-automation.yml`:

```yaml
name: Project Automation

on:
  issues:
    types: [opened, reopened, closed]
  pull_request:
    types: [opened, reopened, closed, merged]

jobs:
  add-to-project:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/add-to-project@v0.5.0
        with:
          project-url: https://github.com/orgs/YOUR_ORG/projects/1
          github-token: ${{ secrets.ADD_TO_PROJECT_PAT }}
```

## Sprint Management Process

### Starting a Sprint

1. Go to Milestones → Select sprint milestone
2. Review issues assigned to this sprint
3. Move issues to "Sprint Board" project
4. Ensure all issues have:
   - Assignees
   - Labels
   - Estimates
5. Post sprint kickoff message in Discussions

### Daily Updates (Async)

Team members comment on their assigned issues:
- What did I complete?
- What am I working on?
- Any blockers?

### Sprint Review

At end of sprint:
1. Demo completed features
2. Mark completed issues
3. Move incomplete issues to next sprint
4. Update roadmap

### Sprint Retrospective

Team discusses:
- What went well?
- What could improve?
- Action items for next sprint

Document in Discussions under "General" category

## Metrics to Track

**Velocity:**
- Story points completed per sprint
- Track in GitHub Projects

**Burn Down:**
- Issues remaining vs. time
- Use GitHub Insights

**Cycle Time:**
- Time from issue open to close
- Use GitHub Insights

**PR Review Time:**
- Time from PR open to merge
- Monitor in PR analytics

## Tips for Success

### Issue Hygiene
- Keep issues small and focused
- Clear acceptance criteria
- Link related issues
- Update status regularly
- Close when truly done

### PR Best Practices
- Link to issue in description
- Keep PRs small (<500 lines)
- Request specific reviewers
- Respond to feedback promptly
- Squash commits before merge

### Communication
- Be responsive (24-48 hour target)
- Use discussions for broad topics
- Use issues for specific work
- Tag people with @mentions
- Be respectful and constructive

### Documentation
- Keep README up to date
- Update docs with code changes
- Link to docs from issues
- Write ADRs for big decisions

## Resources

- [GitHub Docs: Projects](https://docs.github.com/en/issues/planning-and-tracking-with-projects)
- [GitHub Docs: Issues](https://docs.github.com/en/issues)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [CNCF Project Guidelines](https://contribute.cncf.io/)

---

**Next Steps:**

1. Create GitHub repository
2. Push this code
3. Set up milestones and labels
4. Create epic and task issues
5. Start Sprint 1!

Good luck! 🚀
