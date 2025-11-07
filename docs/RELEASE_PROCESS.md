# Release Process

This document defines the release process for Hedgehog Lab Appliance.

## Table of Contents

- [Version Numbering Strategy](#version-numbering-strategy)
- [Release Types](#release-types)
- [Release Checklist](#release-checklist)
- [Changelog Guidelines](#changelog-guidelines)
- [Distribution Channels](#distribution-channels)
- [Release Notes](#release-notes)

---

## Version Numbering Strategy

The project follows **Semantic Versioning (SemVer)** 2.0.0: `MAJOR.MINOR.PATCH`

### Version Format

```
vMAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
```

**Examples:**
- `v0.1.0` - MVP release
- `v0.2.0` - Pre-warmed build feature
- `v0.1.1` - Bug fix to MVP
- `v1.0.0-rc.1` - Release candidate
- `v1.0.0` - GA release

### Version Increment Rules

**MAJOR version (v1.0.0, v2.0.0, etc.):**
- Incompatible API changes
- Breaking changes to appliance format
- Major architectural changes requiring user migration
- Example: VM format change, incompatible data format

**MINOR version (v0.1.0, v0.2.0, etc.):**
- New features added in backward-compatible manner
- New build variants (pre-warmed, cloud, etc.)
- New CLI commands or significant functionality
- Example: Scenario management system, checkpoint system

**PATCH version (v0.1.1, v0.1.2, etc.):**
- Backward-compatible bug fixes
- Security patches
- Documentation updates
- Performance improvements with no API changes
- Example: Bug fixes, dependency updates

### Pre-release Versions

Used during development and testing before stable release:

**Alpha (`-alpha.N`):**
- Early development, feature incomplete
- Internal testing only
- Example: `v0.1.0-alpha.1`

**Beta (`-beta.N`):**
- Feature complete, but may have bugs
- Community testing welcomed
- Example: `v0.1.0-beta.1`

**Release Candidate (`-rc.N`):**
- Final testing before release
- No new features, bug fixes only
- Example: `v1.0.0-rc.1`

### Version Lifecycle

```
v0.1.0-alpha.1 → v0.1.0-beta.1 → v0.1.0-rc.1 → v0.1.0 → v0.1.1
```

---

## Release Types

### Regular Releases (Scheduled)

**Minor releases** follow the roadmap timeline:
- v0.1.0 (MVP) - Q4 2025
- v0.2.0 (Pre-warmed) - Q1 2026
- v0.3.0 (Scenarios) - Q1 2026
- v1.0.0 (GA) - Q2 2026

**Schedule:** Quarterly or milestone-based per roadmap

### Patch Releases (As-Needed)

**Patch releases** are created on-demand for:
- Critical bug fixes
- Security vulnerabilities
- Important performance issues
- Documentation corrections

**Timeline:** Released as soon as validated (1-3 days after fix)

### Emergency Releases

For critical security issues or show-stopper bugs:
- Fast-track review process
- Expedited testing
- Immediate distribution
- Post-release retrospective required

---

## Release Checklist

### Phase 1: Pre-Release Preparation (1-2 weeks before)

#### Code Freeze
- [ ] Create release branch: `release/vX.Y.Z`
- [ ] Announce code freeze to team
- [ ] Only bug fixes allowed on release branch
- [ ] Feature development continues on `main`

#### Version Bump
- [ ] Update version in all relevant files
- [ ] Update `CHANGELOG.md` with release date
- [ ] Update `ROADMAP.md` milestone status
- [ ] Update version in documentation examples

#### Testing
- [ ] All CI/CD checks passing
- [ ] Standard build validation complete
- [ ] Pre-warmed build validation (if applicable)
- [ ] End-to-end testing on VMware
- [ ] End-to-end testing on VirtualBox
- [ ] Manual smoke testing of key features
- [ ] Security scan completed
- [ ] Performance benchmarks recorded

#### Documentation
- [ ] User documentation updated
- [ ] API/CLI documentation current
- [ ] Installation guide verified
- [ ] Troubleshooting guide updated
- [ ] Release notes drafted
- [ ] Upgrade guide created (if needed)

### Phase 2: Build & Artifacts (Release Day)

#### Build Process
- [ ] Create Git tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
- [ ] Push tag: `git push origin vX.Y.Z`
- [ ] Trigger CI/CD build for standard build
- [ ] Monitor build process for errors
- [ ] Validate build artifacts integrity
- [ ] Generate checksums (SHA256) for all artifacts

#### Artifact Verification
- [ ] Download and test standard OVA
- [ ] Verify OVA boots successfully
- [ ] Verify all services initialize correctly
- [ ] Check service endpoints accessible
- [ ] Validate checksum files
- [ ] Test on clean VM environment

### Phase 3: Distribution

#### GitHub Release
- [ ] Create GitHub Release for tag `vX.Y.Z`
- [ ] Add release notes using template
- [ ] Upload artifacts:
  - [ ] `hedgehog-lab-standard-vX.Y.Z.ova`
  - [ ] `hedgehog-lab-standard-vX.Y.Z.ova.sha256`
  - [ ] `hedgehog-lab-prewarmed-vX.Y.Z.ova` (if applicable)
  - [ ] `hedgehog-lab-prewarmed-vX.Y.Z.ova.sha256` (if applicable)
- [ ] Mark as pre-release if applicable
- [ ] Publish release

#### Cloud Storage Upload (Pre-warmed Builds Only)

For pre-warmed builds, upload artifacts to AWS S3 cloud storage:

- [ ] Verify AWS credentials are set (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
- [ ] Upload pre-warmed OVA to S3 using upload script:
  ```bash
  ./scripts/upload-to-s3.sh \
    output-hedgehog-lab-prewarmed/hedgehog-lab-prewarmed-vX.Y.Z.ova \
    X.Y.Z
  ```
- [ ] Verify upload completed successfully (script performs automatic verification)
- [ ] Note download URLs from upload script output for documentation
- [ ] Test download URL accessibility in browser or with curl
- [ ] Verify checksum file is publicly accessible
- [ ] Update DOWNLOADS.md with new version URLs

**Note:** Standard builds remain on GitHub Releases. Only pre-warmed builds (80-100 GB) are uploaded to S3 due to size limitations.

See [Artifact Upload Guide](build/ARTIFACT_UPLOAD.md) for detailed upload procedures.

#### Distribution Channels
- [ ] Verify GitHub Release download links work
- [ ] Update "latest" symlinks (if using external hosting)
- [ ] Upload to mirror sites (if configured)
- [ ] Update [DOWNLOADS.md](DOWNLOADS.md) with new release links

### Phase 4: Announcement & Communication

#### Documentation Updates
- [ ] Update README.md with new version
- [ ] Update installation guide download links
- [ ] Deploy updated documentation site
- [ ] Update quick start guide if needed

#### Announcements
- [ ] Post release announcement in GitHub Discussions
- [ ] Update project README badges
- [ ] Notify Hedgehog Fabric community channels
- [ ] Social media announcement (if applicable)
- [ ] Email notification to subscribers (if applicable)

#### Post-Release
- [ ] Merge release branch back to `main`
- [ ] Close release milestone
- [ ] Close all issues fixed in release
- [ ] Update project board
- [ ] Create GitHub Project for next release
- [ ] Schedule retrospective meeting

### Phase 5: Monitoring (First Week)

#### Issue Tracking
- [ ] Monitor GitHub Issues for bug reports
- [ ] Monitor discussions for user feedback
- [ ] Track download metrics
- [ ] Review CI/CD metrics

#### Support
- [ ] Respond to user questions promptly
- [ ] Document common issues in FAQ
- [ ] Create patches for critical issues
- [ ] Plan for patch release if needed

---

## Changelog Guidelines

We follow [Keep a Changelog](https://keepachangelog.com/) format.

### Changelog Structure

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- New features in development

### Changed
- Changes to existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Security fixes

## [X.Y.Z] - YYYY-MM-DD

### Added
- Feature descriptions

### Fixed
- Bug fix descriptions
```

### Entry Guidelines

**DO:**
- Write for end users, not developers
- Use present tense: "Add feature" not "Added feature"
- Include issue/PR references: `(#123)`
- Group by category (Added, Changed, Fixed, etc.)
- Be specific and concise

**DON'T:**
- Include internal refactoring (unless user-visible)
- Use commit messages verbatim
- Include contributor names in entries
- List every minor change

### Example Entries

**Good:**
```markdown
### Added
- Scenario management system with CLI commands for switching between lab scenarios (#45)
- Pre-warmed build variant for faster workshop deployments (#23)

### Fixed
- VLAB initialization timeout on slow systems (#67)
- ArgoCD login credentials not displayed in welcome message (#71)
```

**Bad:**
```markdown
### Added
- Added a thing (commit abc123)
- New stuff by @contributor

### Fixed
- Fixed bug
- Various improvements
```

---

## Distribution Channels

### Primary Distribution

**GitHub Releases** (Primary)
- **URL:** `https://github.com/afewell-hh/labapp/releases`
- **Artifacts:** OVA files, checksums, source code
- **Audience:** All users
- **Bandwidth:** GitHub CDN (no cost up to limits)
- **Retention:** All releases permanently available

**Release Assets:**
```
hedgehog-lab-standard-vX.Y.Z.ova
hedgehog-lab-standard-vX.Y.Z.ova.sha256
hedgehog-lab-prewarmed-vX.Y.Z.ova (for workshop releases)
hedgehog-lab-prewarmed-vX.Y.Z.ova.sha256
Source code (zip)
Source code (tar.gz)
```

### Secondary Distribution (Future)

**Cloud Storage** (For large pre-warmed builds)
- **Options:** AWS S3, Google Cloud Storage, Azure Blob
- **Use Case:** Workshop distributions, large files
- **Access:** Direct download links, signed URLs for workshops
- **Cost:** Pay per download/bandwidth

**Docker Hub** (Future consideration)
- **Use Case:** Container-based lab alternative
- **Format:** Docker image instead of OVA
- **Target:** Kubernetes-in-Kubernetes deployment

**Mirror Sites** (Community-maintained)
- **Use Case:** Geographic distribution
- **Setup:** Community volunteers host mirrors
- **Management:** Automated sync scripts

### Download URLs

**Latest stable release:**
```
https://github.com/afewell-hh/labapp/releases/latest
```

**Specific version:**
```
https://github.com/afewell-hh/labapp/releases/download/vX.Y.Z/hedgehog-lab-standard-vX.Y.Z.ova
```

**Checksum verification:**
```bash
# Download
wget https://github.com/afewell-hh/labapp/releases/download/v0.1.0/hedgehog-lab-standard-v0.1.0.ova
wget https://github.com/afewell-hh/labapp/releases/download/v0.1.0/hedgehog-lab-standard-v0.1.0.ova.sha256

# Verify
sha256sum -c hedgehog-lab-standard-v0.1.0.ova.sha256
```

---

## Release Notes

Release notes are published with each GitHub Release. Use the template below.

### Release Notes Template

```markdown
# Hedgehog Lab Appliance vX.Y.Z

**Release Date:** YYYY-MM-DD
**Release Type:** [Major | Minor | Patch]

## Overview

[2-3 sentence summary of what this release is about]

## What's New

### 🎉 New Features

- **Feature Name**: Description of the feature and why it's useful (users should do X to try it) (#issue)
- **Another Feature**: Description (#issue)

### 🔧 Improvements

- Improvement description (#issue)
- Another improvement (#issue)

### 🐛 Bug Fixes

- Fix description explaining what was broken and how it's fixed (#issue)
- Another fix (#issue)

### 📚 Documentation

- Documentation improvement (#issue)

## Breaking Changes

⚠️ **[If any breaking changes, list them here with migration instructions]**

- Breaking change description and how to migrate

## Upgrade Instructions

### From vX.Y.Z

[Specific upgrade steps if needed, or:]

No special upgrade steps required. Download and import the new OVA.

## Downloads

### Standard Build (Recommended for Self-Paced Learning)

**Size:** ~15-20GB compressed | **First Boot:** ~15-20 minutes

- [hedgehog-lab-standard-vX.Y.Z.ova](URL)
- [Checksum (SHA256)](URL)

### Pre-Warmed Build (For Workshops)

**Size:** ~80-100GB compressed | **First Boot:** ~2-3 minutes

- [hedgehog-lab-prewarmed-vX.Y.Z.ova](URL)
- [Checksum (SHA256)](URL)

## Verification

```bash
# Verify download integrity
sha256sum -c hedgehog-lab-standard-vX.Y.Z.ova.sha256
```

## System Requirements

- **Hypervisor:** VMware Workstation/Fusion 16+, VirtualBox 7+
- **CPU:** 8 cores (4 cores minimum)
- **RAM:** 16GB (12GB minimum)
- **Disk:** 100GB free space
- **Network:** Internet connection for first-time initialization

## Documentation

- [Downloads](docs/DOWNLOADS.md)
- [Installation Guide](docs/INSTALL.md)
- [Quick Start Guide](docs/QUICKSTART.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [FAQ](docs/FAQ.md)

## What's Next

Check out the [Roadmap](ROADMAP.md) for upcoming features in vX.Y.Z!

## Contributors

Thank you to everyone who contributed to this release! 🙏

[If applicable, list contributors or use:]

Full changelog: [vA.B.C...vX.Y.Z](comparison-URL)

---

**Questions?** Open a [Discussion](discussions-URL)
**Found a bug?** Report an [Issue](issues-URL)
```

### Release Notes Best Practices

1. **User-Focused Language**
   - Write for end users, not developers
   - Explain "why" not just "what"
   - Include usage examples for new features

2. **Clear Sections**
   - Separate new features, improvements, and fixes
   - Highlight breaking changes prominently
   - Provide upgrade instructions

3. **Complete Information**
   - Include download links and checksums
   - System requirements
   - Documentation links
   - Known issues (if any)

4. **Visual Appeal**
   - Use emojis sparingly for section headers
   - Format code blocks properly
   - Include screenshots for UI changes (optional)

5. **Call to Action**
   - Link to documentation
   - Encourage feedback
   - Preview next release

---

## Roles & Responsibilities

### Release Manager (Rotating Role)

Responsibilities:
- Drives release process end-to-end
- Updates release checklist
- Coordinates with team
- Creates GitHub Release
- Writes release notes
- Announces release

Rotation: Changes per release or quarterly

### Team Responsibilities

**Engineering:**
- Code freeze compliance
- Bug fix PRs during release window
- Build validation testing

**Documentation:**
- Update user-facing docs
- Review release notes
- Update installation guides

**QA/Testing:**
- Execute test plans
- Report blocking issues
- Validate artifacts

---

## Troubleshooting Releases

### Build Failures

**Symptom:** CI/CD build fails during release
**Actions:**
1. Review build logs in GitHub Actions
2. Fix issues on release branch
3. Re-tag if necessary: `git tag -f vX.Y.Z`
4. Force push tag: `git push -f origin vX.Y.Z`

### Artifact Issues

**Symptom:** OVA doesn't boot or services fail
**Actions:**
1. Delete bad release immediately
2. Fix issue on release branch
3. Create new patch version (vX.Y.Z+1)
4. Communicate issue to users who downloaded

### Documentation Out of Sync

**Symptom:** Docs don't match release
**Actions:**
1. Quick fix via PR to main
2. Add note to release notes
3. Plan better doc freeze for next release

---

## Release Calendar

### Planned Releases (Based on Roadmap)

| Version | Target Date | Milestone |
|---------|-------------|-----------|
| v0.1.0 | Q4 2025 | MVP |
| v0.2.0 | Q1 2026 | Pre-warmed Build |
| v0.3.0 | Q1 2026 | Scenario Management |
| v0.4.0 | Q2 2026 | Checkpoint System |
| v1.0.0 | Q2 2026 | GA Release |

### Release Blackout Periods

Avoid releases during:
- Major holidays (Dec 23-Jan 2)
- Conference weeks (if presenting)
- Team vacation periods

---

## Post-Release Review

Within 1 week after release, conduct retrospective:

**Review Topics:**
- What went well?
- What could be improved?
- Were timelines realistic?
- Were there any surprises?
- Action items for next release

**Document outcomes** in `docs/releases/vX.Y.Z-retrospective.md`

---

## References

- [Semantic Versioning](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)
- [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github)
- [ROADMAP.md](../ROADMAP.md)
- [CONTRIBUTING.md](../CONTRIBUTING.md)

---

**Last Updated:** 2025-11-05
**Version:** 1.0
**Owner:** Engineering Team
