# ADR-001: Dual Build Pipeline Strategy

**Status:** Accepted
**Date:** 2025-10-23
**Deciders:** Project Lead, Engineering Team
**Technical Story:** Initial architecture design

## Context

The lab appliance needs to serve two distinct use cases:

1. **Online Self-Paced Learning:** Students download and run the appliance on their own machines
2. **In-Person Workshops:** Instructors need appliances ready immediately for time-constrained events

The Hedgehog VLAB requires 15-20 minutes of initialization on first boot, which is acceptable for self-paced learning but problematic for workshops where students expect immediate access.

Appliance size is a significant factor:
- Standard (uninitialized): ~15-20GB compressed
- Pre-warmed (initialized): ~80-100GB compressed

## Decision

Implement **two separate build pipelines** producing different appliance variants:

### Pipeline 1: Standard Build (Default)
- Installs all software but does NOT initialize VLAB
- Smaller download size (~15-20GB)
- First boot performs full initialization (15-20 min)
- Automated builds on every release
- Distributed via public download

### Pipeline 2: Pre-Warmed Build (On-Demand)
- Fully initializes VLAB during build process
- Larger image size (~80-100GB)
- First boot only starts services (2-3 min)
- Built manually or on-demand for specific events
- Distributed via USB/local network/cloud storage for workshops

### Shared Components
- Both use same orchestrator code
- Build type detection via `/etc/hedgehog-lab/build-type`
- Orchestrator adapts behavior based on build type
- Identical user experience after initialization complete

## Consequences

### Positive
- **Optimized for each use case:** Small downloads for students, fast boot for workshops
- **Cost efficiency:** Don't pay for large storage/bandwidth when not needed
- **Flexibility:** Can produce pre-warmed builds on-demand for specific events
- **Better UX:** Students get appropriate download size, workshop attendees get immediate access

### Negative
- **Build complexity:** Need to maintain two Packer configurations
- **Testing overhead:** Must test both build types
- **Documentation:** Need to clearly explain which build to use when
- **CI/CD resources:** Pre-warmed builds require powerful runners with nested virtualization

### Neutral
- **Storage costs:** Pre-warmed builds stored only when needed
- **Maintenance:** Same orchestrator code means fixes apply to both

## Alternatives Considered

### Alternative 1: Single Standard Build Only
**Rejected:** Workshop attendees would face 15-20 min wait time, poor experience

### Alternative 2: Single Pre-Warmed Build Only
**Rejected:** Forces all students to download 80-100GB, prohibitive for many

### Alternative 3: Cloud-Based Lab Environment
**Rejected for MVP:** Adds infrastructure complexity, ongoing costs, requires internet connectivity. May reconsider for v2.0+

### Alternative 4: Incremental Initialization with Aggressive Caching
**Rejected:** Complex to implement, marginal improvements, doesn't solve workshop use case

## Implementation Notes

- Use Packer for both pipelines to maintain consistency
- Standard build: Automated via GitHub Actions on every release
- Pre-warmed build: Manual workflow trigger with reason field
- Build type stored in appliance at `/etc/hedgehog-lab/build-type`
- Orchestrator checks build type and adjusts initialization accordingly

## Related Decisions

- ADR-002: Orchestrator Design *(forthcoming)*
- ADR-003: Scenario Management System *(forthcoming)*

## References

- Issue #1: MVP Requirements
- Discussion: Build strategy options
- Packer documentation: https://packer.io
