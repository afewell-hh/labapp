# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records for significant technical decisions.

## Index

- [ADR-001: Dual Build Pipeline Strategy](001-dual-build-pipeline.md)
- [ADR-002: Orchestrator Design](002-orchestrator-design.md)
- [ADR-003: Performance Optimizations](003-performance-optimizations.md)
- [ADR-004: AWS S3 Artifact Storage](004-aws-s3-artifact-storage.md)
- [ADR-005: Scenario Management System](005-scenario-system.md) *(planned)*

## Format

Each ADR follows this structure:

```markdown
# ADR-XXX: Title

**Status:** [Proposed | Accepted | Deprecated | Superseded]
**Date:** YYYY-MM-DD
**Deciders:** Names
**Technical Story:** Issue link

## Context
What is the issue we're seeing that is motivating this decision?

## Decision
What is the change that we're actually proposing/doing?

## Consequences
What becomes easier or more difficult to do because of this change?

## Alternatives Considered
What other options were considered?
```

## Creating a New ADR

1. Copy `template.md` to `NNN-title.md`
2. Fill in the sections
3. Submit as PR for review
4. Update index above after merge
