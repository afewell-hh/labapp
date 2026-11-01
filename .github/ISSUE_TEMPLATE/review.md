---
name: Review task
about: Independent review of a PR or research report against its task criteria
title: '[REVIEW] '
labels: 'kind/review'
assignees: ''
---

<!--
Process rules live in docs/contributing/agent-workflow.md (Roles). Do not write
a reviewer or agent mention in this body. The lead dispatches the review
separately.
-->

## Target
<!-- PR / report link and exact head commit SHA or comment URL. Task issue: #N -->

(fill in)

## Criteria to assess
<!-- Copy or link the task's acceptance criteria; the review must give a result for each. -->

- [ ] (criterion)

## Significant-defect focus
<!-- Correctness, security, scope creep, unintended file changes, doc accuracy. -->

- (fill in)

## Evidence to check
<!-- Claimed commands/results, cited sources, and whether denied/unrun checks were reported honestly. -->
<!-- Provenance/coverage: exact head reviewed, whether the handoff lists read
files/sections/comment IDs and skipped, partial, summarized or truncated
sources, and whether conclusions that depend on gaps are marked provisional. -->

- (fill in)

## Output
Per-criterion result (met / not met / could not assess, with reason), then
findings ranked by severity with file and line. A default bug review alone does
not show every criterion was assessed. State what you could not verify.
Do not approve or merge.

## Dependencies

- Depends on: #N
