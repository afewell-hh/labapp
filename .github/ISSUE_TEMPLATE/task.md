---
name: Development task
about: Scoped implementation or documentation task for one worker
title: '[TASK] '
labels: 'kind/task'
assignees: ''
---

<!--
Process rules (roles, onboarding, testing, handoff) live in
docs/contributing/agent-workflow.md. Link to it; do not copy it here.
Do not write an agent mention in this body. The lead dispatches the worker in a
separate comment after the issue exists (a mention in a newly opened issue
starts a job immediately).
-->

## Goal
<!-- One or two sentences: the outcome and why. Parent: #N -->

## Scope
In scope:

- (fill in)

Out of scope (cloud/production access, other components, refactors):

- (fill in)

## Deliverables
<!-- Concrete files/PR outputs. Name the docs to update, or say none needed. -->

- (fill in)

## Acceptance criteria
<!-- Each must be checkable by an independent reviewer. -->

- [ ] (criterion)
- [ ] (criterion)

## Verification plan and limits
<!-- Cheapest representative layer per criterion, exact commands, and what each cannot prove. -->

| Check | Command / method | Cannot prove |
|---|---|---|
| | | |

A failed, denied or unrun check is reported as such, not as passing.

## Sources and compatibility
<!-- Official docs / issues / code to read first, with the version scope that
applies. Name consequential files/sections/comment IDs and why each matters.
Product, safety and authorization context stays required; a checkpoint may
replace long parent history but not a named dependency. -->

- (fill in)

## Dependencies

- Parent / epic: #N
- Depends on: #N
- Blocks: #N

## Iteration bound and handoff
Max two focused revision rounds after review, then escalate to the lead with
the exact blocker. Handoff in the PR: exact head SHA, criteria met/unmet, files,
sections and comment IDs read, sources skipped/partial/summarized/truncated and
resulting coverage limits, checks run and denied, docs updated, uncertainties.
Sanitized evidence only; raw private outputs stay private. Do not merge or close.
