# TASK-NNN — <short title>

<!-- Template hierarchy: SPEC-NNN → plans/PLAN-NNN.md → tasks/TASK-NNN.md -->
<!-- Copy to tasks/TASK-NNN.md for each new task. -->
<!-- Replace NNN with the actual monotonically increasing task ID. -->
<!-- A task may belong to a PLAN or be a standalone one-off (no plan needed). -->
<!-- This file contains EXACTLY the information a worker needs — nothing more. -->
<!-- Do not paste entire source files. Reference files and symbols by path/name. -->

## Parent

<!-- Link to the plan this task belongs to, or "standalone" if it's a one-off. -->

- Plan: `plans/PLAN-NNN.md` (or **standalone** — no plan, this is a one-off task)
- SPEC: `specs/SPEC-NNN.md` (if applicable)

## Supersedes

<!-- If this task replaces an earlier one, list it here with a reason. -->
<!-- Delete this section if this is a new task, not a replacement. -->
<!-- When a newer task supersedes THIS one, add "Superseded by: TASK-NNN" below. -->

- Supersedes: <!-- TASK-NNN, or "none" -->
- Reason: <!-- why the old task is no longer valid — scope changed, approach abandoned, etc. -->
- Superseded by: <!-- filled in when a newer task replaces this one, or "none" -->

## Status

<!-- Lifecycle: todo → in_progress → review → done -->
<!-- Blocked: in_progress → blocked. Failed review: review → in_progress -->

- **Status**: todo
- **Owner**: unassigned
- **Model class**: <!-- implementer | fast-worker | debugger -->
- **Dependencies**: <!-- TASK-NNN, or "none" -->

## Goal

<!-- One sentence — what success looks like. -->

## Repositories

<!-- Only repositories the worker will touch or read. Not every repository. -->

- `<repo-path>`

## Relevant Files

### To create
<!-- New files the worker must create. -->

- `<path>` — <one-line purpose>

### To modify
<!-- Existing files the worker must change. -->

- `<path>` — <what changes>

## Relevant Symbols

### Existing (read-only reference)
<!-- Functions/classes/types the worker must understand but not modify. -->

- `<file>` → `<symbol>` (<type>)

### To create
<!-- New functions/classes/types the worker must implement. Include signatures. -->

- `<module>.<function>(<args>) -> <return>`
- `<module>.<Class>`:
  - `<field>: <type>`

## Existing Behavior

<!-- How the relevant existing code works today. -->
<!-- Only the parts the worker needs to know to make correct changes. -->

- 

## Required Change

<!-- Numbered, concrete steps. Each unambiguous and independently verifiable. -->

1. **`<file>`**: <what to do>
2. **`<file>`**: <what to do>

## Constraints

<!-- Hard constraints for this task only. Project-wide constraints live in AGENTS.md. -->

- 

## Acceptance Criteria

<!-- Observable, testable conditions. The checker validates these. -->

1. 
2. 

## Verification

<!-- Exact test command to run. -->

```
<test command>
```

## Do-Not-Touch

<!-- Files/modules the worker must not modify under any circumstance. -->

- 

## Commit Log

<!-- Every commit related to this task is logged here. -->
<!-- Workers append a row after each commit. Do not delete prior entries. -->
<!-- Include fix commits — mark them with "fix" in the Type column. -->

| Commit | Date | Type | Message |
|---|---|---|---|
| | | | |
