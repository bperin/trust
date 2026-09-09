# PLAN-NNN: <short title>

<!-- Template hierarchy: SPEC-NNN → plans/PLAN-NNN.md → tasks/TASK-NNN.md -->
<!-- Copy to plans/PLAN-NNN.md. Replace NNN with the real ID. -->
<!-- The PLAN describes HOW the system is built — architecture, not what/why. -->
<!-- The SPEC (in specs/SPEC-NNN.md) describes what/why. Do not duplicate it here. -->

## Supersedes

<!-- If this plan replaces an earlier one, list it here with a reason. -->
<!-- Delete this section if this is the first plan for this SPEC. -->
<!-- When a newer plan supersedes THIS one, add "Superseded by: PLAN-NNN" below. -->

- Supersedes: <!-- PLAN-NNN, or "none" -->
- Reason: <!-- why the old plan is no longer accurate — architecture changed, features removed, etc. -->
- Superseded by: <!-- filled in when a newer plan replaces this one, or "none" -->

## Source Specification

<!-- Which SPEC this plan implements. -->

SPEC-NNN — <short title> (`specs/SPEC-NNN.md`)

## Objective

<!-- One-paragraph summary of what this plan achieves. -->

## System Map

<!-- ASCII diagram of the major components and their relationships. -->
<!-- Show every process boundary, transport, and data flow. -->

```
┌─────────────────────────────────────┐
│  <Component A>                      │
│  - <responsibility>                 │
└──────────┬──────────────────────────┘
           │  <transport>
     ┌─────▼──────────────────────────┐
     │  <Component B>                  │
     │  - <responsibility>             │
     └────────────────────────────────┘
```

## Repositories

<!-- List every repository involved and its role. -->
<!-- Not every repository in the project is necessarily relevant. -->

| Path | Role | Description |
|---|---|---|
| `<repo>/` | | |

## Architecture

### New package: `<name>/`

```
<package>/
├── __init__.py
├── <module>.py          # <one-line responsibility>
└── ...
```

### Key design decisions

<!-- Numbered list of architectural decisions. -->
<!-- Record durable decisions in DECISIONS.md as ADR-NNN. -->

1. **<decision>** — <rationale>
2. **<decision>** — <rationale>

## Communication Topology

<!-- Every inter-component communication path and its transport. -->
<!-- Do not assume HTTP. Consider WebSocket, gRPC, SSE, queues, Pub/Sub, etc. -->

| Path | Transport | Purpose |
|---|---|---|
| <A → B> | | |

## Data / Ownership

<!-- Who owns each piece of data. Where it's stored. Ephemeral vs durable. -->

- **<data category>**: <owner / location>

## Workstreams

<!-- Group tasks into workstreams by concern. -->
<!-- Task IDs are monotonically increasing across all files in tasks/. -->
<!-- Each task here links to its task file in tasks/TASK-NNN.md. -->

| ID | Workstream | Tasks |
|---|---|---|
| W1 | | TASK-NNN |

## Dependencies

### External packages (to add)
<!-- Third-party packages that must be added as dependencies. -->

### Existing code dependencies (read-only, not modified)
<!-- Existing modules/functions that new code depends on but must not modify. -->

## Constraints

<!-- Hard constraints the implementation must respect. Non-negotiable. -->

- 

## Current Focus

<!-- The single task that should be executed next, with a one-line rationale. -->

**TASK-NNN: <title>** — <why this is next>

## Completion Criteria

<!-- Observable, testable conditions that mean the plan is fully delivered. -->

1. 
2. 

## Linked Tasks

<!-- Every task file created from this plan. -->
<!-- The Architect copies TASK-NNN.template.md → tasks/TASK-NNN.md for each. -->

- `tasks/TASK-NNN.md` — <one-line summary>
