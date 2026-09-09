# Agent Protocol

> The single source of truth for project conventions, skill-gated implementation,
> testing rules, Godoc rules, and module structure is the root
> [`AGENTS.md`](../AGENTS.md). This file defines the development workflow protocol
> only. Do not duplicate conventions here — update the root `AGENTS.md` instead.

## Session start

1. **Read identity first.** Read the root [`AGENTS.md`](../AGENTS.md) to
   understand what the project is, its modules, and the dependency rule.
2. **Load always-on skills.** `go-systems-programmer`, `go-security-expert`,
   `go-memory-oom-guard` — load in parallel at session start. See the
   Skill-Gated Implementation section in root `AGENTS.md`.
3. **Consult architecture.** Read
   [`Go Trust & Security Platform — Architecture Specification.md`](../Go%20Trust%20%26%20Security%20Platform%20—%20Architecture%20Specification.md)
   for the full architecture.
4. **Inspect state.** Read `.ai-trust/context/state/current.md` and
   `.ai-trust/STATE.md` for the current execution state. Read
   `.ai-trust/DECISIONS.md` for decision history.
5. **Inspect active specs.** Read the specs in `.ai-trust/context/specs/`
   that are not superseded.
6. **Follow workflows.** Execute tasks strictly via PLAN and TASK templates
   (`.ai-trust/context/plans/PLAN-NNN.template.md`).

## Building a plan

When building a `PLAN-NNN.md`:

1. Read the relevant SPEC(s) that the plan implements.
2. For each workstream that implements an algorithm, consult the
   algorithm-to-skill matrix in `trust/algorithms.json` (the `skill` field
   on each algorithm entry). List the primary and secondary skills the
   workstream will load.
3. Confirm skills are installed (`.agents/skills/` for project-local, or
   user-level). If missing, install before starting the workstream.
4. Do not load all skills at once — load only what the current workstream
   needs. This keeps context lean.
5. Each workstream task cites the governing standard from the algorithm's
   `godoc_citation` field.

## During implementation

1. Load the on-demand skill(s) for the algorithm being implemented.
2. Follow the skill's guidance — do not guess at crypto or auth.
3. Write Godoc comments citing the standard (see Godoc Rules in root
   `AGENTS.md`).
4. Write tests with known vectors (see Testing Rules in root `AGENTS.md`).
5. If Wycheproof has vectors for the algorithm, add Wycheproof tests too.
6. Run `go build`, `go vet`, `go test -race`, `govulncheck` before committing.
7. Humanize the commit message with the `content-humanizer` skill before
   committing. Cite the standard in the commit body.
