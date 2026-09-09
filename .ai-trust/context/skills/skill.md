# Skill: Project Context Protocol

## Capability

Bootstraps and manages a robust cross-IDE multi-repository AI control plane (`.ai/`) with GraphRAG Qdrant knowledge integration.

## When to Invoke

- When setting up a new multi-repository project for AI agents (Gemini CLI, Devin, Cursor, Claude Code).
- When initializing structured specs (`SPEC-NNN.md`), plans (`PLAN-NNN.md`), tasks (`TASK-NNN.md`), and ADRs.

## What It Does

1. Runs `project-context` (or `setup-project-context.sh`) to initialize the `.ai/` control plane.
2. Sets up durable state tracking (`STATE.md`), architectural decisions (`DECISIONS.md`), and agent protocols (`AGENTS.md`).
3. Configures Qdrant payload-based GraphRAG indexes for structured code knowledge retrieval.

## Installation & Usage

Via npm:
\`\`\`bash
npm install -g project-context-protocol
project-context
\`\`\`
