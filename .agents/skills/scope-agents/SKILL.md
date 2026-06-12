---
name: scope-agents
description: Shared Steps 1–2 for repository-wide multi-agent workflows — discover `apps/`, `services/`, and `packages/` scopes, detect the current PR, and fan out parallel Sonnet agents (per-scope, cross-scope, tests, scripts). Parent skills supply domain-specific survey rules and checklists.
---

# Scope Agents

Use this skill as the **orchestration layer** for codebase-wide analysis tasks that fan out parallel agents by repository area. **Parent skills** (for example redundancy, inconsistencies, dead code, security) define *what* to look for; this skill defines *how* scopes are discovered and how agents are assigned.

## When to use

- **Full (Steps 1–2):** Invoke alongside a domain skill that says “follow `scope-agents` for Steps 1–2.” Used by skills that fan out per-scope agents across `apps/`, `services/`, and `packages/` (e.g. `claude-security`, `claude-redundancy`, `claude-dead-code`, `claude-inconsistencies`).
- **Step 1 only:** A skill may invoke only Step 1 when it needs repository structure and PR detection but handles its own agent topology. Used by `claude-review`, which runs fixed-lens review agents over the PR diff rather than per-scope fan-out.

## Step 1 — Repository and PR discovery (Haiku)

Use a Haiku agent to inspect the repository root and return:

- The list of paths under `apps/`, `services/`, and `packages/` (one level deep each)
- Whether a PR number or PR URL was provided in the arguments or is otherwise detectable from the current git branch (e.g. via `gh pr view`)
- If a PR is detected, return its number and repo slug (owner/repo)

## Step 2 — Parallel scoped Sonnet agents

Launch all of the following Sonnet agents **in parallel**.

Each agent must:

- **Survey before judging.** Glob the full file tree of its scope first, then read a broad sample of files across the entire scope. Apply the **domain-specific** “survey before judging” rule from the parent skill (redundancy, inconsistency, dead code, security, etc.) so you only flag issues supported by evidence.
- Explore its assigned scope thoroughly (the parent skill names what to read: imports, routes, handlers, tests, scripts, and so on).
- Return a flat list of **findings**, each with: a short title, a description that matches the parent skill’s expectations, and the file path(s) and line number(s) involved.

**Agent topology** (fixed):

**Per-scope agents** — one agent per discovered top-level path from Step 1:

- For each path under `apps/` (e.g. `apps/api/`), one agent scoped to that app
- For each path under `services/` (e.g. `services/records/`), one agent scoped to that service
- For each path under `packages/` (e.g. `packages/core/`), one agent scoped to that package

**Cross-scope agent** (exactly 1):

- Scope: all of `apps/`, `services/`, and `packages/` at a structural level — compare across these trees for issues the parent skill describes (for example duplicate logic, cross-service drift, orphaned symbols).

**Tests agent** (exactly 1):

- Scope: `tests/`

**Scripts agent** (exactly 1):

- Scope: `scripts/`

The parent skill **must** provide the checklists and rules each of these agents applies (what to flag under per-scope, cross-scope, tests, and scripts). This skill does not define domain findings.

## Branch naming convention

When a parent skill applies fixes to the repository, it must create a git branch before editing any files. Use this naming pattern:

```
claude/{short-name}-{random-chars}
```

- `short-name` — 1–3 lowercase words describing the fix (e.g. `security-fixes`, `dead-code`, `dedup`, `consistency`)
- `random-chars` — 7–10 alphanumeric characters (e.g. generated with `openssl rand -hex 4` or `git rev-parse --short HEAD`)

Example: `claude/security-fixes-a3f9b2c`, `claude/dead-code-4e8d12ab`

Create the branch with `git checkout -b <branch>` before the first file edit, then commit all approved fixes to that branch.

## Notes

- When reporting file paths in downstream steps, use paths relative to the repository root.
- Step 3 onward (scoring, user approval, fixes, PR comment) lives in the **parent skill**, not here.
