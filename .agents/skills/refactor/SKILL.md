---
name: refactor
description: Run a large-scale, whole-repository refactor — code simplification, slop and code-smell removal, de-duplication, and cross-module consistency — with behavior preserved and uncertain changes escalated to the user. Use when asked to refactor the codebase, clean up at scale, or consolidate duplicated logic.
---

# Large-Scale Refactor

A whole-codebase refactor pass. **Everything is in scope.** The goal is to leave the implementation dramatically simpler, more consistent, and free of slop — without changing behavior.

## Step 1 — Discover the scope

Enumerate the repository's top-level areas (for example `services/`, `packages/`, `apps/`, `workers/`, `src/`, `scripts/` — whatever this repository actually has). Skip generated code (generated clients, lockfiles, build artifacts) and vendored dependencies.

## Step 2 — Fan out sub-agents

Launch parallel sub-agents, one per area. **Each sub-agent must also read the sibling areas** — not to edit them, but to spot violations inside its own area: divergent patterns, duplicated helpers, models that already exist elsewhere. Consistency findings only count when backed by a concrete reference to where the canonical pattern lives.

## Step 3 — What to hunt

- **Code slop and smells**: dead code, leftover scaffolding, defensive branches for cases that cannot happen, wrapper indirection, copy-paste drift.
- **Duplicate code**: same logic in two places; extract to the canonical home.
- **Module consolidation**: modules that should be combined and de-duplicated; merge them and update every importer.
- **Shared-code promotion**: models, helpers, or contracts used by more than one area that belong in the repository's shared/common packages (if the repo has them); move them there.
- **Normalization and validation**: ad-hoc transformations that the repository's existing annotation/validator/helper layer already handles — use the shared mechanism, or extend it with a new annotation rather than inlining the logic.
- **Cross-area inconsistency**: area A does something one way and area B does the same thing a different way; converge on the better pattern.

Additionally, run the **code-simplify** skill's rubric over the areas you touch and apply its fixes as part of this pass.

## Step 4 — Behavior preservation and escalation

Every refactor must preserve behavior: same inputs, outputs, side effects, and error behavior. If you find something valuable to refactor but you are **unsure** — a slight behavior change, an external contract (routes, response shapes, durable identifiers, persisted formats), or an ambiguous intent — **do not guess**: collect it and ask the user with `AskUserQuestion`, batching related items.

## Step 5 — Verify

- If the repository has tests, run them and make them pass. Start whatever the test setup needs (for example Docker services) if the repository supports it.
- If there are no tests, skip this — rely on type checkers, linters, and careful reading.
- Never leave the repo in a broken state between consolidation steps: when you move or merge modules, update all consumers in the same change.

## Step 6 — Report

Summarize: refactors applied (grouped by area), duplications removed, items escalated to the user and their outcomes, and verification results.
