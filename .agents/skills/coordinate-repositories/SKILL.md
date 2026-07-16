---
name: coordinate-repositories
description: Coordinate one authorized task across a bounded collection of local repositories while preserving unrelated work. Use when a task spans repositories to apply a scoped change, run the same review or validation, or collect and merge information into one result.
---

# Coordinate Repositories

Carry out the caller's task consistently across the selected repository collection without treating matching names or layouts as proof of matching behavior.

## Workflow

1. Determine the bounded repository collection from the current repository, accessible sibling repositories, and the user's scope. Do not crawl unrelated locations.
2. For each candidate, read the relevant files and enough local guidance to understand whether the task applies. Keep repository-specific behavior unless the caller explicitly requests a unification.
3. Choose the task mode:
   - For a read-only task, gather evidence from every applicable repository and merge it into one clearly attributed result.
   - For a change or review-and-fix task, before selecting a worktree or branch, query the hosting service for an open pull request whose current head branch and task scope match the candidate. Verify its current state, exact remote head branch, and task scope. Never treat a local branch, remote-tracking branch, remembered URL, or prior task output as evidence that a pull request should receive new work.
4. For a change or review-and-fix task:
   - When a verified matching pull request is open, create an isolated worktree from that pull request's remote head branch and update only that pull request.
   - When no verified matching pull request is open—or it is merged, closed, missing, or its branch was deleted—create a fresh isolated worktree from the current remote default branch and a new collision-free branch. When the user authorizes persistent changes, validate first, then commit, push, and open a new focused pull request.
   - In every case, leave the original checkout, branch, and unrelated dirty or in-progress work untouched.
5. Carry only the user-authorized task artifacts into each isolated worktree. Do not copy unrelated in-progress changes, generated outputs, credentials, or machine-specific configuration.
6. Validate each completed repository with the relevant native checks. If the task manages generated files, use its owning generator rather than hand-editing generated outputs.
7. Report every repository completed, skipped, or blocked; the applied or gathered result; validation; and all pull-request links created or updated.

## Guardrails

- Preserve repository-specific instructions and report contradictions for the caller to resolve.
- Do not commit, push, or open pull requests unless the user authorized persistent changes.
- Keep each repository's changes focused; never combine unrelated work merely because it is present locally.
- Prefer independent progress: a conflict or failure in one repository does not block unaffected repositories.
