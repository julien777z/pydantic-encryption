---
alwaysApply: true
---

# GitHub Rules

## Configuration Options

- Do not manually specify options like `python-version` in workflows.
- Use the defaults from shared actions or reusable workflows unless there is a specific edge case requiring a different version.
- If an edge case requires a specific version, add a comment explaining why.

## Branch Continuity

- When the user assigns additional work while the current checkout is on a non-default branch, treat it as a continuation: retain that branch and add the work to its pull request.
- Before creating a pull request, query the current branch's existing pull request. Reuse it when it is open; if none exists, create one from the current branch rather than splitting the work.
- Do not create a separate branch or pull request merely because the additional task differs or could be reviewed independently. Do so only when the user explicitly asks, or when the current branch represents an already-merged pull request; in the latter case, start the new work from the default branch.
