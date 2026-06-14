---
name: "claude-review"
description: "Review a GitHub pull request with parallel specialized agents and post inline review comments rated by severity. Surfaces every valid issue; does not fix anything. Use when asked to review a PR or run /code-review."
---

# Claude Code Review

Review a GitHub pull request with parallel specialized agents and post the findings as **inline review comments**, each rated by severity. Surface every valid issue — do not fix anything.

**Scope — pre-existing issues are in scope.** Do not limit the review to the lines this PR changed. Real bugs and project-rule violations that already existed in the touched files, or that the PR did not introduce, are within scope. Never dismiss a finding solely because it predates this PR.

## Steps 1–2 — PR discovery and context

**Step 1:** Read and execute **Step 1** of the **scope-agents** skill (repository discovery and PR detection). This returns the repository structure and — if a PR is detectable — its number and repo slug.

If no PR is detected, stop and ask the user to provide a PR number or URL.

Then use a Haiku agent to check eligibility: stop without proceeding if the PR is (a) closed, (b) a draft, (c) clearly automated or trivially simple and obviously fine, or (d) already has a review or code-review comment from you **for the PR's current head commit** — a new push since your last review makes the PR eligible again.

**Step 2 (two parallel Haiku agents):**

- Agent A: Fetch the PR diff and return a summary of the change and the list of changed files.
- Agent B: List the project rule files loaded for this repository (the agent's own rules directory, wherever the platform keeps it); names only, not contents.

## Step 3 — Review

Launch **5 parallel Sonnet agents** to independently review the PR diff. Each agent reads the changed files and returns a flat list of issues with the reason each was flagged (e.g. rule compliance, bug, historical context):

- Agent #1 (rules): Audit the changes for compliance with the project rule files gathered earlier (Step 2). Note that the rules are guidance for code generation, so not all instructions apply during review.
- Agent #2 (bugs): Scan the diff for obvious bugs. Focus on real defects; ignore likely false positives. You may read surrounding context in the touched files; pre-existing bugs in those files are in scope.
- Agent #3 (history): Read git blame and history of the changed files; flag bugs that only make sense in light of that history.
- Agent #4 (prior PRs): Read previous pull requests that touched the same files; check whether comments on those PRs also apply here.
- Agent #5 (comments): Read code comments in the modified files; flag anything in the diff that contradicts guidance in those comments.

## Step 4 — Validity and severity

First **deduplicate**: the five agents overlap, so merge findings that report the same issue at the same file and line into a single finding (keep the clearest wording and the highest severity). Then drop **clear false positives** only (see the list below). **Keep every remaining valid finding** and assign it a severity — do **not** discard a finding for being minor; a real-but-minor issue is a **Low**, not a drop. This is the bar: validity, not a confidence cutoff.

- **Critical** — data loss, security/auth bypass, a crash, or clearly broken core behavior.
- **High** — a real bug likely hit in normal use, or a clear violation of a project rule that matters in practice.
- **Medium** — a real issue with limited, conditional, or non-obvious impact.
- **Low** — valid but minor: a nitpick the change genuinely got wrong, a rare edge case, or a small correctness/UX deviation (e.g. a state that now persists across a remount where it previously reset).

For rule-compliance findings: confirm the rule file actually calls out that specific issue before rating it above Low.

## Step 5 — Post one inline review

Use a Haiku agent to repeat the eligibility check from Step 1. If still eligible, post **one** pull request review containing an **inline comment per finding**, anchored to the exact file and line, via the GitHub API.

**Assemble the JSON payload with `jq` — never hand-write it** — so the newlines and quotes in each multi-line comment body are escaped correctly. Build the `comments` array (one object per finding), then post the review:

```bash
# Append one comment object per finding (jq escapes each multi-line body via
# --arg). Run this jq line once per finding so the objects accumulate — start
# from an empty file and append (>>); do not overwrite it.
: > /tmp/review-comments.ndjson
jq -nc --arg path "relative/path.tsx" --argjson line 402 \
  --arg body "$(printf '### Short title\n\n**Low Severity**\n\nExplanation.')" \
  '{path: $path, line: $line, side: "RIGHT", body: $body}' >> /tmp/review-comments.ndjson
# ... repeat the jq line above for each additional finding ...

# Slurp every finding into the comments array and post one review:
jq -n --arg commit "<full head sha>" --arg summary "Found 2 issues." \
  --slurpfile comments /tmp/review-comments.ndjson \
  '{commit_id: $commit, event: "COMMENT", body: $summary, comments: $comments}' \
  | gh api --method POST "repos/<owner>/<repo>/pulls/<number>/reviews" --input -
```

- The review **body** carries only a one-line summary (for example `Found 2 issues.` or `No issues found.`) plus, when needed, the off-diff findings described below. Never include a "what was reviewed" / coverage summary, a list of areas checked, or any description of your process.
- One entry in `comments[]` per finding, anchored to the line the issue is on (`side: "RIGHT"` for added/current lines; `side: "LEFT"` for removed lines).
- If a finding sits on a line **not present in the PR diff** (a pre-existing line GitHub will reject as an inline target), append it to the body under an `Outside the diff:` heading — one line per finding with its file:line, severity, and explanation — rather than as an inline comment.
- A single `comments[]` entry whose line is not in the diff makes GitHub reject the **entire** review with 422. Anchor inline comments only to diff lines; if the post still fails on an inline target, drop that one comment (fold it into the `Outside the diff:` body list) and retry, so one bad anchor never blocks the other findings.
- If there are no valid findings, post the review with an empty `comments` array and `body` = `No issues found.`

## Inline comment format

Each `comments[].body` follows this format (matches a severity-rated bug review):

```
### <Short imperative title>

**<Severity> Severity**

<1–3 sentences: what is wrong and when it bites. Cite the rule file when the finding is rule-based.>
```

## False Positives to Ignore

- Something that looks like a bug but is not
- Pedantic nitpicks a senior engineer would never call out
- Issues a linter, typechecker, or CI step would catch (assume CI runs separately)
- General code quality (test coverage, documentation) unless the project rules require it
- Issues called out in the project rules but explicitly silenced in the code (e.g. a lint-ignore comment)
- Likely intentional behavior changes related to the broader PR goal

## Notes

- Make a todo list first.
- Do not attempt to build or typecheck the project, and do not modify code — this skill only reviews and comments.
- Use `gh` for all GitHub operations; do not use web fetch.
- Use the full head-commit SHA in `commit_id` (not a branch name or `HEAD`).
- When reporting file paths, use paths relative to the repository root.
