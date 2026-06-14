---
name: "claude-review"
description: "Review a GitHub pull request with parallel specialized agents and post inline review comments rated by severity. Surfaces every valid issue; does not fix anything. Use when asked to review a PR or run /code-review."
---

# Claude Code Review

Review a GitHub pull request with parallel specialized agents and post the findings as **inline review comments**, each rated by severity. Surface every valid issue — do not fix anything.

**Scope — pre-existing issues are in scope.** Do not limit the review to the lines this PR changed. Real bugs and project-rule violations that already existed in the touched files, or that the PR did not introduce, are within scope. Never dismiss a finding solely because it predates this PR.

All GitHub interaction uses the **GitHub MCP pull request tools** — `pull_request_read`, `pull_request_review_write`, and `add_comment_to_pending_review`. Do not hand-build review JSON or call the REST API.

## Steps 1–2 — PR discovery and context

**Step 1:** Read and execute **Step 1** of the **scope-agents** skill (repository discovery and PR detection). This returns the repository structure and — if a PR is detectable — its number and repo slug.

If no PR is detected, stop and ask the user to provide a PR number or URL.

Then use a Haiku agent to check eligibility: stop without proceeding if the PR is (a) closed, (b) a draft, (c) clearly automated or trivially simple and obviously fine, or (d) you **already reviewed the PR's current head commit** — a new push since your last review makes the PR eligible again. To check (d), list **all** the PR's reviews (`pull_request_read` with `method: "get_reviews"`, paging through every page via `page`/`perPage`), keep only **submitted** reviews **authored by you** (ignore `PENDING` and `DISMISSED` states), and treat the head as already reviewed only when one of them has a `commit_id` equal to the current head SHA. Match on `commit_id`, never on timestamps; a review by anyone else, or one tied to an earlier commit, does not count.

**Step 2 (two parallel Haiku agents):**

- Agent A: Fetch the PR diff (`pull_request_read` with `method: "get_diff"`) and return a summary of the change, the list of changed files, and the **head SHA the diff was taken at** (`pull_request_read` with `method: "get"`, `head.sha`). Retain that SHA as the baseline — Step 5 compares the current head against it to detect a mid-run push.
- Agent B: List the project rule files loaded for this repository (the agent's own rules directory, wherever the platform keeps it); names only, not contents.

## Step 3 — Review

Launch **5 parallel Sonnet agents** to independently review the PR diff. Each agent reads the changed files and returns a flat list of issues — each with its **file path, line number, and diff side** (`RIGHT` for an added/current line, `LEFT` for a removed line, or `off-diff` for a line the PR did not touch) so it can be anchored inline — and the reason it was flagged (e.g. rule compliance, bug, historical context). For a `RIGHT` line use the line number in the new (head) file; for a `LEFT` line use the line number on the diff's **base** side (the pre-change file), since removed lines are not present in the head file:

- Agent #1 (rules): Audit the changes for compliance with the project rule files gathered earlier (Step 2). Note that the rules are guidance for code generation, so not all instructions apply during review.
- Agent #2 (bugs): Scan the diff for obvious bugs. Focus on real defects; ignore likely false positives. You may read surrounding context in the touched files; pre-existing bugs in those files are in scope.
- Agent #3 (history): Read git blame and history of the changed files; flag bugs that only make sense in light of that history.
- Agent #4 (prior PRs): Read previous pull requests that touched the same files; check whether comments on those PRs also apply here.
- Agent #5 (comments): Read code comments in the modified files; flag anything in the diff that contradicts guidance in those comments.

## Step 4 — Validity and severity

First **deduplicate**: the five agents overlap, so merge findings that report the same issue at the same file and line — or the same issue on adjacent lines — into a single finding (keep the clearest wording). Then drop **clear false positives** only (see the **False Positives to Ignore** section near the end). **Keep every remaining valid finding** and assign it a severity — do **not** discard a finding for being minor; a real-but-minor issue is a **Low**, not a drop. This is the bar: validity, not a confidence cutoff.

- **Critical** — data loss, security/auth bypass, a crash, or clearly broken core behavior.
- **High** — a real bug likely hit in normal use, or a clear violation of a project rule that matters in practice.
- **Medium** — a real issue with limited, conditional, or non-obvious impact.
- **Low** — valid but minor: a nitpick the change genuinely got wrong, a rare edge case, or a small correctness/UX deviation (e.g. a state that now persists across a remount where it previously reset).

For rule-compliance findings: confirm the rule file actually calls out that specific issue before rating it above Low.

## Step 5 — Post one inline review

Before posting anything, run two gates in order; only if **both** pass do you create and submit the review.

1. Use a Haiku agent to repeat the eligibility check from Step 1. If it is no longer eligible, stop.
2. Re-fetch the head SHA (`pull_request_read` with `method: "get"`, read `head.sha`) and compare it to the baseline SHA the diff and findings were gathered against (Step 2). If they differ, the head moved mid-run — **stop without posting**; the workflow fires a fresh run for the new commit, so stale findings are never anchored to a newer commit.

With both gates passed, post the findings as a single pending review using the GitHub MCP pull request tools and submit it:

1. **Clear any stale pending review, then open a fresh one.** A cancelled or failed earlier run can leave a self-authored `PENDING` review on the PR, which makes `create` collide. First delete it (`pull_request_review_write` with `method: "delete_pending"`); deleting when none exists is a harmless no-op. Then `pull_request_review_write` with `method: "create"`, the `owner`/`repo`/`pullNumber`, and `commitID` set to that head SHA. Omit `event` so the review stays **pending** — passing `event` submits it immediately, before any inline comments are attached.
2. **Add one inline comment per on-diff finding.** For each finding whose anchor is on the diff, call `add_comment_to_pending_review` with `path`, `body`, `subjectType: "LINE"`, `line`, and `side` (`RIGHT` for added/current lines, `LEFT` for removed lines; add `startLine`/`startSide` for a multi-line range).
   - **Validate the anchor against the diff first.** `add_comment_to_pending_review` **silently drops** a comment whose `line`/`side` is not part of the PR diff — it does not error, so an unvalidated finding would just vanish. Build the set of valid `(path, line, side)` targets from the diff (`pull_request_read` with `method: "get_files"`, reading each file's `patch`; page through **all** files via `page`/`perPage`; a file with no `patch` — binary or too large — exposes no inline targets) and add a comment only when its anchor is in that set. Every other finding goes to the summary body in the next step.
3. **Submit the review.** `pull_request_review_write` with `method: "submit_pending"`, `event: "COMMENT"`, and `body` = a one-line summary (for example `Found 3 issues.`) optionally followed by an `Outside the diff:` list — one line per finding that could not be anchored inline (`file:line — severity — explanation`). The summary count covers **every** finding, inline plus off-diff. The body never includes a "what was reviewed" / coverage summary, a list of areas checked, or any description of your process. When there are no findings, submit with `body: "No issues found."` and no inline comments.

If you create the pending review but cannot submit it, delete it (`pull_request_review_write` with `method: "delete_pending"`) so no stray pending review is left on the PR.

## Inline comment format

Each `add_comment_to_pending_review` `body` follows this format (matches a severity-rated bug review):

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
- Use the GitHub MCP pull request tools for all GitHub operations; do not use web fetch or hand-built REST calls.
- Pin the review to the full head-commit SHA via `commitID` (not a branch name or `HEAD`).
- When reporting file paths, use paths relative to the repository root.
