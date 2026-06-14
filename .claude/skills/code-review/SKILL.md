---
name: code-review
description: Review a GitHub pull request with parallel specialized agents and post inline review comments rated by severity. Surfaces every valid issue; does not fix anything. Use when asked to review a PR or run /code-review.
---

# Code Review

Review a GitHub pull request with parallel specialized agents and post the findings as **inline review comments**, each rated by severity. Surface every valid issue — do not fix anything.

**Scope — pre-existing issues are in scope.** Do not limit the review to the lines this PR changed. Real bugs and project-rule violations that already existed in the touched files, or that the PR did not introduce, are within scope. Never dismiss a finding solely because it predates this PR.

## GitHub tools — pick by runner

All GitHub interaction goes through your platform's pull-request tools — never hand-built REST/JSON.

- **If you are a Claude agent:** read with `pull_request_read` (methods `get`, `get_diff`, `get_files`, `get_reviews`). Post each inline comment with `mcp__github_inline_comment__create_inline_comment` (set `confirmed: true`; anchor with the full head SHA and an `Lstart-Lend` line range). If that tool is unavailable in your environment, fall back to the pending-review flow: `pull_request_review_write` (`create` then `submit_pending`) with `add_comment_to_pending_review` per inline comment.
- **If you are a Cursor agent (or any non-Claude runner):** use your own GitHub pull-request tools — discover them in your available tool list at runtime. Use the tool that reads the PR diff and the tool that posts an inline review comment anchored to a file and line. Do not call Claude-specific `mcp__github__*` names.

If your runtime cannot launch parallel sub-agents, run the per-agent steps below **sequentially within this single thread** instead — same lenses, same output.

## Step 1 — Eligibility and PR discovery

Identify the target PR: its number and repo slug (owner/repo) are normally supplied by the runner (repo, PR number/URL, head ref and SHA, author). If not supplied, detect the PR from the current branch (`pull_request_read`, or `gh pr view --json number,headRefOid,state,isDraft`). If no PR is detectable, stop and ask the user for a PR number or URL.

Then check eligibility (delegate to a sub-agent when sub-agents are available): stop without proceeding if the PR is (a) closed, (b) clearly automated or trivially simple and obviously fine, or (c) you **already reviewed the current head commit** — a new push since your last review makes it eligible again. Draft PRs are in scope; review them like any other. For (c): list the PR's reviews (`pull_request_read` `method: "get_reviews"`, paging through all pages), keep non-dismissed reviews (ignore `PENDING`/`DISMISSED`) whose body contains your `<!-- code-review:claude -->` marker (see Step 6), and treat the head as already reviewed only when one has a `commit_id` equal to the current head SHA. Match on `commit_id`, never on timestamps. A review without that marker (a human's, or the other review tier's) does not count.

## Step 2 — Context (two parallel agents)

- Agent A: fetch the PR diff and changed files (`pull_request_read` `method: "get_diff"` / `"get_files"`). Return a summary of the change, the changed-file list, and **record the baseline head SHA** the diff was taken at.
- Agent B: list the project rule files loaded for this repository (the agent's own rules directory, wherever the platform keeps it); names only, not contents.

## Step 3 — Review (parallel reviewers)

Launch the following review agents in parallel (or sequentially in this thread if sub-agents are unavailable). Each reads the changed files and returns a flat list of findings — each with its **file path, line number, and diff side** (`RIGHT` for an added/current line, `LEFT` for a removed line using the base-side line number, or `off-diff` for a line the PR did not touch) plus the reason it was flagged:

- Agent #1 (rules): audit the changes for compliance with the project rule files from Step 2. The rules are guidance for code generation, so not all apply during review.
- Agent #2 (bugs): scan for real defects; ignore likely false positives. Pre-existing bugs in the touched files are in scope.
- Agent #3 (history): read git blame and history of the changed files; flag bugs that only make sense in light of that history.
- Agent #4 (prior PRs): read previous PRs that touched the same files; check whether their comments also apply here.
- Agent #5 (comments): read code comments in the modified files; flag anything in the diff that contradicts them.

## Step 4 — Validate, dedup, severity

First **deduplicate**: merge findings that report the same issue at the same file and line — or on adjacent lines — into one (keep the clearest wording). Then drop **clear false positives** only (see the **False Positives to Ignore** section near the end). **Keep every remaining valid finding** and assign a severity — do not discard a finding for being minor; a real-but-minor issue is a **Low**, not a drop. The bar is validity, not a confidence cutoff.

- **Critical** — data loss, security/auth bypass, a crash, or clearly broken core behavior.
- **High** — a real bug likely hit in normal use, or a clear violation of a project rule that matters in practice.
- **Medium** — a real issue with limited, conditional, or non-obvious impact.
- **Low** — valid but minor: a nitpick the change genuinely got wrong, a rare edge case, or a small correctness/UX deviation.

For rule-compliance findings, confirm the rule file actually calls out that specific issue before rating it above Low.

## Step 5 — Re-gate before posting

Repeat the eligibility check from Step 1, and re-fetch the head SHA. If it differs from the baseline recorded in Step 2, the head moved mid-run — **stop without posting**; the next run reviews the new commit. Never anchor findings gathered against one commit to a different head.

## Step 6 — Post one inline review

**If there are no findings, do not post anything — skip the review entirely.** Never post a "no issues" / "looks good" review. Otherwise post **one** review: an inline comment per **on-diff** finding, plus any off-diff findings collected into a single summary comment. Use the posting tool for your runner (see **GitHub tools** above).

- Anchor each inline comment to the finding's `path`, line, and `side`, using the **full head SHA**. **Validate each anchor against the diff first** — a comment on a line not present in the diff is silently dropped or rejected, so move anything that will not anchor into the summary instead.
- The summary body is one line (e.g. `Found 3 issues.`), optionally followed by an `Outside the diff:` list, one entry per off-diff finding (`path:line — Severity — explanation`). The count covers **every** finding, inline plus off-diff. Never include a "what was reviewed" / coverage summary or any description of your process.
- End the summary body with the hidden marker `<!-- code-review:claude -->` on its own line (this is your tier's marker; the Cursor CI runner stamps its own). A later run treats the head as already reviewed (Step 1c) when a non-dismissed review carrying this marker exists for the current head SHA, so the marker is what lets re-triggers skip re-reviewing the same commit.

## Inline comment format

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
- When reporting file paths, use paths relative to the repository root.
- Anchor inline comments to the full head-commit SHA (not a branch name or `HEAD`).
