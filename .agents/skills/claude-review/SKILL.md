---
name: claude-review
description: Review a GitHub pull request using parallel specialized agents with confidence-based scoring. Posts findings as a PR comment via `gh`. Use when asked to review a PR or run /code-review.
---

# Claude Code Review

Review a GitHub pull request using parallel specialized agents, confidence scoring, and optional fix application.

**Scope — pre-existing issues are in scope.** Do not limit the review to the lines this PR changed. Real bugs and project-rule violations that already existed in the touched files, or that the PR did not introduce, are within scope: flag them and fix them alongside the PR's own issues. Never dismiss a finding solely because it predates this PR.

## Local / pre-push mode

When this skill is invoked **outside a GitHub PR** — for example by the Stop hook before a push, or whenever the caller asks for a local review of the branch — adapt the flow:

- Review the **local branch diff** — `git diff $(git merge-base <base> HEAD)` plus any untracked files the branch adds — where `<base>` is the repository's remote default branch (for example `origin/main` — use the actual default branch name; fall back to the local default branch if no remote is configured). The merge-base anchors the diff at the branch's fork point — and, when working directly on the default branch, at the last pushed commit — so it covers branch commits **and uncommitted working-tree changes** without pulling in unrelated upstream commits. Do not fetch a PR; skip the PR discovery and eligibility checks in Steps 1–2 entirely (do not stop or ask for a PR). Still gather the rules context Step 3 needs: list the project rule files loaded for this repository (the agent's own rules directory, wherever the platform keeps it).
- Run the Step 3 review agents and the Step 4 confidence scoring over that scope — the diff plus the untracked files — exactly as written.
- **Apply** the surviving findings directly to the working tree and fold them into the commit being pushed. Skip the `AskUserQuestion` gate (Step 6), the separate `claude/review-fixes-*` branch (Step 7), and Step 8 entirely — never post a comment in this mode. Step 5's “skip to step 8” does not apply here: if no findings survive the filter, report that in your reply and conclude.

Use the full PR flow (Steps 1–2, 6–8, and the comment format) **only** when reviewing an actual GitHub PR.

## Steps 1–2 — PR discovery and context

**Step 1:** Read and execute **Step 1** of the **scope-agents** skill (repository discovery and PR detection). This returns the repository structure and — if a PR is detectable — its number and repo slug.

If no PR is detected and you are reviewing a PR (not in local / pre-push mode), stop and ask the user to provide a PR number or URL.

Then use a Haiku agent to check eligibility: stop without proceeding if the PR is (a) closed, (b) a draft, (c) clearly automated or trivially simple and obviously fine, or (d) already has a code review comment from you.

**Step 2 (two parallel Haiku agents):**

- Agent A: Fetch the PR diff and return a summary of the change and the list of changed files.
- Agent B: List the project rule files loaded for this repository (the agent's own rules directory, wherever the platform keeps it); names only, not contents.

## Steps 3–8 — Review, scoring, approval, fixes, report

Follow these steps precisely (in local / pre-push mode, the **Local / pre-push mode** section above replaces Steps 1–2 and overrides Steps 6–8):

3. Launch **5 parallel Sonnet agents** to independently review the diff (the PR diff, or the local branch diff in local / pre-push mode). Each agent reads the changed files and returns a flat list of issues with the reason each was flagged (e.g. rule compliance, bug, historical context):
   - Agent #1 (rules): Audit the changes for compliance with the project rule files gathered earlier (Step 2, or locally in local / pre-push mode). Note that the rules are guidance for code generation, so not all instructions apply during review.
   - Agent #2 (bugs): Scan the diff for obvious bugs. Focus on large bugs; ignore nitpicks and likely false positives. You may read surrounding context in the touched files; pre-existing bugs in those files are in scope.
   - Agent #3 (history): Read git blame and history of the changed files; flag bugs that only make sense in light of that history.
   - Agent #4 (prior PRs): Read previous pull requests that touched the same files; check whether comments on those PRs also apply here.
   - Agent #5 (comments): Read code comments in the modified files; flag anything in the diff that contradicts guidance in those comments.

4. For each issue found in step 3, launch a **parallel Haiku agent** that scores it 0–100. Give this rubric to the agent verbatim:
   - 0: Clear false positive — does not hold up to light scrutiny.
   - 25: Uncertain — might be real, but the agent could not verify it. If stylistic, it is not explicitly called out in the project rules.
   - 50: Likely real but minor — the agent verified it, but it is a nitpick or happens rarely.
   - 75: High confidence — verified, likely hit in practice, important or explicitly mentioned in the project rules.
   - 100: Certain — confirmed real, happens frequently, directly evidenced.

   For rule-compliance issues: double-check that the rule file actually calls out that specific issue before scoring above 50.

5. Filter out issues with a score below 80. If none remain, skip to step 8.

6. **You must call `AskUserQuestion` before applying any fix.** Present up to 4 issues per batch, asking for each: "Fix this? (yes / skip)". Wait for responses before the next batch. Record every decision.

7. Implement every finding the user approved. Before editing any file, create a git branch following the naming convention in **scope-agents** (e.g. `claude/review-fixes-a3f9b2c`) and commit all fixes to that branch. Keep each fix minimal — do not refactor unrelated code.

8. Use a Haiku agent to repeat the eligibility check from Step 1. If still eligible, post a comment using `gh pr comment <number> --body "..."`. Follow the comment format below.

## False Positives to Ignore

- Something that looks like a bug but is not
- Pedantic nitpicks a senior engineer would not call out
- Issues a linter, typechecker, or CI step would catch (assume CI runs separately)
- General code quality (test coverage, documentation) unless the project rules require it
- Issues called out in the project rules but explicitly silenced in the code (e.g. a lint-ignore comment)
- Likely intentional behavior changes related to the broader PR goal

## Notes

- Make a todo list first.
- Do not attempt to build or typecheck the project.
- Use `gh` for all GitHub operations; do not use web fetch.
- Cite and link every issue (including the relevant rule file when applicable).
- When reporting file paths, use paths relative to the repository root.

## Comment/Output Format

Follow this format precisely (example with 3 issues, 1 fixed and 2 skipped):

---

### Code review

Found 3 issues (1 fixed, 2 skipped):

1. ✅ **Missing auth check on mutating route** *(fixed)* — Added `CurrentUser` dependency consistent with sibling routes. (rules/fastapi.md says "…")

   `https://github.com/owner/repo/blob/<full-sha>/path/to/file.py#L40-L44`

2. **Potential SQL injection via string format** *(skipped)* — User input passed directly to a raw query without parameterization.

   `https://github.com/owner/repo/blob/<full-sha>/path/to/file.py#L112-L115`

3. **Stale import left in file** *(skipped)* — `SomeClass` imported but no longer referenced after this change.

   `https://github.com/owner/repo/blob/<full-sha>/path/to/file.py#L3`

GitHub Diff: [claude/example-review-fixes](https://github.com/owner/repo/compare/main...claude/example-review-fixes?expand=1)

---

Or, if no issues were found:

---

### Code review

No issues found above the confidence bar. Checked for bugs and project rule compliance.

---

## Code Link Format

`https://github.com/owner/repo/blob/<full-sha>/path/to/file.py#L10-L15`

- Full git SHA required (not a branch name or `HEAD`)
- Commands like `$(git rev-parse HEAD)` will not work since the comment is rendered as Markdown
- `#` after the filename, then line range as `L[start]-L[end]`
- Provide at least 1 line of context before and after the relevant lines
