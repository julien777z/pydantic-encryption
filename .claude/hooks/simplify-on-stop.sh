#!/usr/bin/env bash
# Stop hook: before each push, ask the agent to run two project skills over the
# whole branch diff as a local pre-push pass — first code review, then
# simplification — and fold the fixes into the push. The agent decides whether
# the skills apply; if the branch has no changes it skips gracefully and stops.
#
# Loop prevention: `stop_hook_active` is true when Claude Code retries Stop after
# our block; exit clean then so we never block twice. If that flag cannot be read
# (no python3, or an unreadable payload), treat it as active and exit clean —
# skipping a single nudge is acceptable, an infinite Stop-hook loop is not.

set -euo pipefail

input=$(cat)

command -v python3 >/dev/null 2>&1 || exit 0

is_active=$(printf '%s' "$input" | python3 -c \
  'import json,sys;print(str(json.load(sys.stdin).get("stop_hook_active",False)).lower())' \
  2>/dev/null || echo "true")

[ "$is_active" = "true" ] && exit 0

# Outside a git work tree there is nothing to push or diff, so let Stop complete.
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0

# Only nudge when something is actually about to be pushed. If the working tree
# is clean and HEAD is not ahead of an existing upstream, there is nothing to
# review or simplify before a push (e.g. the branch is already pushed/merged, or
# the session only answered a question), so skip. A branch with no upstream yet,
# or any git error, falls through and still gets nudged.
if [ -z "$(git status --porcelain 2>/dev/null)" ] \
  && git rev-parse --verify --quiet '@{u}' >/dev/null 2>&1; then
  ahead=$(git rev-list --count '@{u}..HEAD' 2>/dev/null || echo "x")
  [ "$ahead" = "0" ] && exit 0
fi

echo '{"decision":"block","reason":"Before pushing, run two project skills over the WHOLE branch diff (every change versus the base branch, including uncommitted work — not just this session) as a LOCAL pre-push pass — no GitHub PR is required. First, call the Skill tool with skill=\"claude-review\" in its local / pre-push mode: review the whole branch diff and apply the real fixes it surfaces directly (pre-existing issues in the touched files are in scope); for this pass do not open or require a PR, do not ask before fixing, do not branch off, and do not post a comment. Second, call skill=\"code-simplify\" (the project skill, NOT the built-in \"simplify\") over the same branch diff and apply its simplifications. Fold every edit from both skills into the commit you are about to push — do not rubber-stamp \"no changes needed\" or split them into a separate follow-up commit. If the branch has no code changes, skip both skills and conclude."}'
