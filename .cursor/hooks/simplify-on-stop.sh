#!/usr/bin/env bash
# Stop hook: before each push, ask the agent to run two project skills over the
# whole branch diff — first code review, then simplification — and fold the fixes
# into the push. The agent decides whether the skills apply; if the branch has no
# changes it skips gracefully and stops.
#
# Loop prevention: `stop_hook_active` is true when Claude Code retries Stop after
# our block; exit clean then so we never block twice. Without python3 we cannot
# read that flag, so skip rather than risk an infinite Stop-hook loop. A malformed
# payload while python3 is present is not a retry (the retry always carries
# stop_hook_active=true as valid JSON), so fall through and still emit the nudge.

set -euo pipefail

input=$(cat)

command -v python3 >/dev/null 2>&1 || exit 0

is_active=$(printf '%s' "$input" | python3 -c \
  'import json,sys;print(str(json.load(sys.stdin).get("stop_hook_active",False)).lower())' \
  2>/dev/null || echo "false")

[ "$is_active" = "true" ] && exit 0

# Only nudge when something is actually about to be pushed. If the working tree
# is clean and HEAD is not ahead of an existing upstream, there is nothing to
# review or simplify before a push (e.g. the branch is already pushed/merged, or
# the session only answered a question), so skip. A branch with no upstream yet,
# or any git error, falls through and still gets nudged.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  && [ -z "$(git status --porcelain 2>/dev/null)" ] \
  && git rev-parse --verify --quiet '@{u}' >/dev/null 2>&1; then
  ahead=$(git rev-list --count '@{u}..HEAD' 2>/dev/null || echo "x")
  [ "$ahead" = "0" ] && exit 0
fi

echo '{"decision":"block","reason":"Before pushing, run two project skills over the WHOLE branch diff (every change versus the base branch, not just this session). First, call the Skill tool with skill=\"claude-review\" and review the entire branch diff, then fix the real issues it surfaces (pre-existing issues in the touched files are in scope too). Second, call the Skill tool with skill=\"code-simplify\" (the project skill, NOT the built-in \"simplify\") and walk it against the whole branch diff, applying its fixes — do not rubber-stamp \"no changes needed\". Fold every edit from both skills into the commit you are about to push; do not split them into a separate follow-up commit. If the branch has no code changes, skip both skills and conclude."}'
