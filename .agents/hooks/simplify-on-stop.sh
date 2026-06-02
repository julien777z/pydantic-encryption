#!/usr/bin/env bash
# Stop hook: before each push, ask the agent to run the code-simplify skill over
# the files it changed this session. The agent decides whether the skill
# applies; if it changed nothing it skips gracefully and stops.
#
# Loop prevention: `stop_hook_active` is true when Claude Code retries Stop after
# our block. Checking it first and exiting clean is the documented way to avoid
# an infinite Stop-hook loop — when set, we must not block again.

set -euo pipefail

input=$(cat)

is_active=$(printf '%s' "$input" | python3 -c \
  'import json,sys;print(str(json.load(sys.stdin).get("stop_hook_active",False)).lower())' \
  2>/dev/null || echo "true")

[ "$is_active" = "true" ] && exit 0

# Only nudge when something is actually about to be pushed. If the working tree
# is clean and HEAD is not ahead of an existing upstream, there is nothing to
# simplify before a push (e.g. the branch is already pushed/merged, or the
# session only answered a question), so skip. A branch with no upstream yet, or
# any git error, falls through and still gets nudged.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  && [ -z "$(git status --porcelain 2>/dev/null)" ] \
  && git rev-parse --verify --quiet '@{u}' >/dev/null 2>&1; then
  ahead=$(git rev-list --count '@{u}..HEAD' 2>/dev/null || echo "x")
  [ "$ahead" = "0" ] && exit 0
fi

echo '{"decision":"block","reason":"Before pushing, call the Skill tool with skill=\"code-simplify\" (the project skill, not the built-in \"simplify\") and run it over the files you changed this session — not the whole branch diff. Fold its fixes into the commit you are about to push; do not rubber-stamp \"no changes needed\" or split them into a separate follow-up commit. If you changed no code, skip and conclude."}'
