#!/usr/bin/env bash
# Stop hook: block exactly once per session and ask the agent to invoke the
# code-simplify skill. The agent decides whether the skill applies; if no
# code was modified it skips gracefully and stops.
#
# Loop prevention:
# 1. `stop_hook_active`: when Claude Code retries Stop after our block,
#    this flag is true — exit clean.
# 2. /tmp lock keyed by session_id: belt-and-suspenders for the case where
#    `stop_hook_active` fails to propagate (anthropics/claude-code#54360).

set -euo pipefail

input=$(cat)

is_active=$(printf '%s' "$input" | python3 -c \
  'import json,sys;print(str(json.load(sys.stdin).get("stop_hook_active",False)).lower())' \
  2>/dev/null || echo "true")

session_id=$(printf '%s' "$input" | python3 -c \
  'import json,sys;print(json.load(sys.stdin).get("session_id",""))' \
  2>/dev/null || echo "")

[ "$is_active" = "true" ] && exit 0

if [ -n "$session_id" ]; then
  lock="${TMPDIR:-/tmp}/simplify-on-stop-${session_id}.lock"
  [ -e "$lock" ] && exit 0
  : > "$lock" 2>/dev/null || true
fi

echo '{"decision":"block","reason":"Before stopping, invoke the code-simplify skill to review the code you modified this session. If no code was modified, skip the skill and conclude."}'
