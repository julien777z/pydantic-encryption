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
#    If we can't establish a lock (missing session_id, unwritable tmp),
#    exit clean rather than risk an infinite block loop.

set -euo pipefail

input=$(cat)

is_active=$(printf '%s' "$input" | python3 -c \
  'import json,sys;print(str(json.load(sys.stdin).get("stop_hook_active",False)).lower())' \
  2>/dev/null || echo "true")

session_id=$(printf '%s' "$input" | python3 -c \
  'import json,sys;v=json.load(sys.stdin).get("session_id");print(v if isinstance(v,str) else "")' \
  2>/dev/null || echo "")

[ "$is_active" = "true" ] && exit 0

# Require session_id + writable lock; otherwise exit clean to avoid loops.
[ -z "$session_id" ] && exit 0

lock="${TMPDIR:-/tmp}/simplify-on-stop-${session_id}.lock"
[ -e "$lock" ] && exit 0
# Establish the lock first. If /tmp is unwritable we exit clean rather than risk
# unbounded blocking on every retry. (A failed echo afterward could only lose
# the nudge for this session, which is strictly better than looping.)
: > "$lock" 2>/dev/null || exit 0

echo '{"decision":"block","reason":"Before stopping, call the Skill tool with skill=\"code-simplify\" (the project skill, NOT the built-in \"simplify\" skill) to review code you modified this session. If you modified no code, skip the skill and conclude."}'
