#!/usr/bin/env bash
# Stop hook: when Claude finishes a turn, remind it to run the simplify-code skill.
#
# Recursion safety: Claude Code sets `stop_hook_active: true` in the hook input
# JSON when it re-invokes Stop hooks after a previous block. We exit 0 in that
# case so Claude can actually stop — this is the canonical pattern documented
# by Claude Code for preventing infinite Stop-hook loops.

set -euo pipefail

input=$(cat)

is_active=$(
  printf '%s' "$input" \
    | python3 -c 'import json,sys; print(str(json.load(sys.stdin).get("stop_hook_active", False)).lower())' \
    2>/dev/null \
  || echo "false"
)

if [ "$is_active" = "true" ]; then
  exit 0
fi

cat <<'JSON'
{"decision": "block", "reason": "Before stopping, invoke the simplify-code skill in default/session mode to review and refine the code you modified during this session. Apply project standards (see .agents/rules/ or .claude/rules/ if present), preserve behavior, and then conclude."}
JSON
