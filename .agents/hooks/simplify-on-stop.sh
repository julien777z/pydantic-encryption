#!/usr/bin/env bash
# Stop hook: when Claude finishes a turn after making code changes, remind it
# to run the simplify-code skill before stopping.
#
# Safeguards against runaway blocking:
# 1. Re-invocation flag: when Claude Code retries Stop with `stop_hook_active: true`,
#    exit 0. Canonical Claude Code pattern.
# 2. Session lock: belt-and-suspenders on top of (1), in case `stop_hook_active`
#    fails to propagate (anthropics/claude-code#54360). We allow at most one block
#    per `session_id` per machine via a /tmp lock file.
# 3. Parse failure: default to allowing stop. Blocking on error would create the
#    loop we're trying to avoid.
# 4. No session work: skip the block when nothing changed during the session —
#    pure Q&A / planning sessions should not be interrupted. "Did work" means
#    HEAD moved since SessionStart (so commits/pushes count) OR the tree is
#    currently dirty. Falls back to dirty-only when no start sentinel exists.

set -euo pipefail

input=$(cat)

is_active=$(
  printf '%s' "$input" \
    | python3 -c 'import json,sys; print(str(json.load(sys.stdin).get("stop_hook_active", False)).lower())' \
    2>/dev/null \
  || echo "true"
)
session_id=$(
  printf '%s' "$input" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("session_id", ""))' \
    2>/dev/null \
  || echo ""
)

if [ "$is_active" = "true" ]; then
  exit 0
fi

lock=""
if [ -n "$session_id" ]; then
  lock="${TMPDIR:-/tmp}/simplify-on-stop-${session_id}.lock"
  if [ -e "$lock" ]; then
    exit 0
  fi
fi

project_dir="${CLAUDE_PROJECT_DIR:-.}"
session_did_work=true

if command -v git >/dev/null 2>&1 \
   && git -C "$project_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  session_did_work=false

  if [ -n "$(git -C "$project_dir" status --porcelain 2>/dev/null)" ]; then
    session_did_work=true
  fi

  if [ "$session_did_work" = "false" ] && [ -n "$session_id" ]; then
    start_sentinel="${TMPDIR:-/tmp}/simplify-on-stop-${session_id}.start"
    if [ -f "$start_sentinel" ]; then
      starting_head=$(cat "$start_sentinel" 2>/dev/null || echo "")
      current_head=$(git -C "$project_dir" rev-parse HEAD 2>/dev/null || echo "")
      if [ -n "$starting_head" ] && [ -n "$current_head" ] \
         && [ "$starting_head" != "$current_head" ]; then
        session_did_work=true
      fi
    fi
  fi
fi

if [ "$session_did_work" = "false" ]; then
  exit 0
fi

if [ -n "$lock" ]; then
  : > "$lock" 2>/dev/null || true
fi

cat <<'JSON'
{"decision": "block", "reason": "Before stopping, invoke the simplify-code skill in default/session mode to review and refine the code you modified during this session. Apply project standards (see .agents/rules/ or .claude/rules/ if present), preserve behavior, and then conclude."}
JSON
