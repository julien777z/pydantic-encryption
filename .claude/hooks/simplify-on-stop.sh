#!/usr/bin/env bash
# Stop hook: when Claude finishes a turn, remind it to run the simplify-code skill.
#
# Safeguards against runaway blocking:
# 1. Re-invocation flag: when Claude Code retries Stop with `stop_hook_active: true`,
#    exit 0. Canonical Claude Code pattern.
# 2. Session sentinel: belt-and-suspenders on top of (1), in case `stop_hook_active`
#    fails to propagate (anthropics/claude-code#54360). We allow at most one block
#    per `session_id` per machine via a /tmp lock file.
# 3. Parse failure: default to allowing stop. Blocking on error would create the
#    loop we're trying to avoid.
# 4. Clean working tree: if there are no modified files, there is nothing to
#    simplify — skip the block so pure Q&A / planning sessions are not interrupted.

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

sentinel=""
if [ -n "$session_id" ]; then
  sentinel="${TMPDIR:-/tmp}/simplify-on-stop-${session_id}.lock"
  if [ -e "$sentinel" ]; then
    exit 0
  fi
fi

project_dir="${CLAUDE_PROJECT_DIR:-.}"
if command -v git >/dev/null 2>&1 \
   && git -C "$project_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
   && [ -z "$(git -C "$project_dir" status --porcelain 2>/dev/null)" ]; then
  exit 0
fi

if [ -n "$sentinel" ]; then
  : > "$sentinel" 2>/dev/null || true
fi

cat <<'JSON'
{"decision": "block", "reason": "Before stopping, invoke the simplify-code skill in default/session mode to review and refine the code you modified during this session. Apply project standards (see .agents/rules/ or .claude/rules/ if present), preserve behavior, and then conclude."}
JSON
