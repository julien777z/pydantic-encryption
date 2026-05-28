#!/usr/bin/env bash
# SessionStart hook: record the starting HEAD SHA so simplify-on-stop can tell
# whether the session actually changed code (commits + pushes + clean tree at
# Stop time still mean work happened — HEAD moved).
#
# Best-effort: any failure is silent. The Stop hook falls back to dirty-tree
# detection when no start sentinel exists.

set -euo pipefail

input=$(cat)

session_id=$(
  printf '%s' "$input" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("session_id", ""))' \
    2>/dev/null \
  || echo ""
)

[ -z "$session_id" ] && exit 0

project_dir="${CLAUDE_PROJECT_DIR:-.}"

if command -v git >/dev/null 2>&1 \
   && git -C "$project_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  starting_head=$(git -C "$project_dir" rev-parse HEAD 2>/dev/null || echo "")
  if [ -n "$starting_head" ]; then
    sentinel="${TMPDIR:-/tmp}/simplify-on-stop-${session_id}.start"
    printf '%s\n' "$starting_head" > "$sentinel" 2>/dev/null || true
  fi
fi

exit 0
