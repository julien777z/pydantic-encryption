#!/usr/bin/env bash
# Stop hook: before each push, ask the agent to run the code-simplify skill on
# the changes it is about to push. The agent decides whether the skill applies;
# if no code was modified it skips gracefully and stops.
#
# Loop prevention (two independent guards):
# 1. `stop_hook_active`: true when Claude Code retries Stop right after our
#    block, so we exit clean. This is the primary, per-turn guard — each new
#    turn is nudged once and its retry passes straight through.
# 2. Per-session block counter as a circuit breaker: if `stop_hook_active` ever
#    fails to propagate on the retry (anthropics/claude-code#54360), the counter
#    still caps how many times we block in one session, so the session can never
#    wedge in an unbounded block loop. The cap is high enough that normal
#    multi-push sessions keep getting nudged on every push.

set -euo pipefail

MAX_BLOCKS_PER_SESSION=25

input=$(cat)

is_active=$(printf '%s' "$input" | python3 -c \
  'import json,sys;print(str(json.load(sys.stdin).get("stop_hook_active",False)).lower())' \
  2>/dev/null || echo "true")

[ "$is_active" = "true" ] && exit 0

session_id=$(printf '%s' "$input" | python3 -c \
  'import json,sys;v=json.load(sys.stdin).get("session_id");print(v if isinstance(v,str) else "")' \
  2>/dev/null || echo "")

# We can only bound the number of blocks with a session_id and a writable
# counter. If either is unavailable, exit clean rather than risk an unbounded
# block loop should stop_hook_active fail to propagate.
[ -z "$session_id" ] && exit 0

counter="${TMPDIR:-/tmp}/simplify-on-stop-${session_id}.count"

# A missing counter means this is the first block; an existing-but-unreadable
# counter means we cannot trust the cap, so exit clean rather than reset to 0
# and risk looping.
if [ -e "$counter" ]; then
  count=$(cat "$counter" 2>/dev/null) || exit 0
  case "$count" in ''|*[!0-9]*) exit 0 ;; esac
else
  count=0
fi

[ "$count" -ge "$MAX_BLOCKS_PER_SESSION" ] && exit 0

printf '%s' "$((count + 1))" > "$counter" 2>/dev/null || exit 0

echo '{"decision":"block","reason":"Do not push yet. First call the Skill tool with skill=\"code-simplify\" (the project skill, NOT the built-in \"simplify\" skill) and walk it against the whole branch diff (every change versus the base branch, not just this session): check each touched file against your rules and the skill defaults, and apply fixes — do not rubber-stamp with \"no changes needed\". Fold every edit the skill produces, correctness fix or cleanup alike, into the commit you are about to push, so each push already contains its own simplification pass. Do not push the simplifications as a separate follow-up commit. It is fine for a multi-turn session to produce several commits and pushes; the only rule is that code-simplify has run over the branch diff before a push happens. If the branch has no code changes, skip the skill and conclude."}'
