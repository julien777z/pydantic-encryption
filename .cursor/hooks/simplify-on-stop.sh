#!/usr/bin/env bash
# Stop hook: ask the agent to run the code-simplify skill on the changes it is
# about to push, before each push. The agent decides whether the skill applies;
# if no code was modified it skips gracefully and stops.
#
# Loop prevention: `stop_hook_active` is true when Claude Code retries Stop after
# our block, so we exit clean on the retry and never block twice in a row. This
# is the documented guard against infinite Stop-hook loops, so no per-session
# lock is used — that keeps the nudge firing once per turn (every push) instead
# of only on the first stop of a session.

set -euo pipefail

input=$(cat)

is_active=$(printf '%s' "$input" | python3 -c \
  'import json,sys;print(str(json.load(sys.stdin).get("stop_hook_active",False)).lower())' \
  2>/dev/null || echo "true")

[ "$is_active" = "true" ] && exit 0

echo '{"decision":"block","reason":"Do not push yet. First call the Skill tool with skill=\"code-simplify\" (the project skill, NOT the built-in \"simplify\" skill) and walk it against the files you changed since your last push: check each against your rules and the skill defaults, and apply fixes — do not rubber-stamp with \"no changes needed\". Fold every edit the skill produces, correctness fix or cleanup alike, into the commit you are about to push, so each push already contains its own simplification pass. Do not push the simplifications as a separate follow-up commit. It is fine for a multi-turn session to produce several commits and pushes; the only rule is that code-simplify has run on the changes in a push before that push happens. If you modified no code at all, skip the skill and conclude."}'
