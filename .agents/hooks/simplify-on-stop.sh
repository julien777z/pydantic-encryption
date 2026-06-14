#!/usr/bin/env bash
# Stop hook: nudge the agent to run code-simplify over the branch diff before a
# push. A HEAD + working-tree stamp fires once per branch state; stop_hook_active
# (or an unreadable flag) exits clean to avoid a second block / infinite loop.

set -euo pipefail

input=$(cat)

command -v python3 >/dev/null 2>&1 || exit 0

is_active=$(printf '%s' "$input" | python3 -c \
  'import json,sys;print(str(json.load(sys.stdin).get("stop_hook_active",False)).lower())' \
  2>/dev/null || echo "true")

[ "$is_active" = "true" ] && exit 0

# Nothing to push or diff outside a work tree (a bare repo has none).
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0
git_dir=$(git rev-parse --git-dir 2>/dev/null) || exit 0

# State = HEAD + working-tree content (binary-safe diff plus untracked blobs), so
# any content change re-fires. An unreadable status stays non-empty to nudge.
head_sha=$(git rev-parse HEAD 2>/dev/null || echo "no-head")
porcelain=$(git status --porcelain --untracked-files=normal 2>/dev/null || echo "status-error")
dirty_sha=$(
  {
    git diff --binary HEAD 2>/dev/null || true
    git ls-files --others --exclude-standard -z 2>/dev/null \
      | while IFS= read -r -d '' file; do
          printf '%s\0' "$file"
          git hash-object "$file" 2>/dev/null || true
        done
  } | git hash-object --stdin 2>/dev/null || echo "hash-error"
)
state="$head_sha:$dirty_sha"

stamp_file="$git_dir/simplify-on-stop.stamp"
[ -f "$stamp_file" ] && [ "$(cat "$stamp_file")" = "$state" ] && exit 0

# Skip a clean tree with no diff over the remote default (origin/HEAD, else
# origin/main or origin/master); a missing ref or git error falls through.
if [ -z "$porcelain" ]; then
  default_ref=$(git symbolic-ref --quiet refs/remotes/origin/HEAD 2>/dev/null || echo "")
  if [ -z "$default_ref" ]; then
    for cand in refs/remotes/origin/main refs/remotes/origin/master; do
      git rev-parse --verify --quiet "$cand" >/dev/null 2>&1 && { default_ref="$cand"; break; }
    done
  fi
  if [ -n "$default_ref" ]; then
    base=$(git merge-base "$default_ref" HEAD 2>/dev/null || echo "")
    if [ -n "$base" ] && git diff --quiet "$base" HEAD 2>/dev/null; then
      exit 0
    fi
  fi
fi

printf '%s' "$state" > "$stamp_file"

echo '{"decision":"block","reason":"Run a LOCAL pre-push pass over the WHOLE branch diff versus the base branch, including uncommitted work — no GitHub PR required. Call the Skill tool with skill=\"code-simplify\" (the project skill, NOT the built-in \"simplify\") over that diff and apply its simplifications directly (no PR, no asking, no branching off, no comment). Commit the edits, and push them if the branch was already pushed. If the branch has no code changes, skip the skill and conclude."}'
