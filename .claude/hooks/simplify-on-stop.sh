#!/usr/bin/env bash
# Stop hook: once per branch, nudge the agent to run claude-review and
# code-simplify over the whole branch diff as a local pre-push pass — then stay
# quiet. After a branch has been nudged once, later stops on it (the review
# pass's own commit, CI-fix follow-ups, further tweaks) do NOT re-run the pass.
# `stop_hook_active` guards the immediate continuation; a per-branch record in
# the git dir guards every stop after that. If the active flag cannot be read,
# treat it as active — a skipped nudge beats an infinite Stop loop.

set -euo pipefail

input=$(cat)

command -v python3 >/dev/null 2>&1 || exit 0

is_active=$(printf '%s' "$input" | python3 -c \
  'import json,sys;print(str(json.load(sys.stdin).get("stop_hook_active",False)).lower())' \
  2>/dev/null || echo "true")

[ "$is_active" = "true" ] && exit 0

# Outside a git work tree (a bare repo has none) there is nothing to push or
# diff, so let Stop complete. Check the work tree first, then take the git dir.
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0
git_dir=$(git rev-parse --git-dir 2>/dev/null) || exit 0

# Key the once-per-branch record by branch name, or by HEAD sha when detached.
branch_key=$(git symbolic-ref --quiet --short HEAD 2>/dev/null \
  || git rev-parse HEAD 2>/dev/null || echo "")
[ -n "$branch_key" ] || exit 0

# Already nudged this branch — do not re-run the pass for the review's own
# commit, a CI-fix follow-up push, or any later work on the same branch.
nudged_file="$git_dir/simplify-on-stop.nudged"
if [ -f "$nudged_file" ] && grep -qxF "$branch_key" "$nudged_file" 2>/dev/null; then
  exit 0
fi

# Nothing to review when the tree is clean and HEAD has no diff over the remote
# default branch. An unreadable status falls back to a non-empty sentinel so it
# is treated as "maybe dirty" and still nudges, rather than silently skipping.
# Resolve the default via origin/HEAD, then fall back to whichever of
# origin/main or origin/master exists; a missing ref or git error falls through
# and still nudges.
porcelain=$(git status --porcelain --untracked-files=normal 2>/dev/null || echo "status-error")
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

# Record this branch as nudged before blocking, so the pass runs exactly once.
printf '%s\n' "$branch_key" >> "$nudged_file"

echo '{"decision":"block","reason":"Run a LOCAL pre-push pass over the WHOLE branch diff versus the base branch, including uncommitted work — no GitHub PR required. First call the Skill tool with skill=\"claude-review\" in local mode and apply the real fixes directly (no PR, no asking, no branching off, no comment). Then call skill=\"code-simplify\" (the project skill, NOT the built-in \"simplify\") over the same diff and apply its simplifications. Commit the edits from both skills, and push them if the branch was already pushed. If the branch has no code changes, skip both skills and conclude."}'
