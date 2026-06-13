#!/usr/bin/env bash
# Stop hook: nudge the agent to run claude-review and code-simplify over the
# whole branch diff as a local pre-push pass. A stamp of HEAD + working-tree
# content in the git dir limits the nudge to once per branch state — gating on
# unpushed work would never fire in remote sessions, which push within the same
# turn. `stop_hook_active` stops a second block in one stop cycle; if it cannot
# be read, treat it as active — a skipped nudge beats an infinite Stop loop.

set -euo pipefail

input=$(cat)

command -v python3 >/dev/null 2>&1 || exit 0

is_active=$(printf '%s' "$input" | python3 -c \
  'import json,sys;print(str(json.load(sys.stdin).get("stop_hook_active",False)).lower())' \
  2>/dev/null || echo "true")

[ "$is_active" = "true" ] && exit 0

# Outside a git work tree there is nothing to push or diff, so let Stop complete.
git_dir=$(git rev-parse --git-dir 2>/dev/null) || exit 0

# State = HEAD plus a hash of the actual working-tree content (tracked diff and
# untracked file contents), so re-editing an already-modified file changes the
# stamp and the pre-push pass fires again instead of matching a stale stamp.
head_sha=$(git rev-parse HEAD 2>/dev/null || echo "no-head")
porcelain=$(git status --porcelain --untracked-files=normal 2>/dev/null || echo "status-error")
dirty_sha=$(
  {
    git diff HEAD 2>/dev/null || true
    git ls-files --others --exclude-standard -z 2>/dev/null \
      | xargs -0 -r git hash-object 2>/dev/null || true
  } | git hash-object --stdin 2>/dev/null || echo "hash-error"
)
state="$head_sha:$dirty_sha"

stamp_file="$git_dir/simplify-on-stop.stamp"
[ -f "$stamp_file" ] && [ "$(cat "$stamp_file")" = "$state" ] && exit 0

# Clean tree with no diff over the remote default branch means nothing to
# review. Resolve the default via origin/HEAD, then fall back to whichever of
# origin/main or origin/master exists; a missing ref or git error falls through
# and still nudges.
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

echo '{"decision":"block","reason":"Run a LOCAL pre-push pass over the WHOLE branch diff versus the base branch, including uncommitted work — no GitHub PR required. First call the Skill tool with skill=\"claude-review\" in local mode and apply the real fixes directly (no PR, no asking, no branching off, no comment). Then call skill=\"code-simplify\" (the project skill, NOT the built-in \"simplify\") over the same diff and apply its simplifications. Commit the edits from both skills, and push them if the branch was already pushed. If the branch has no code changes, skip both skills and conclude."}'
