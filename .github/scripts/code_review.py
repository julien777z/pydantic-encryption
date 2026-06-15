import argparse
import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Final, TypedDict

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("code_review")

HUNK_HEADER: Final[re.Pattern[str]] = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
FENCE: Final[re.Pattern[str]] = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)
PRIOR_COMMENTS_LIMIT: Final[int] = 100
LOW_FINDINGS_CAP: Final[int] = 3


class ReviewConfig(TypedDict):
    routine_host: str
    anthropic_version: str
    routine_beta: str
    cursor_marker: str
    claude_marker: str
    cursor_status_context: str


CONFIG: Final[ReviewConfig] = ReviewConfig(
    routine_host="https://api.anthropic.com/v1/claude_code/routines",
    anthropic_version="2023-06-01",
    routine_beta="experimental-cc-routine-2026-04-01",
    cursor_marker="<!-- code-review:cursor -->",
    claude_marker="<!-- code-review:claude -->",
    cursor_status_context="code-review/cursor",
)


class Finding(TypedDict):
    path: str
    line: int
    side: str
    severity: str
    title: str
    body: str


class ReviewComment(TypedDict):
    path: str
    line: int
    side: str
    body: str


class ReviewPayload(TypedDict):
    commit_id: str
    event: str
    body: str
    comments: list[ReviewComment]


def run_gh(args: list[str], *, token: str) -> str:
    """Run a `gh` command with the given token and return stdout."""

    result = subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "GH_TOKEN": token},
    )

    return result.stdout


def current_head_sha(repo: str, pr_number: str, token: str) -> str:
    """Return the PR's current head SHA."""

    return run_gh(
        ["pr", "view", pr_number, "--repo", repo, "--json", "headRefOid", "--jq", ".headRefOid"],
        token=token,
    ).strip()


def already_reviewed(repo: str, pr_number: str, head_sha: str, token: str, marker: str) -> bool:
    """Return True if this tier already posted a review (carrying its marker) for the given head commit."""

    raw = run_gh(
        [
            "api",
            "--paginate",
            f"repos/{repo}/pulls/{pr_number}/reviews",
            "--jq",
            '.[] | select(.state != "PENDING" and .state != "DISMISSED" '
            f'and ((.body // "") | contains("{marker}"))) | .commit_id',
        ],
        token=token,
    )

    return head_sha in raw.split()


def head_reviewed(repo: str, head_sha: str, token: str) -> bool:
    """Return True if a successful Cursor review commit status is already recorded for this head."""

    raw = run_gh(
        [
            "api",
            f"repos/{repo}/commits/{head_sha}/statuses",
            "--jq",
            f'.[] | select(.context == "{CONFIG["cursor_status_context"]}") | .state',
        ],
        token=token,
    )

    return "success" in raw.split()


def mark_head_reviewed(repo: str, head_sha: str, token: str) -> None:
    """Record a successful Cursor review commit status so a later re-run of the same head can skip it."""

    try:
        run_gh(
            [
                "api",
                "--method",
                "POST",
                f"repos/{repo}/statuses/{head_sha}",
                "-f",
                "state=success",
                "-f",
                f"context={CONFIG['cursor_status_context']}",
                "-f",
                "description=Cursor code review complete",
            ],
            token=token,
        )
    except subprocess.CalledProcessError as exc:
        logger.warning("Could not record reviewed status for %s: %s", head_sha, exc.stderr.strip())


def resolve_stale_threads(
    repo: str,
    pr_number: str,
    head_sha: str,
    token: str,
    current_keys: set[tuple[str, str]],
    marker: str,
) -> None:
    """Resolve this tier's own outdated inline threads whose finding the current review dropped."""

    if current_head_sha(repo, pr_number, token) != head_sha:
        return

    owner, _, name = repo.partition("/")
    list_query = (
        "query($owner:String!,$name:String!,$number:Int!,$after:String){"
        "repository(owner:$owner,name:$name){pullRequest(number:$number){"
        "reviewThreads(first:100,after:$after){pageInfo{hasNextPage endCursor} "
        "nodes{id isResolved isOutdated "
        "comments(first:1){nodes{author{login} body path}}}}}}}"
    )

    threads = []
    after = None
    try:
        while True:
            args = [
                "api",
                "graphql",
                "-f",
                f"query={list_query}",
                "-f",
                f"owner={owner}",
                "-f",
                f"name={name}",
                "-F",
                f"number={pr_number}",
            ]
            if after is not None:
                args += ["-f", f"after={after}"]

            page = json.loads(run_gh(args, token=token))["data"]["repository"]["pullRequest"][
                "reviewThreads"
            ]
            threads.extend(page["nodes"])
            if not page["pageInfo"]["hasNextPage"]:
                break

            after = page["pageInfo"]["endCursor"]
    except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError, TypeError) as exc:
        logger.warning("Could not list all review threads to resolve; using what was fetched: %s", exc)

    resolve_mutation = "mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{id}}}"

    for thread in threads:
        try:
            if thread["isResolved"] or not thread["isOutdated"]:
                continue

            comment = next(iter(thread["comments"]["nodes"]), None)
            if comment is None:
                continue

            author = (comment["author"] or {}).get("login")
            body = comment.get("body") or ""
            if author not in ("github-actions", "github-actions[bot]") or marker not in body:
                continue

            title = next(
                (row[4:].strip() for row in body.splitlines() if row.startswith("### ")),
                None,
            )
            if title is None or (comment.get("path"), title) in current_keys:
                continue

            run_gh(
                ["api", "graphql", "-f", f"query={resolve_mutation}", "-f", f"id={thread['id']}"],
                token=token,
            )
        except (subprocess.CalledProcessError, KeyError, TypeError) as exc:
            logger.warning("Could not resolve a review thread: %s", exc)


def record_reviewed(
    repo: str,
    pr_number: str,
    head_sha: str,
    token: str,
    current_keys: set[tuple[str, str]],
    marker: str,
) -> None:
    """Resolve outdated threads for findings no longer raised, then record the reviewed status."""

    resolve_stale_threads(repo, pr_number, head_sha, token, current_keys, marker)
    mark_head_reviewed(repo, head_sha, token)


def posted_finding_keys(repo: str, pr_number: str, token: str) -> set[tuple[str, str]]:
    """Return (path, title) keys for inline review comments a bot already posted on this PR."""

    raw = run_gh(
        [
            "api",
            f"repos/{repo}/pulls/{pr_number}/comments"
            f"?per_page={PRIOR_COMMENTS_LIMIT}&sort=created&direction=desc",
            "--jq",
            '.[] | select(.user.type == "Bot") | {path, body}',
        ],
        token=token,
    )

    keys: set[tuple[str, str]] = set()

    for line in raw.splitlines():
        if not line.strip():
            continue

        entry = json.loads(line)
        title = next(
            (row[4:].strip() for row in (entry.get("body") or "").splitlines() if row.startswith("### ")),
            None,
        )
        if title:
            keys.add((entry["path"], title))

    return keys


def parse_patch(patch: str) -> tuple[set[int], set[int]]:
    """Return the (RIGHT new-side, LEFT old-side) line numbers a unified-diff patch exposes."""

    right: set[int] = set()
    left: set[int] = set()
    old_line = 0
    new_line = 0
    in_hunk = False

    for raw in patch.splitlines():
        header = HUNK_HEADER.match(raw)
        if header is not None:
            old_line = int(header.group(1))
            new_line = int(header.group(2))
            in_hunk = True

            continue

        if not in_hunk:
            # Ignore any `diff --git` / `---` / `+++` headers before the first hunk.
            continue

        if raw.startswith("+"):
            right.add(new_line)
            new_line += 1
        elif raw.startswith("-"):
            left.add(old_line)
            old_line += 1
        elif raw.startswith(" "):
            right.add(new_line)
            left.add(old_line)
            new_line += 1
            old_line += 1

    return right, left


def diff_anchors(
    repo: str, pr_number: str, token: str
) -> tuple[dict[str, tuple[set[int], set[int]]], set[str]]:
    """Map patched changed files to their (RIGHT, LEFT) anchor lines, plus changed files GitHub gave no patch for."""

    raw = run_gh(
        [
            "api",
            "--paginate",
            f"repos/{repo}/pulls/{pr_number}/files",
            "--jq",
            ".[] | {filename, patch}",
        ],
        token=token,
    )

    anchors: dict[str, tuple[set[int], set[int]]] = {}
    unpatched: set[str] = set()

    for line in raw.splitlines():
        if not line.strip():
            continue

        entry = json.loads(line)
        patch = entry.get("patch")
        if patch:
            anchors[entry["filename"]] = parse_patch(patch)
        else:
            unpatched.add(entry["filename"])

    return anchors, unpatched


def build_prompt(repo: str, pr_number: str, head_sha: str, diff: str) -> str:
    """Compose the review prompt: the skill reference, the PR context, and the strict JSON output contract."""

    return (
        "Follow your `code-review` skill to review the pull request below.\n"
        "You are a single agent running in CI: you have no sub-agents and no GitHub posting tools, "
        "so ignore any skill steps about launching parallel agents or posting via tools — the runner "
        "posts the review. Apply the skill's review lenses and severity bar to the diff yourself, "
        "then reply with ONLY a JSON object "
        "(no prose, no code fence) of the form:\n"
        '{"findings": [{"path": "<repo-relative>", "line": <int>, "side": "RIGHT|LEFT", '
        '"severity": "Critical|High|Medium|Low", "title": "<short>", "body": "<1-3 sentences>"}]}\n'
        "Use RIGHT with new-file line numbers for added/current lines and LEFT with base-file line "
        "numbers for removed lines. Only report findings on the diff's changed lines. Apply the "
        "skill's severity bar: post every Critical, High, and Medium finding, but at most the three "
        "most important Low findings. Order findings most-important-first. Return an empty "
        'list ({"findings": []}) when there are none.\n\n'
        f"Repository: {repo}\nPull request: #{pr_number}\nHead commit: {head_sha}\n\n"
        f"Unified diff:\n{diff}\n"
    )


def parse_findings(reply: str) -> list[Finding]:
    """Extract the deduplicated findings list from the agent's JSON reply."""

    text = reply.strip()
    fenced = FENCE.search(text)
    if fenced is not None:
        text = fenced.group(1)

    data = json.loads(text)
    if isinstance(data, dict):
        raw_findings = data.get("findings") or []
    elif isinstance(data, list):
        raw_findings = data
    else:
        raise ValueError(f"unexpected findings JSON root: {type(data).__name__}")

    seen: set[tuple[str, int, str, str]] = set()
    findings: list[Finding] = []

    for item in raw_findings:
        side = "LEFT" if str(item.get("side", "RIGHT")).upper() == "LEFT" else "RIGHT"
        title = str(item["title"])
        key = (str(item["path"]), int(item["line"]), side, title)
        if key in seen:
            continue

        seen.add(key)
        findings.append(
            {
                "path": key[0],
                "line": key[1],
                "side": side,
                "severity": str(item["severity"]),
                "title": title,
                "body": str(item["body"]),
            }
        )

    return findings


def cap_low_findings(findings: list[Finding]) -> list[Finding]:
    """Keep every Critical/High/Medium finding but at most LOW_FINDINGS_CAP Low ones, in order."""

    capped: list[Finding] = []
    low_count = 0

    for finding in findings:
        if finding["severity"].strip().lower() == "low":
            if low_count >= LOW_FINDINGS_CAP:
                continue

            low_count += 1

        capped.append(finding)

    return capped


def comment_body(finding: Finding) -> str:
    """Render one inline comment body in the shared severity format."""

    return (
        f"### {finding['title']}\n\n**{finding['severity']} Severity**\n\n{finding['body']}"
        f"\n\n{CONFIG['cursor_marker']}"
    )


def finding_anchors(finding: Finding, anchors: dict[str, tuple[set[int], set[int]]]) -> bool:
    """Return True if the finding's line is present on its diff side."""

    right, left = anchors.get(finding["path"], (set(), set()))

    return finding["line"] in (left if finding["side"] == "LEFT" else right)


def is_postable(
    finding: Finding, anchors: dict[str, tuple[set[int], set[int]]], unpatched: set[str]
) -> bool:
    """Return True if the finding can be posted: inline-anchorable, or on a changed file with no patch."""

    return finding_anchors(finding, anchors) or finding["path"] in unpatched


def build_review(
    head_sha: str, findings: list[Finding], anchors: dict[str, tuple[set[int], set[int]]]
) -> ReviewPayload:
    """Build one review: inline comments for anchorable findings, a summary list for the rest."""

    comments: list[ReviewComment] = []
    summary: list[str] = []

    for finding in findings:
        if finding_anchors(finding, anchors):
            comments.append(
                {
                    "path": finding["path"],
                    "line": finding["line"],
                    "side": finding["side"],
                    "body": comment_body(finding),
                }
            )
        else:
            # Callers only pass postable findings, so a non-anchorable one is on a changed file
            # that GitHub returned no patch for (too large) — surface it in the summary.
            summary.append(
                f"- {finding['path']}:{finding['line']} — {finding['severity']} — {finding['body']}"
            )

    count = len(findings)
    body = f"Found {count} issue{'s' if count != 1 else ''}."
    if summary:
        body = f"{body}\n\nOn files too large to anchor inline:\n" + "\n".join(summary)

    body = f"{body}\n\n{CONFIG['cursor_marker']}"

    return {"commit_id": head_sha, "event": "COMMENT", "body": body, "comments": comments}


def post_review(repo: str, pr_number: str, payload: ReviewPayload, token: str) -> bool:
    """Post the review (inline comments + summary) in one call; return False if GitHub rejects it."""

    process = subprocess.run(
        ["gh", "api", "--method", "POST", f"repos/{repo}/pulls/{pr_number}/reviews", "--input", "-"],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "GH_TOKEN": token},
    )

    if process.returncode != 0:
        logger.error("Review POST failed (%s): %s", process.returncode, process.stderr.strip())

        return False

    logger.info("Posted review: %s", process.stdout.strip())

    return True


def fire_claude_routine() -> int:
    """Fire the hosted Anthropic Claude review routine for the current PR."""

    repo = os.environ["REPO"]
    pr_number = os.environ["PR_NUMBER"]
    head_sha = os.environ["HEAD_SHA"]
    token = os.environ["GITHUB_TOKEN"]

    if already_reviewed(repo, pr_number, head_sha, token, CONFIG["claude_marker"]):
        logger.info("Head %s already reviewed by Claude; not firing the routine.", head_sha)

        return 0

    if current_head_sha(repo, pr_number, token) != head_sha:
        logger.info("Head moved since the event; not firing for superseded commit %s.", head_sha)

        return 0

    routine_id = os.environ["CLAUDE_REVIEW_ROUTINE_ID"]
    text = (
        f"Review pull request #{pr_number} ({os.environ['PR_URL']}) "
        f"in repo {repo}, on branch {os.environ['HEAD_REF']}, "
        f"opened by {os.environ['PR_AUTHOR']}, triggered by commit {head_sha}."
    )
    request = urllib.request.Request(
        f"{CONFIG['routine_host']}/{routine_id}/fire",
        data=json.dumps({"text": text}).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {os.environ['CLAUDE_REVIEW_ROUTINE_API_KEY']}",
            "anthropic-version": CONFIG["anthropic_version"],
            "anthropic-beta": CONFIG["routine_beta"],
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request) as response:
            logger.info("Fired Claude review routine (%s).", response.status)

        return 0
    except urllib.error.HTTPError as exc:
        logger.error("Routine fire failed (%s): %s", exc.code, exc.read().decode(errors="replace"))

        return 1


async def run_cursor_review() -> int:
    """Run the cheap Cursor (composer-2.5) review for one PR and post the result."""

    # cursor_sdk is a Cursor-only dependency, imported here so the Claude path need not install it.
    from cursor_sdk import AsyncAgent, AsyncClient, CloudAgentOptions, CursorAgentError

    repo = os.environ["REPO"]
    pr_number = os.environ["PR_NUMBER"]
    head_sha = os.environ["HEAD_SHA"]
    api_key = os.environ["CURSOR_API_KEY"]
    token = os.environ["GITHUB_TOKEN"]
    model = os.environ.get("CURSOR_AGENT_MODEL", "composer-2.5")

    if head_reviewed(repo, head_sha, token) or already_reviewed(
        repo, pr_number, head_sha, token, CONFIG["cursor_marker"]
    ):
        logger.info("Head %s already reviewed by Cursor; skipping.", head_sha)

        return 0

    diff = run_gh(["pr", "diff", pr_number, "--repo", repo], token=token)
    anchors, unpatched = diff_anchors(repo, pr_number, token)
    prompt = build_prompt(repo, pr_number, head_sha, diff)

    try:
        client = await AsyncClient.launch_bridge()
        agent = await AsyncAgent.create(client=client, model=model, api_key=api_key, cloud=CloudAgentOptions())

        try:
            run = await agent.send(prompt)
            reply = await run.text()
        finally:
            await agent.close()
    except CursorAgentError as exc:
        logger.error("Cursor agent run failed: %s", exc)

        return 1

    try:
        findings = parse_findings(reply)
    except (json.JSONDecodeError, AttributeError, KeyError, TypeError, ValueError) as exc:
        logger.error("Could not parse agent reply: %s", exc)

        return 1

    current_keys = {(finding["path"], finding["title"].strip()) for finding in findings}

    # Re-gate on the head SHA once the agent run is done (skill Step 5): if the head advanced
    # while the agent worked, neither post nor record a status for the superseded commit — the
    # next event reviews the new head.
    if current_head_sha(repo, pr_number, token) != head_sha:
        logger.info("Head moved during the agent run; skipping (the new commit reviews next).")

        return 0

    if not findings:
        logger.info("No findings; recording reviewed status without posting.")
        record_reviewed(repo, pr_number, head_sha, token, current_keys, CONFIG["cursor_marker"])

        return 0

    posted = posted_finding_keys(repo, pr_number, token)
    findings = [finding for finding in findings if (finding["path"], finding["title"].strip()) not in posted]

    findings = [finding for finding in findings if is_postable(finding, anchors, unpatched)]
    findings = cap_low_findings(findings)

    # Re-check the head before resolving stale threads or posting: it can move during the
    # prior-comment fetch, and acting on findings gathered against a superseded commit would
    # resolve threads using stale keys.
    if current_head_sha(repo, pr_number, token) != head_sha:
        logger.info("Head moved since the diff was loaded; skipping.")

        return 0

    if not findings:
        logger.info("No new in-scope findings to post; recording reviewed status.")
        record_reviewed(repo, pr_number, head_sha, token, current_keys, CONFIG["cursor_marker"])

        return 0

    if head_reviewed(repo, head_sha, token) or already_reviewed(
        repo, pr_number, head_sha, token, CONFIG["cursor_marker"]
    ):
        logger.info("Head %s reviewed by Cursor during the run; skipping.", head_sha)

        return 0

    payload = build_review(head_sha, findings, anchors)
    if not post_review(repo, pr_number, payload, token):
        return 1

    record_reviewed(repo, pr_number, head_sha, token, current_keys, CONFIG["cursor_marker"])

    return 0


def main() -> int:
    """Route a PR code review to the requested agent runner."""

    parser = argparse.ArgumentParser(description="Run a PR code review with the requested agent.")
    parser.add_argument("--agent", required=True, choices=["claude", "cursor"])
    args = parser.parse_args()

    match args.agent:
        case "claude":
            return fire_claude_routine()
        case "cursor":
            return asyncio.run(run_cursor_review())
        case _:
            parser.error(f"unsupported agent: {args.agent}")

            return 1


if __name__ == "__main__":
    sys.exit(main())
