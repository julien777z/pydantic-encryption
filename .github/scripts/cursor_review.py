import asyncio
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Final, TypedDict

from cursor_sdk import AsyncAgent, AsyncClient, CloudAgentOptions, CursorAgentError

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("cursor_review")

SKILL_PATH: Final[Path] = Path(".cursor/skills/claude-review/SKILL.md")
HUNK_HEADER: Final[re.Pattern[str]] = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
FENCE: Final[re.Pattern[str]] = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)


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


def already_reviewed(repo: str, pr_number: str, head_sha: str, token: str) -> bool:
    """Return True if this runner's bot already reviewed the given head commit (skill Step 1d)."""

    raw = run_gh(
        [
            "api",
            "--paginate",
            f"repos/{repo}/pulls/{pr_number}/reviews",
            "--jq",
            '.[] | select(.user.login == "github-actions[bot]" and .state != "PENDING" '
            'and .state != "DISMISSED") | .commit_id',
        ],
        token=token,
    )

    return head_sha in raw.split()


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


def diff_anchors(repo: str, pr_number: str, token: str) -> dict[str, tuple[set[int], set[int]]]:
    """Map each changed file path to its valid (RIGHT, LEFT) inline-comment line numbers."""

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

    for line in raw.splitlines():
        if not line.strip():
            continue

        entry = json.loads(line)
        patch = entry.get("patch")
        if patch:
            anchors[entry["filename"]] = parse_patch(patch)

    return anchors


def build_prompt(skill_text: str, repo: str, pr_number: str, head_sha: str, diff: str) -> str:
    """Compose the review prompt: the skill, the PR context, and the strict JSON output contract."""

    return (
        f"{skill_text}\n\n"
        "---\n"
        "You are running as a Cursor agent inside CI. Do NOT post anything yourself; "
        "the runner posts the review. Review the pull request below following the skill, "
        "then reply with ONLY a JSON object (no prose, no code fence) of the form:\n"
        '{"findings": [{"path": "<repo-relative>", "line": <int>, "side": "RIGHT|LEFT", '
        '"severity": "Critical|High|Medium|Low", "title": "<short>", "body": "<1-3 sentences>"}]}\n'
        "Use RIGHT with new-file line numbers for added/current lines and LEFT with base-file "
        "line numbers for removed lines. Surface every valid finding rated by severity; return "
        'an empty list ({"findings": []}) when there are none.\n\n'
        f"Repository: {repo}\nPull request: #{pr_number}\nHead commit: {head_sha}\n\n"
        f"Unified diff:\n{diff}\n"
    )


async def run_agent(prompt: str, model: str, api_key: str) -> str:
    """Run a single Cursor cloud agent to completion and return its text reply."""

    client = await AsyncClient.launch_bridge()
    agent = await AsyncAgent.create(
        client=client,
        model=model,
        api_key=api_key,
        cloud=CloudAgentOptions(),
    )

    try:
        run = await agent.send(prompt)

        return await run.text()
    finally:
        await agent.close()


def parse_findings(reply: str) -> list[Finding]:
    """Extract the findings list from the agent's JSON reply."""

    text = reply.strip()
    fenced = FENCE.search(text)
    if fenced is not None:
        text = fenced.group(1)

    data = json.loads(text)
    if not isinstance(data, dict):
        return []

    return [
        {
            "path": str(item["path"]),
            "line": int(item["line"]),
            "side": "LEFT" if str(item.get("side", "RIGHT")).upper() == "LEFT" else "RIGHT",
            "severity": str(item["severity"]),
            "title": str(item["title"]),
            "body": str(item["body"]),
        }
        for item in (data.get("findings") or [])
    ]


def comment_body(finding: Finding) -> str:
    """Render one inline comment body in the shared severity format."""

    return f"### {finding['title']}\n\n**{finding['severity']} Severity**\n\n{finding['body']}"


def build_review(
    head_sha: str,
    findings: list[Finding],
    anchors: dict[str, tuple[set[int], set[int]]],
) -> ReviewPayload:
    """Split findings into on-diff inline comments and an off-diff summary list, validated against the diff."""

    comments: list[ReviewComment] = []
    off_diff: list[str] = []

    for finding in findings:
        right, left = anchors.get(finding["path"], (set(), set()))
        valid = finding["line"] in (left if finding["side"] == "LEFT" else right)

        if valid:
            comments.append(
                {
                    "path": finding["path"],
                    "line": finding["line"],
                    "side": finding["side"],
                    "body": comment_body(finding),
                }
            )
        else:
            off_diff.append(
                f"- {finding['path']}:{finding['line']} — {finding['severity']} — {finding['body']}"
            )

    count = len(findings)
    body = f"Found {count} issue{'s' if count != 1 else ''}." if count else "No issues found."
    if off_diff:
        body = f"{body}\n\nOutside the diff:\n" + "\n".join(off_diff)

    return {"commit_id": head_sha, "event": "COMMENT", "body": body, "comments": comments}


def post_review(repo: str, pr_number: str, payload: ReviewPayload, token: str) -> bool:
    """Post the review; on a validation failure, retry with the summary only so it still lands."""

    def submit(body: ReviewPayload) -> str:
        process = subprocess.run(
            ["gh", "api", "--method", "POST", f"repos/{repo}/pulls/{pr_number}/reviews", "--input", "-"],
            input=json.dumps(body),
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "GH_TOKEN": token},
        )

        return process.stdout.strip()

    try:
        logger.info("Posted review: %s", submit(payload))

        return True
    except subprocess.CalledProcessError as exc:
        logger.warning("Review POST failed (%s); retrying without inline anchors: %s", exc.returncode, exc.stderr.strip())

    # The first attempt rejected an inline anchor, so drop anchors but keep every
    # finding's text by folding the inline comments into the body — none are lost.
    folded = "\n\n".join(
        f"**{entry['path']}:{entry['line']}**\n\n{entry['body']}" for entry in payload["comments"]
    )
    body = payload["body"]
    if folded:
        body = f"{body}\n\nInline findings (could not anchor):\n\n{folded}"

    fallback: ReviewPayload = {**payload, "body": body, "comments": []}

    try:
        logger.info("Posted review (no inline anchors): %s", submit(fallback))

        return True
    except subprocess.CalledProcessError as exc:
        logger.error("Review POST failed again (%s): %s", exc.returncode, exc.stderr.strip())

        return False


async def main() -> int:
    """Run the Cursor review for one PR synchronize event and post the result."""

    repo = os.environ["REPO"]
    pr_number = os.environ["PR_NUMBER"]
    head_sha = os.environ["HEAD_SHA"]
    api_key = os.environ["CURSOR_API_KEY"]
    token = os.environ["GITHUB_TOKEN"]
    model = os.environ.get("CURSOR_AGENT_MODEL", "composer-2.5")

    if not SKILL_PATH.exists():
        logger.error("Skill not found at %s", SKILL_PATH)

        return 1

    if already_reviewed(repo, pr_number, head_sha, token):
        logger.info("Head %s already reviewed by the bot; skipping.", head_sha)

        return 0

    skill_text = SKILL_PATH.read_text(encoding="utf-8")
    diff = run_gh(["pr", "diff", pr_number, "--repo", repo], token=token)
    anchors = diff_anchors(repo, pr_number, token)

    prompt = build_prompt(skill_text, repo, pr_number, head_sha, diff)

    try:
        reply = await run_agent(prompt, model, api_key)
    except CursorAgentError as exc:
        logger.error("Cursor agent run failed: %s", exc)

        return 1

    try:
        findings = parse_findings(reply)
    except (json.JSONDecodeError, AttributeError, KeyError, TypeError, ValueError) as exc:
        logger.error("Could not parse agent reply: %s", exc)

        return 1

    # Re-gate before posting (skill Step 5): if the PR advanced during the run the diff
    # and findings are stale, and if another run already reviewed this head, do not double-post.
    if current_head_sha(repo, pr_number, token) != head_sha:
        logger.info("Head moved since the diff was loaded; skipping post.")

        return 0

    if already_reviewed(repo, pr_number, head_sha, token):
        logger.info("Head %s reviewed by the bot during the run; skipping.", head_sha)

        return 0

    payload = build_review(head_sha, findings, anchors)
    if not post_review(repo, pr_number, payload, token):
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
