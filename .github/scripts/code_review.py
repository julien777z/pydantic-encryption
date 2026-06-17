import argparse
import asyncio
import json
import logging
import os
import re
import signal
import subprocess
import sys
import urllib.error
import urllib.request
from types import FrameType
from typing import Final, TypedDict

from cursor_sdk import AsyncAgent, AsyncClient, CloudAgentOptions, CursorAgentError, ModelSelection

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("code_review")

HUNK_HEADER: Final[re.Pattern[str]] = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
FENCE: Final[re.Pattern[str]] = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)
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
    cursor_status_context="Approval Verdict",
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


class ThreadCommentNode(TypedDict):
    author: dict[str, str] | None
    body: str
    path: str | None


class ThreadComments(TypedDict):
    nodes: list[ThreadCommentNode]


class ReviewThread(TypedDict):
    id: str
    isResolved: bool
    isOutdated: bool
    comments: ThreadComments


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


def head_check_concluded(repo: str, head_sha: str, token: str) -> bool:
    """Return True if a completed Cursor review check run already exists for this head commit."""

    raw = run_gh(
        [
            "api",
            "--paginate",
            f"repos/{repo}/commits/{head_sha}/check-runs",
            "--jq",
            f'.check_runs[] | select(.name == "{CONFIG["cursor_status_context"]}" '
            'and .status == "completed" and (.conclusion == "success" '
            'or .conclusion == "neutral" or .conclusion == "failure")) | .id',
        ],
        token=token,
    )

    return bool(raw.split())


def start_check_run(repo: str, head_sha: str, token: str) -> str | None:
    """Open an in-progress review check run (yellow/pending while the agent reviews) and return its id."""

    try:
        raw = run_gh(
            [
                "api",
                "--method",
                "POST",
                f"repos/{repo}/check-runs",
                "-f",
                f"name={CONFIG['cursor_status_context']}",
                "-f",
                f"head_sha={head_sha}",
                "-f",
                "status=in_progress",
                "-f",
                "output[title]=Cursor code review",
                "-f",
                "output[summary]=Reviewing the changes…",
            ],
            token=token,
        )

        return str(json.loads(raw)["id"])
    except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError) as exc:
        logger.warning("Could not open the review check run: %s", exc)

        return None


def complete_check_run(
    repo: str, check_id: str | None, conclusion: str, title: str, summary: str, token: str
) -> bool:
    """Conclude the review check run with the round's verdict; return whether it is no longer pending."""

    if check_id is None:
        return True

    try:
        run_gh(
            [
                "api",
                "--method",
                "PATCH",
                f"repos/{repo}/check-runs/{check_id}",
                "-f",
                "status=completed",
                "-f",
                f"conclusion={conclusion}",
                "-f",
                f"output[title]={title}",
                "-f",
                f"output[summary]={summary}",
            ],
            token=token,
        )

        return True
    except subprocess.CalledProcessError as exc:
        logger.warning("Could not conclude the review check run: %s", exc)

        return False


def thread_title(comment: ThreadCommentNode) -> str | None:
    """Return the finding title from this tier's comment body (the `### ` heading), if present."""

    body = comment.get("body") or ""

    return next((row[4:].strip() for row in body.splitlines() if row.startswith("### ")), None)


def thread_severity(comment: ThreadCommentNode) -> str:
    """Return the severity word from this tier's comment body (the `**X Severity**` line), or empty."""

    body = comment.get("body") or ""
    line = next(
        (
            row.strip()
            for row in body.splitlines()
            if row.strip().startswith("**") and row.strip().lower().endswith("severity**")
        ),
        "",
    )
    words = line.strip("*").split()

    return words[0] if words else ""


def is_tier_comment(comment: ThreadCommentNode | None, marker: str) -> bool:
    """Return True when the comment is this tier's own posting (github-actions bot plus the marker)."""

    if comment is None:
        return False

    author = (comment["author"] or {}).get("login")

    return author in ("github-actions", "github-actions[bot]") and marker in (comment.get("body") or "")


def list_review_threads(repo: str, pr_number: str, token: str) -> list[ReviewThread]:
    """List every review thread on the PR via GraphQL, paginating fully; raise on a partial fetch."""

    owner, _, name = repo.partition("/")
    list_query = (
        "query($owner:String!,$name:String!,$number:Int!,$after:String){"
        "repository(owner:$owner,name:$name){pullRequest(number:$number){"
        "reviewThreads(first:100,after:$after){pageInfo{hasNextPage endCursor} "
        "nodes{id isResolved isOutdated comments(first:1){nodes{author{login} body path}}}}}}}"
    )

    threads: list[ReviewThread] = []
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
        # A partial thread list would drop still-open threads from the verdict and could approve over
        # them; fail loudly so the caller concludes the check as a failure instead of a false success.
        logger.error("Could not list review threads to reconcile: %s", exc)

        raise

    return threads


def existing_finding_titles(
    repo: str, pr_number: str, token: str, marker: str
) -> dict[str, list[tuple[str, str]]]:
    """Return this tier's posted (severity, title) pairs per file (open and resolved); best-effort."""

    try:
        threads = list_review_threads(repo, pr_number, token)
    except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError, TypeError):
        return {}

    findings: dict[str, list[tuple[str, str]]] = {}
    for thread in threads:
        try:
            comment = next(iter(thread["comments"]["nodes"]), None)
            if not is_tier_comment(comment, marker) or comment is None:
                continue

            path = comment.get("path")
            title = thread_title(comment)
            if path and title:
                findings.setdefault(path, []).append((thread_severity(comment), title))
        except (KeyError, TypeError):
            continue

    return findings


def reconcile_threads(
    repo: str,
    pr_number: str,
    token: str,
    marker: str,
    current_keys: set[tuple[str, str]],
    reviewed_files: set[str],
) -> tuple[set[tuple[str, str]], set[tuple[str, str]], list[str], set[tuple[str, str]]]:
    """Classify this tier's threads read-only into posted, open, stale, and kept-critical keys."""

    threads = list_review_threads(repo, pr_number, token)

    posted_keys: set[tuple[str, str]] = set()
    open_keys: set[tuple[str, str]] = set()
    stale_ids: list[str] = []
    kept_critical_keys: set[tuple[str, str]] = set()

    for thread in threads:
        try:
            comment = next(iter(thread["comments"]["nodes"]), None)
            if not is_tier_comment(comment, marker) or comment is None:
                continue

            title = thread_title(comment)
            if title is None:
                continue

            key = (comment.get("path"), title)
            posted_keys.add(key)
            if thread["isResolved"]:
                continue

            if key in current_keys:
                open_keys.add(key)

                continue

            # The finding is gone this round. An outdated thread is genuinely stale (GitHub marks it
            # outdated because the anchored code changed), so resolve it at any severity. Otherwise
            # the absence is not trustworthy: the agent reports findings only on changed diff lines,
            # so a still-current thread on an unchanged line of a re-reviewed file cannot be re-raised.
            # Resolve those only when non-Critical (noise reduction); keep Critical threads open so the
            # verdict never approves over an unconfirmed Critical, and keep every thread on a file the
            # agent did not review this round.
            is_critical = thread_severity(comment).lower() == "critical"

            if thread.get("isOutdated") or (comment.get("path") in reviewed_files and not is_critical):
                stale_ids.append(thread["id"])
            else:
                open_keys.add(key)
                if is_critical:
                    kept_critical_keys.add(key)
        except (KeyError, TypeError) as exc:
            logger.warning("Could not classify a review thread: %s", exc)

    return posted_keys, open_keys, stale_ids, kept_critical_keys


def resolve_threads(repo: str, thread_ids: list[str], token: str) -> None:
    """Resolve the given review threads — run only after the head is confirmed and the review posted."""

    mutation = "mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{id}}}"

    for thread_id in thread_ids:
        try:
            run_gh(
                ["api", "graphql", "-f", f"query={mutation}", "-f", f"id={thread_id}"],
                token=token,
            )
        except subprocess.CalledProcessError as exc:
            logger.warning("Could not resolve a review thread: %s", exc)


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
    """Map patched changed files to their (RIGHT, LEFT) anchor lines, plus files GitHub gave no patch."""

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


def build_prompt(
    repo: str, pr_number: str, head_sha: str, diff: str, posted_titles: dict[str, list[tuple[str, str]]]
) -> str:
    """Compose the review prompt: the skill reference, the PR context, and the strict JSON output contract."""

    if posted_titles:
        listed = "\n".join(
            f"- {path}: [{severity}] {title}" if severity else f"- {path}: {title}"
            for path in sorted(posted_titles)
            for severity, title in posted_titles[path]
        )
        existing_block = (
            "These issues already have review comments on this PR (file: [severity] title); some may "
            "have been resolved by a human. For any that still applies, report it again on the SAME "
            "file and with its title and severity copied EXACTLY so the runner matches it to the "
            "existing comment instead of posting a near-duplicate or downgrading it — this also keeps "
            "a hand-resolved comment resolved rather than reopening it. Omit a listed title only when "
            "that issue is now fixed:\n"
            f"{listed}\n\n"
        )
    else:
        existing_block = ""

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
        'list ({"findings": []}) when there are none.\n'
        "Report every issue that still applies to the diff at the location where it occurs — include "
        "a finding even when a similar review comment already exists, and never skip a still-valid "
        "finding. The runner reconciles your full set against the existing threads, so omitting a "
        "still-applicable finding would wrongly resolve its thread.\n"
        + existing_block
        + f"Repository: {repo}\nPull request: #{pr_number}\nHead commit: {head_sha}\n\n"
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
    """Render one Cursor inline comment body in the severity format."""

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


def verdict_summary(event: str, open_count: int, previous_count: int) -> str:
    """Phrase the verdict as the count of unresolved issues and how many carried from past reviews."""

    if event == "APPROVE":
        return "No unresolved issues — approving."

    plural = "s" if open_count != 1 else ""
    verb = "is" if open_count == 1 else "are"
    carried = f" (including {previous_count} from a previous review)" if previous_count else ""
    line = f"There {verb} {open_count} unresolved issue{plural}{carried}."

    if event == "REQUEST_CHANGES":
        return f"{line} A Critical issue is open — requesting changes."

    return line


def compute_verdict(open_count: int, open_critical: bool) -> tuple[str, str, str]:
    """Return the (review event, check conclusion, check title) for the round's open-issue state."""

    if open_count == 0:
        return "APPROVE", "success", "No unresolved issues"

    if open_critical:
        return "REQUEST_CHANGES", "failure", "Critical issue open"

    plural = "s" if open_count != 1 else ""

    return "COMMENT", "neutral", f"{open_count} unresolved issue{plural}"


def post_review_with_fallback(
    repo: str, pr_number: str, payload: ReviewPayload, event: str, token: str
) -> None:
    """Post the review, re-posting an APPROVE the bot cannot submit as a COMMENT."""

    if post_review(repo, pr_number, payload, token):
        return

    # GitHub forbids github-actions[bot] from APPROVE-ing the PR, so a clean round would otherwise
    # leave only the green check with no visible review. Re-post the approving body as a COMMENT
    # (which the bot may submit); the check run stays the real verdict.
    if event == "APPROVE":
        payload["event"] = "COMMENT"

    if event != "APPROVE" or not post_review(repo, pr_number, payload, token):
        logger.warning(
            "Could not post the %s review; the check run still records the verdict.", event
        )


def build_review(
    head_sha: str,
    findings: list[Finding],
    anchors: dict[str, tuple[set[int], set[int]]],
    event: str,
    summary_line: str,
) -> ReviewPayload:
    """Build the round's review: inline comments for the new findings plus the verdict summary body."""

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

    body = summary_line

    if summary:
        body = f"{body}\n\nOn files too large to anchor inline:\n" + "\n".join(summary)

    body = f"{body}\n\n{CONFIG['cursor_marker']}"

    return {"commit_id": head_sha, "event": event, "body": body, "comments": comments}


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

    repo = os.environ["REPO"]
    pr_number = os.environ["PR_NUMBER"]
    head_sha = os.environ["HEAD_SHA"]
    api_key = os.environ["CURSOR_API_KEY"]
    token = os.environ["GITHUB_TOKEN"]
    model = os.environ.get("CURSOR_AGENT_MODEL", "composer-2.5")

    # The check run is the verdict of record. Once this head has a concluded check, skip re-running
    # the agent: posting the visible review is best-effort within that run, and a clean round the bot
    # cannot APPROVE already falls back to a COMMENT, so a concluded head needs no further pass.
    if head_check_concluded(repo, head_sha, token):
        logger.info("Head %s already reviewed by Cursor; skipping.", head_sha)

        return 0

    diff = run_gh(["pr", "diff", pr_number, "--repo", repo], token=token)
    anchors, unpatched = diff_anchors(repo, pr_number, token)
    posted_titles = existing_finding_titles(repo, pr_number, token, CONFIG["cursor_marker"])
    prompt = build_prompt(repo, pr_number, head_sha, diff, posted_titles)

    check_id = start_check_run(repo, head_sha, token)
    concluded = False

    # GitHub Actions cancels a superseded run (cancel-in-progress) and an uncaught exit would leave
    # this head's check stuck in_progress; conclude it on the cancellation signals before exiting.
    # Setting concluded keeps the finally from overwriting the cancellation with action_required.
    def _conclude_on_signal(signum: int, frame: FrameType | None) -> None:
        """Conclude the pending check run when the job is cancelled, then exit."""

        nonlocal concluded
        complete_check_run(
            repo, check_id, "cancelled", "Superseded", "The review job was cancelled.", token
        )
        concluded = True

        sys.exit(1)

    for cancel_signal in (signal.SIGTERM, signal.SIGINT):
        signal.signal(cancel_signal, _conclude_on_signal)

    # The in-progress check must always reach a conclusion. Every explicit exit below records a
    # verdict; if any other error escapes first (bridge launch, model listing, reconciliation, a
    # gh/network failure), the finally concludes it as action_required so it never stays pending.
    try:
        try:
            client = await AsyncClient.launch_bridge()

            # Composer 2.5 defaults to the "fast" variant (≈6x the token cost); select the
            # non-default (standard) variant from the catalog so background reviews use the cheaper tier.
            catalog = await client.list_models(api_key=api_key)
            sdk_model = next((entry for entry in catalog if entry.id == model), None)
            standard_variant = next(
                (
                    variant
                    for variant in (sdk_model.variants if sdk_model else ())
                    if not variant.is_default
                ),
                None,
            )
            model_selection: str | ModelSelection = (
                ModelSelection(id=model, params=list(standard_variant.params))
                if standard_variant is not None
                else model
            )

            agent = await AsyncAgent.create(
                client=client, model=model_selection, api_key=api_key, cloud=CloudAgentOptions()
            )

            try:
                run = await agent.send(prompt)
                reply = await run.text()
            finally:
                await agent.close()
        except CursorAgentError as exc:
            logger.error("Cursor agent run failed: %s", exc)
            complete_check_run(
                repo, check_id, "action_required", "Review failed", "The Cursor agent run failed.", token
            )
            concluded = True

            return 1

        try:
            findings = parse_findings(reply)
        except (json.JSONDecodeError, AttributeError, KeyError, TypeError, ValueError) as exc:
            logger.error("Could not parse agent reply: %s", exc)
            complete_check_run(
                repo, check_id, "action_required", "Review failed", "Could not parse the agent reply.", token
            )
            concluded = True

            return 1

        current_keys = {(finding["path"], finding["title"].strip()) for finding in findings}

        # Re-gate on the head SHA once the agent run is done: if the head advanced while the agent
        # worked, do not act on the superseded commit — the next event reviews the new head.
        if current_head_sha(repo, pr_number, token) != head_sha:
            logger.info("Head moved during the agent run; skipping (the new commit reviews next).")
            complete_check_run(
                repo, check_id, "cancelled", "Superseded", "The head moved during review.", token
            )
            concluded = True

            return 0

        # Reconcile this tier's existing threads against the round's findings: resolve the ones whose
        # finding is gone, and learn which keys are already posted and which remain open.
        reviewed_files = set(anchors) | unpatched
        posted_keys, open_existing, stale_ids, kept_critical = reconcile_threads(
            repo, pr_number, token, CONFIG["cursor_marker"], current_keys, reviewed_files
        )

        postable = [finding for finding in findings if is_postable(finding, anchors, unpatched)]

        new_findings = []
        seen_new_keys: set[tuple[str, str]] = set()
        for finding in postable:
            key = (finding["path"], finding["title"].strip())
            if key in posted_keys or key in seen_new_keys:
                continue

            seen_new_keys.add(key)
            new_findings.append(finding)

        new_findings = cap_low_findings(new_findings)

        severity_by_key = {
            (finding["path"], finding["title"].strip()): finding["severity"] for finding in findings
        }
        # The verdict's open set is every in-scope finding still raised that is not already resolved
        # on GitHub: the tier's still-open threads, plus genuinely new findings (those without a
        # thread yet). A new finding counts even when it fails anchor validation and so cannot be
        # posted inline — it is still an open issue, so the verdict must not approve over it. A
        # finding whose thread a human resolved stays resolved. The Low cap only limits how many
        # inline comments post, not the verdict.
        new_open_keys = {key for key in current_keys if key not in posted_keys}
        open_keys = open_existing | new_open_keys
        open_count = len(open_keys)
        open_critical = bool(kept_critical) or any(
            (severity_by_key.get(key) or "").lower() == "critical" for key in open_keys
        )

        previous_count = len(open_existing)
        event, conclusion, title = compute_verdict(open_count, open_critical)
        summary = verdict_summary(event, open_count, previous_count)

        # Re-check the head right before mutating: it can advance during reconciliation, and a review
        # must not anchor to a superseded commit.
        if current_head_sha(repo, pr_number, token) != head_sha:
            logger.info("Head moved before posting; skipping (the new commit reviews next).")
            complete_check_run(
                repo, check_id, "cancelled", "Superseded", "The head moved before posting.", token
            )
            concluded = True

            return 0

        # The check run is the authoritative verdict; posting the review is best-effort. Post it
        # unless this head already has one (re-run or concurrent run), and if posting fails (e.g.
        # GitHub rejects a bot APPROVE) still resolve threads and conclude so the verdict is recorded.
        if not already_reviewed(repo, pr_number, head_sha, token, CONFIG["cursor_marker"]):
            payload = build_review(head_sha, new_findings, anchors, event, summary)
            post_review_with_fallback(repo, pr_number, payload, event, token)

        logger.info("Resolving %d stale thread(s); %d open issue(s) remain.", len(stale_ids), open_count)
        resolve_threads(repo, stale_ids, token)

        complete_check_run(repo, check_id, conclusion, title, summary, token)
        concluded = True

        return 0
    finally:
        if not concluded:
            complete_check_run(
                repo, check_id, "action_required", "Review failed", "The review run did not complete.", token
            )


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
