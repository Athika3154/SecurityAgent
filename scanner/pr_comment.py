"""Post or update the scanner's summary comment on a pull request (GitHub REST API)."""
import argparse
import http.client
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

from scanner.gate import EXIT_ERROR

MARKER = "<!-- secret-scanner-report -->"
BOT_LOGIN = "github-actions[bot]"
DEFAULT_API_URL = "https://api.github.com"
API_TIMEOUT = 30
PAGE_SIZE = 100
MAX_PAGES = 10
MAX_ROWS = 25
MAX_CELL_CHARS = 120
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_ROTATE_NOTICE = (
    "**Rotate every exposed credential now.** Removing it from the code is not enough, "
    "because it stays in Git history and in every clone."
)


class CommentError(Exception):
    """Reading the report or calling the GitHub API failed. Messages are safe to print."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: urllib would forward the Authorization header."""

    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _cell(value: object) -> str:
    """Render untrusted text as a one-line inline code span safe inside a Markdown table."""
    text = " ".join(str(value).split())[:MAX_CELL_CHARS]
    return "`" + text.replace("`", "'").replace("|", "\\|") + "`"


def build_comment(report: dict[str, object]) -> str:
    findings = report.get("findings", [])
    summary = report.get("summary", {})
    if not isinstance(findings, list) or not isinstance(summary, dict):
        raise CommentError("report has an unexpected structure")
    lines = [MARKER, "### Secret scan"]
    if not findings:
        lines.append("No findings.")
    else:
        lines += [
            f"**{len(findings)} finding(s)** in the commits of this pull request.",
            "",
            "| Severity | Category | Location | Rule | Commit | Tool |",
            "|---|---|---|---|---|---|",
        ]
        for finding in findings[:MAX_ROWS]:
            if not isinstance(finding, dict):
                raise CommentError("report has an unexpected structure")
            line = finding.get("line")
            location = f"{finding.get('file', '')}:{line}" if line else finding.get("file", "")
            lines.append(
                f"| {_cell(finding.get('severity', ''))} | {_cell(finding.get('category', ''))} "
                f"| {_cell(location)} | {_cell(finding.get('rule', ''))} "
                f"| {_cell(finding.get('commit', ''))} | {_cell(finding.get('tool', ''))} |"
            )
        if len(findings) > MAX_ROWS:
            lines.append(f"\n...and {len(findings) - MAX_ROWS} more. See the full report artifact.")
        if any(isinstance(f, dict) and f.get("category") == "secret" for f in findings):
            lines += ["", _ROTATE_NOTICE]
    for key, label in (
        ("suppressed", "suppressed by the allowlist"),
        ("baselined", "already in the baseline"),
    ):
        count = summary.get(key, 0)
        if isinstance(count, int) and count:
            lines.append(f"\n{count} finding(s) {label}.")
    return "\n".join(lines)


def _api(method: str, url: str, token: str, payload: dict[str, str] | None = None) -> object:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "secret-scanner",
            "Content-Type": "application/json",
        },
    )
    try:
        with _OPENER.open(request, timeout=API_TIMEOUT) as response:
            body = response.read()
    except urllib.error.HTTPError as error:
        code = error.code
        error.close()
        raise CommentError(f"GitHub API returned HTTP {code}") from None
    except (OSError, http.client.HTTPException):
        raise CommentError("could not reach the GitHub API") from None
    try:
        return json.loads(body) if body else None
    except ValueError:
        raise CommentError("GitHub API returned invalid JSON") from None


def _find_existing(api_url: str, repo: str, pr_number: int, token: str) -> int | None:
    """Id of our earlier comment. Only the Actions bot's comments count, so no one can spoof it."""
    for page in range(1, MAX_PAGES + 1):
        url = f"{api_url}/repos/{repo}/issues/{pr_number}/comments?per_page={PAGE_SIZE}&page={page}"
        comments = _api("GET", url, token)
        if not isinstance(comments, list):
            raise CommentError("GitHub API returned an unexpected response")
        for comment in comments:
            user = comment.get("user") if isinstance(comment, dict) else None
            body = comment.get("body") if isinstance(comment, dict) else None
            if (
                isinstance(user, dict) and user.get("login") == BOT_LOGIN
                and isinstance(body, str) and MARKER in body
                and isinstance(comment.get("id"), int)
            ):
                return comment["id"]
        if len(comments) < PAGE_SIZE:
            break
    return None


def post_comment(api_url: str, repo: str, pr_number: int, token: str, body: str) -> None:
    """Create the summary comment, or update it in place if we already posted one."""
    existing = _find_existing(api_url, repo, pr_number, token)
    if existing is None:
        _api("POST", f"{api_url}/repos/{repo}/issues/{pr_number}/comments", token, {"body": body})
    else:
        _api("PATCH", f"{api_url}/repos/{repo}/issues/comments/{existing}", token, {"body": body})


def _load_report(path: Path) -> dict[str, object]:
    try:
        with path.open(encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, ValueError):
        raise CommentError("report file is missing or not valid JSON") from None
    if not isinstance(report, dict):
        raise CommentError("report has an unexpected structure")
    return report


def _settings() -> tuple[str, str, str]:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    api_url = os.environ.get("GITHUB_API_URL", DEFAULT_API_URL).rstrip("/")
    if not _REPO.fullmatch(repo):
        raise CommentError("GITHUB_REPOSITORY must look like owner/name")
    if not token:
        raise CommentError("GITHUB_TOKEN is not set")
    if not api_url.startswith("https://"):
        raise CommentError("GITHUB_API_URL must be an https URL")
    return repo, token, api_url


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scanner-comment", description="Comment on a PR.")
    parser.add_argument("--report", type=Path, required=True, help="JSON report from the scanner")
    parser.add_argument("--pr-number", type=int, required=True, help="pull request number")
    args = parser.parse_args(argv)
    try:
        if args.pr_number < 1:
            raise CommentError("--pr-number must be a positive integer")
        repo, token, api_url = _settings()
        body = build_comment(_load_report(args.report))
        post_comment(api_url, repo, args.pr_number, token, body)
    except CommentError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    print(f"posted scan summary to {repo}#{args.pr_number}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
