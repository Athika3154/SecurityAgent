import io
import json
import urllib.error
import urllib.request

import pytest

from scanner import pr_comment
from scanner.pr_comment import (
    BOT_LOGIN, MARKER, MAX_ROWS, CommentError, build_comment, main, post_comment,
)

TOKEN = "ghs_FAKE_TOKEN_FOR_TESTS_ONLY"
API = "https://api.github.com"


def _finding(**overrides):
    base = {"file": "src/app.py", "line": 7, "secret_type": "private-key", "severity": "critical",
            "tool": "gitleaks", "commit": "abcdef12", "fingerprint": "f" * 32, "remediation": "rotate"}
    return {**base, **overrides}


def _report(findings=(), suppressed=0):
    return {"summary": {"total": len(findings), "suppressed": suppressed}, "findings": list(findings)}


class FakeOpener:
    """Stands in for the urllib opener; replays queued responses and records requests."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []
        self.timeouts = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        self.timeouts.append(timeout)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return io.BytesIO(item if isinstance(item, bytes) else json.dumps(item).encode())


@pytest.fixture
def opener(monkeypatch):
    def install(*responses):
        fake = FakeOpener(*responses)
        monkeypatch.setattr(pr_comment, "_OPENER", fake)
        return fake

    return install


def _comment(cid, login, body):
    return {"id": cid, "user": {"login": login}, "body": body}


def test_creates_a_comment_when_none_exists(opener):
    fake = opener([], {"id": 1})
    post_comment(API, "o/r", 5, TOKEN, "hello " + MARKER)
    get, post = fake.requests
    assert get.get_method() == "GET" and "/repos/o/r/issues/5/comments" in get.full_url
    assert post.get_method() == "POST" and post.full_url == f"{API}/repos/o/r/issues/5/comments"
    assert json.loads(post.data) == {"body": "hello " + MARKER}
    assert post.get_header("Authorization") == f"Bearer {TOKEN}"
    assert fake.timeouts == [pr_comment.API_TIMEOUT] * 2


def test_updates_the_existing_bot_comment_in_place(opener):
    fake = opener([_comment(1, "someone", "hi"), _comment(42, BOT_LOGIN, MARKER + " old")], {"id": 42})
    post_comment(API, "o/r", 5, TOKEN, "new")
    patch = fake.requests[1]
    assert patch.get_method() == "PATCH" and patch.full_url == f"{API}/repos/o/r/issues/comments/42"


def test_a_human_cannot_spoof_the_marker(opener):
    fake = opener([_comment(9, "attacker", MARKER + " fake")], {"id": 10})
    post_comment(API, "o/r", 5, TOKEN, "new")
    assert fake.requests[1].get_method() == "POST"


def test_finds_the_comment_on_a_later_page(opener):
    page1 = [_comment(i, "someone", "x") for i in range(100)]
    fake = opener(page1, [_comment(500, BOT_LOGIN, MARKER)], {"id": 500})
    post_comment(API, "o/r", 5, TOKEN, "new")
    assert "page=2" in fake.requests[1].full_url
    assert fake.requests[2].full_url.endswith("/issues/comments/500")


def test_pagination_is_bounded(opener):
    full_page = [_comment(i, "someone", "x") for i in range(100)]
    fake = opener(*([full_page] * pr_comment.MAX_PAGES), {"id": 1})
    post_comment(API, "o/r", 5, TOKEN, "new")
    assert len(fake.requests) == pr_comment.MAX_PAGES + 1


@pytest.mark.parametrize("failure,expected", [
    (urllib.error.HTTPError(API, 403, "Forbidden", {}, io.BytesIO(b"")), "HTTP 403"),
    (urllib.error.HTTPError(API, 500, "Boom", {}, io.BytesIO(b"")), "HTTP 500"),
    (urllib.error.URLError("dns failure"), "could not reach"),
    (TimeoutError("timed out"), "could not reach"),
    (ConnectionResetError(), "could not reach"),
])
def test_api_failures_become_safe_errors(opener, failure, expected):
    opener(failure)
    with pytest.raises(CommentError) as info:
        post_comment(API, "o/r", 5, TOKEN, "x")
    assert expected in str(info.value) and TOKEN not in str(info.value)


def test_failure_on_the_write_call_is_reported(opener):
    opener([], urllib.error.HTTPError(API, 403, "Forbidden", {}, io.BytesIO(b"")))
    with pytest.raises(CommentError, match="HTTP 403"):
        post_comment(API, "o/r", 5, TOKEN, "x")


@pytest.mark.parametrize("bad", [b"<html>not json", {"message": "not a list"}, "text"])
def test_bad_api_responses_are_rejected(opener, bad):
    opener(bad)
    with pytest.raises(CommentError):
        post_comment(API, "o/r", 5, TOKEN, "x")


def test_redirects_are_never_followed():
    handler = pr_comment._NoRedirect()
    request = urllib.request.Request(API)
    assert handler.redirect_request(request, None, 302, "Found", {}, "https://evil.example") is None


def test_comment_summarises_findings_and_says_to_rotate():
    body = build_comment(_report([_finding()], suppressed=2))
    assert body.startswith(MARKER) and "1 finding(s)" in body
    assert "`src/app.py:7`" in body and "`private-key`" in body and "`critical`" in body
    assert "Rotate every exposed credential" in body and "2 finding(s) suppressed" in body


def test_comment_with_no_findings():
    assert "No findings." in build_comment(_report())


def test_comment_escapes_hostile_values():
    hostile = _finding(file="a|b`c\n@everyone <script>alert(1)</script>.py", secret_type="x|y")
    body = build_comment(_report([hostile]))
    row = [line for line in body.splitlines() if "everyone" in line]
    assert len(row) == 1  # newline in the name cannot start a new line
    assert "a\\|b'c @everyone" in row[0] and "x\\|y" in row[0]
    assert row[0].count("`") % 2 == 0


def test_comment_rows_are_capped():
    body = build_comment(_report([_finding(line=n) for n in range(MAX_ROWS + 5)]))
    assert body.count("| `critical`") == MAX_ROWS and "and 5 more" in body


@pytest.mark.parametrize("report", [{"findings": "x"}, {"findings": ["x"]}, {"summary": 3}])
def test_malformed_report_is_rejected(report):
    with pytest.raises(CommentError):
        build_comment(report)


def _env(monkeypatch, **values):
    base = {"GITHUB_REPOSITORY": "o/r", "GITHUB_TOKEN": TOKEN}
    for key in ("GITHUB_REPOSITORY", "GITHUB_TOKEN", "GITHUB_API_URL"):
        monkeypatch.delenv(key, raising=False)
    for key, value in {**base, **values}.items():
        if value is not None:
            monkeypatch.setenv(key, value)


def _write_report(tmp_path, report):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return str(path)


def test_main_posts_the_comment(opener, monkeypatch, tmp_path, capsys):
    _env(monkeypatch)
    fake = opener([], {"id": 1})
    assert main(["--report", _write_report(tmp_path, _report([_finding()])), "--pr-number", "5"]) == 0
    assert fake.requests[1].get_method() == "POST"
    assert TOKEN not in capsys.readouterr().out


def test_main_api_failure_exits_1_without_leaking_the_token(opener, monkeypatch, tmp_path, capsys):
    _env(monkeypatch)
    opener(urllib.error.HTTPError(API, 403, "Forbidden", {}, io.BytesIO(b"")))
    assert main(["--report", _write_report(tmp_path, _report()), "--pr-number", "5"]) == 1
    captured = capsys.readouterr()
    assert "HTTP 403" in captured.err and TOKEN not in captured.err + captured.out


@pytest.mark.parametrize("env,pr", [
    ({"GITHUB_REPOSITORY": "not-a-repo"}, "5"),
    ({"GITHUB_REPOSITORY": "o/r/../x"}, "5"),
    ({"GITHUB_TOKEN": None}, "5"),
    ({"GITHUB_API_URL": "http://insecure.example"}, "5"),
    ({}, "0"),
])
def test_main_validates_inputs_before_any_call(opener, monkeypatch, tmp_path, env, pr):
    _env(monkeypatch, **env)
    opener()  # any API call would pop from an empty queue and fail the test
    assert main(["--report", _write_report(tmp_path, _report()), "--pr-number", pr]) == 1


def test_main_missing_or_invalid_report_exits_1(opener, monkeypatch, tmp_path):
    _env(monkeypatch)
    opener()
    assert main(["--report", str(tmp_path / "nope.json"), "--pr-number", "5"]) == 1
    bad = tmp_path / "bad.json"
    bad.write_text("{oops", encoding="utf-8")
    assert main(["--report", str(bad), "--pr-number", "5"]) == 1
