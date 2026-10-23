import pytest

from scanner.cli import main
from scanner.gate import EXIT_ERROR
from scanner.runners import ScannerError
from scanner.runners.semgrep import RUNNER
from tests.conftest import fake_tool, repo_shas

SENTINEL = "TOP-SECRET-SENTINEL-VALUE"


def _result(check_id, path, line, severity):
    return {"check_id": check_id, "path": path, "start": {"line": line, "col": 1},
            "extra": {"severity": severity, "lines": f"key = '{SENTINEL}'",
                      "message": f"found {SENTINEL}"}}


PAYLOAD = {"results": [
    _result("python.lang.security.audit.eval-detected.eval-detected", "tools.py", 7, "WARNING"),
    _result("python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
            "tools.py", 16, "ERROR"),
    _result("generic.secrets.security.detected-github-token.detected-github-token", ".env", 5,
            "ERROR"),
    _result("some.rule.info-level", "app.py", 1, "INFO"),
], "errors": []}


def _run(repo, monkeypatch, payload=PAYLOAD, exit_code=0, calls=None, commit_range=None):
    monkeypatch.setattr("scanner.runners.semgrep.run_quiet", fake_tool(payload, exit_code, calls))
    return RUNNER.run(repo, 30, commit_range)


def test_parses_code_flaws_and_secrets(fake_repo, monkeypatch):
    found = {f.rule.rsplit(".", 1)[-1]: f for f in _run(fake_repo, monkeypatch)}
    eval_ = found["eval-detected"]
    assert (eval_.category, eval_.severity, eval_.file, eval_.line) == ("code", "medium", "tools.py", 7)
    assert eval_.title == "eval detected" and "semgrep.dev/r/" in eval_.remediation
    assert found["subprocess-shell-true"].severity == "high"
    assert found["info-level"].severity == "low"
    secret = found["detected-github-token"]
    assert secret.category == "secret" and "rotate" in secret.remediation.lower()


def test_matched_source_text_is_never_read(fake_repo, monkeypatch):
    assert SENTINEL not in repr([f.to_dict() for f in _run(fake_repo, monkeypatch)])


@pytest.mark.parametrize("payload", [
    {}, {"results": "x"}, [], {"results": [{"check_id": "r", "path": "a", "start": {"line": 1},
                                           "extra": {"severity": "FATAL"}}]},
    {"results": [{"path": "a", "start": {"line": 1}, "extra": {"severity": "ERROR"}}]},
    {"results": [{"check_id": "r", "path": "a", "extra": {"severity": "ERROR"}}]},
    {"results": ["x"]},
])
def test_malformed_report_is_an_error(fake_repo, monkeypatch, payload):
    with pytest.raises(ScannerError):
        _run(fake_repo, monkeypatch, payload=payload)


def test_missing_report_file_is_an_error(fake_repo, monkeypatch):
    with pytest.raises(ScannerError):
        _run(fake_repo, monkeypatch, payload=None)


@pytest.mark.parametrize("code", [1, 2, 7])
def test_nonzero_exit_is_an_error_not_a_pass(fake_repo, monkeypatch, code):
    with pytest.raises(ScannerError, match=f"exit code {code}"):
        _run(fake_repo, monkeypatch, exit_code=code)


def test_empty_results_are_clean(fake_repo, monkeypatch):
    assert _run(fake_repo, monkeypatch, payload={"results": [], "errors": []}) == []


def test_repo_cannot_hide_findings_or_phone_home(fake_repo, monkeypatch):
    calls = []
    _run(fake_repo, monkeypatch, calls=calls)
    cmd, env = calls[0]["cmd"], calls[0]["env"]
    for flag in ("--disable-nosem", "--no-git-ignore", "--x-ignore-semgrepignore-files",
                 "--disable-version-check"):
        assert flag in cmd
    assert cmd[cmd.index("--metrics") + 1] == "off" and env["SEMGREP_SEND_METRICS"] == "off"
    assert calls[0]["cwd"] == fake_repo and cmd[-1] == "."


def test_pr_mode_keeps_only_files_the_pr_touched(fake_repo, monkeypatch):
    _, second, third = repo_shas(fake_repo)
    payload = {"results": [_result("a.b.old", "settings.py", 1, "ERROR"),
                           _result("a.b.new", "notes.md", 1, "ERROR")]}
    findings = _run(fake_repo, monkeypatch, payload=payload, commit_range=f"{second}..{third}")
    assert [f.file for f in findings] == ["notes.md"]


def test_missing_binary_exits_1(fake_repo, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SCAN_SEMGREP_BIN", str(tmp_path / "no-such-semgrep"))
    code = main([str(fake_repo), "--runners", "semgrep", "--output", str(tmp_path / "r.json")])
    assert code == EXIT_ERROR and "not installed" in capsys.readouterr().err
