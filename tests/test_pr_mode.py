import json
import subprocess

import pytest

from scanner.cli import main
from scanner.gate import EXIT_ERROR, EXIT_FINDINGS
from scanner.runners import ScannerError
from scanner.sources import validate_commit_range
from tests.conftest import FAKE_SECRETS, requires_gitleaks


def _shas(repo):
    out = subprocess.run(["git", "rev-list", "--reverse", "HEAD"], cwd=repo, check=True,
                         capture_output=True, text=True).stdout.split()
    return out  # [add settings, remove settings, add notes]


def _scan(repo, tmp_path, commit_range):
    report = tmp_path / "report.json"
    code = main([str(repo), f"--commit-range={commit_range}", "--output", str(report)])
    return code, report


@requires_gitleaks
def test_range_scans_only_the_given_commits(fake_repo, tmp_path):
    first, second, third = _shas(fake_repo)
    code, report = _scan(fake_repo, tmp_path, f"{second}..{third}")
    findings = json.loads(report.read_text(encoding="utf-8"))["findings"]
    assert code == EXIT_FINDINGS
    assert [f["file"] for f in findings] == ["notes.md"]  # the old, deleted AWS key is out of range
    text = report.read_text(encoding="utf-8")
    assert not any(secret in text for secret in FAKE_SECRETS)


@pytest.mark.parametrize("bad", [
    "--output=/tmp/x", "main..HEAD", "abc..def", "a" * 40, f"{'a' * 40}..{'b' * 40};rm -rf /",
    f"{'a' * 40}...{'b' * 40}", "", f" {'a' * 7}..{'b' * 7}",
])
def test_bad_ranges_are_rejected_before_any_scan(bad, fake_repo, tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("scanner was run"))
    with pytest.raises(ScannerError):
        validate_commit_range(bad)
    code, _ = _scan(fake_repo, tmp_path, bad)
    assert code == EXIT_ERROR


def test_good_range_is_accepted():
    assert validate_commit_range(f"{'a' * 40}..{'0' * 7}")


def test_usage_errors_exit_1_not_2(capsys):
    with pytest.raises(SystemExit) as info:
        main([])
    assert info.value.code == EXIT_ERROR
    assert "error" in capsys.readouterr().err
