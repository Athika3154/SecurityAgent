import json
import subprocess
import tempfile

import pytest

from scanner.cli import main
from scanner.gate import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS
from scanner.runners import ScannerError, run_quiet
from tests.conftest import FAKE_SECRETS, requires_gitleaks


def _scan(repo, tmp_path, *extra):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    code = main([str(repo), "--runners", "gitleaks", "--output", str(out / "report.json"), *extra])
    return code, out / "report.json"


@requires_gitleaks
def test_deleted_secret_is_still_found_from_history(fake_repo, tmp_path):
    code, report = _scan(fake_repo, tmp_path)
    findings = json.loads(report.read_text(encoding="utf-8"))["findings"]
    by_file = {finding["file"]: finding for finding in findings}
    assert code == EXIT_FINDINGS
    assert "settings.py" in by_file and not (fake_repo / "settings.py").exists()
    assert by_file["settings.py"]["rule"] == "aws-access-token"
    assert "notes.md" in by_file
    for finding in findings:
        assert set(finding) == {"file", "line", "rule", "category", "title", "severity",
                                "tool", "commit", "fingerprint", "remediation"}
        assert "rotate" in finding["remediation"].lower()


@requires_gitleaks
def test_secret_values_never_reach_output_logs_or_temp_files(
    fake_repo, tmp_path, capsys, caplog, monkeypatch
):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    caplog.set_level("DEBUG")
    _scan(fake_repo, tmp_path)
    captured = capsys.readouterr()
    haystack = [captured.out, captured.err, caplog.text]
    haystack += [p.read_text(encoding="utf-8") for p in (tmp_path / "out").iterdir()]
    for secret in FAKE_SECRETS:
        assert not any(secret in text for text in haystack)
        assert not any(secret[:12] in text for text in haystack)
    assert list(scratch.iterdir()) == []  # raw scanner report was deleted


@requires_gitleaks
def test_allowlist_suppresses_findings_and_clears_the_gate(fake_repo, tmp_path):
    config = tmp_path / "scan.yaml"
    config.write_text("allowlist:\n  rules: [aws-access-token, github-pat]\n", encoding="utf-8")
    code, report = _scan(fake_repo, tmp_path, "--config", str(config))
    data = json.loads(report.read_text(encoding="utf-8"))
    assert code == EXIT_CLEAN and data["summary"]["suppressed"] == 2 and data["findings"] == []


@requires_gitleaks
def test_fail_on_critical_ignores_high_findings(fake_repo, tmp_path):
    config = tmp_path / "scan.yaml"
    config.write_text("fail_on: critical\nallowlist:\n  rules: [aws-access-token]\n", encoding="utf-8")
    code, _ = _scan(fake_repo, tmp_path, "--config", str(config))
    assert code == EXIT_CLEAN  # only the high-severity GitHub token remains


def test_missing_scanner_binary_exits_1_never_clean(fake_repo, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SCAN_GITLEAKS_BIN", str(tmp_path / "no-such-gitleaks"))
    code, report = _scan(fake_repo, tmp_path)
    assert code == EXIT_ERROR and not report.exists()
    assert "not installed" in capsys.readouterr().err


@pytest.mark.parametrize("returncode", [1, 2, 126, 255])
def test_scanner_crash_exits_1(fake_repo, tmp_path, monkeypatch, returncode):
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, returncode)
    )
    code, _ = _scan(fake_repo, tmp_path)
    assert code == EXIT_ERROR


def test_scanner_timeout_exits_1(fake_repo, tmp_path, monkeypatch, capsys):
    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(args, 1)

    monkeypatch.setattr(subprocess, "run", boom)
    code, _ = _scan(fake_repo, tmp_path)
    assert code == EXIT_ERROR and "timed out" in capsys.readouterr().err


def test_clean_exit_with_missing_report_is_empty_not_error(fake_repo, tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0))
    code, report = _scan(fake_repo, tmp_path)
    assert code == EXIT_CLEAN and json.loads(report.read_text(encoding="utf-8"))["findings"] == []


def test_leaks_exit_with_garbage_report_exits_1(fake_repo, tmp_path, monkeypatch):
    def fake_run(cmd, **kwargs):
        report = cmd[cmd.index("--report-path") + 1]
        with open(report, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        return subprocess.CompletedProcess(cmd, 3)

    monkeypatch.setattr(subprocess, "run", fake_run)
    code, _ = _scan(fake_repo, tmp_path)
    assert code == EXIT_ERROR


def test_invalid_config_exits_1(fake_repo, tmp_path):
    config = tmp_path / "scan.yaml"
    config.write_text("fail_on: nonsense\n", encoding="utf-8")
    code, _ = _scan(fake_repo, tmp_path, "--config", str(config))
    assert code == EXIT_ERROR


def test_run_quiet_missing_binary_is_a_scanner_error(tmp_path):
    with pytest.raises(ScannerError):
        run_quiet([str(tmp_path / "missing")], 5, "x")
