import pytest

from scanner.cli import main
from scanner.gate import EXIT_ERROR
from scanner.runners import ScannerError
from scanner.runners.trivy import RUNNER
from tests.conftest import fake_tool, repo_shas

SENTINEL = "TOP-SECRET-SENTINEL-VALUE"
PAYLOAD = {"Results": [
    {"Target": "requirements.txt", "Class": "lang-pkgs", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2018-1000656", "PkgName": "flask", "InstalledVersion": "0.12.2",
         "FixedVersion": "0.12.3", "Severity": "HIGH", "Title": "DoS in flask"},
        {"VulnerabilityID": "CVE-2000-0001", "PkgName": "old", "InstalledVersion": "1.0",
         "Severity": "UNKNOWN"},
    ]},
    {"Target": "Dockerfile", "Class": "config", "Misconfigurations": [
        {"ID": "DS-0002", "Title": "Image user should not be 'root'", "Severity": "HIGH",
         "Resolution": "Add a USER instruction.", "CauseMetadata": {"StartLine": 2}},
        {"ID": "DS-0026", "Title": "No HEALTHCHECK", "Severity": "LOW", "CauseMetadata": {}},
    ]},
    {"Target": ".env", "Class": "secret", "Secrets": [
        {"RuleID": "github-pat", "Title": "GitHub PAT", "Severity": "CRITICAL", "StartLine": 5,
         "Match": f"token={SENTINEL}", "Code": {"Lines": [{"Content": SENTINEL}]}},
    ]},
]}


def _run(repo, monkeypatch, payload=PAYLOAD, exit_code=0, calls=None, commit_range=None):
    monkeypatch.setattr("scanner.runners.trivy.run_quiet", fake_tool(payload, exit_code, calls))
    return RUNNER.run(repo, 30, commit_range)


def test_parses_vulnerabilities_misconfigurations_and_secrets(fake_repo, monkeypatch):
    found = {f"{f.category}:{f.rule}": f for f in _run(fake_repo, monkeypatch)}
    vuln = found["vulnerability:CVE-2018-1000656"]
    assert (vuln.file, vuln.line, vuln.severity, vuln.tool) == ("requirements.txt", 0, "high", "trivy")
    assert vuln.remediation == "Upgrade flask from 0.12.2 to 0.12.3."
    assert "No fixed version" in found["vulnerability:CVE-2000-0001"].remediation
    assert found["vulnerability:CVE-2000-0001"].severity == "low"
    root = found["misconfiguration:DS-0002"]
    assert (root.file, root.line, root.remediation) == ("Dockerfile", 2, "Add a USER instruction.")
    assert found["misconfiguration:DS-0026"].line == 0
    secret = found["secret:github-pat"]
    assert secret.severity == "critical" and "rotate" in secret.remediation.lower()


def test_matched_secret_text_is_never_read(fake_repo, monkeypatch):
    assert SENTINEL not in repr([f.to_dict() for f in _run(fake_repo, monkeypatch)])


def test_commit_is_the_repo_head(fake_repo, monkeypatch):
    findings = _run(fake_repo, monkeypatch)
    assert {f.commit for f in findings} == {repo_shas(fake_repo)[-1][:8]}


def test_no_results_is_an_empty_list(fake_repo, monkeypatch):
    assert _run(fake_repo, monkeypatch, payload={"SchemaVersion": 2}) == []


@pytest.mark.parametrize("payload", [
    [], {"Results": "x"}, {"Results": ["x"]}, {"Results": [{"Class": "secret"}]},
    {"Results": [{"Target": "a", "Secrets": [{"RuleID": "r", "Title": "t", "Severity": "BAD",
                                              "StartLine": 1}]}]},
    {"Results": [{"Target": "a", "Vulnerabilities": "x"}]},
    {"Results": [{"Target": "a", "Secrets": [{"Title": "t", "Severity": "HIGH", "StartLine": 1}]}]},
])
def test_malformed_report_is_an_error(fake_repo, monkeypatch, payload):
    with pytest.raises(ScannerError):
        _run(fake_repo, monkeypatch, payload=payload)


def test_missing_report_file_is_an_error(fake_repo, monkeypatch):
    with pytest.raises(ScannerError):
        _run(fake_repo, monkeypatch, payload=None)


@pytest.mark.parametrize("code", [1, 2, 127])
def test_nonzero_exit_is_an_error_not_a_pass(fake_repo, monkeypatch, code):
    with pytest.raises(ScannerError, match=f"exit code {code}"):
        _run(fake_repo, monkeypatch, exit_code=code)


def test_repo_config_and_ignore_files_are_neutralised(fake_repo, monkeypatch):
    calls = []
    _run(fake_repo, monkeypatch, calls=calls)
    cmd = calls[0]["cmd"]
    assert cmd[cmd.index("--config") + 1] == cmd[cmd.index("--ignorefile") + 1]  # our empty file
    assert "--skip-dirs" in cmd and cmd[-1] == str(fake_repo)


def test_pr_mode_keeps_only_files_the_pr_touched(fake_repo, monkeypatch):
    _, second, third = repo_shas(fake_repo)
    payload = {"Results": [
        {"Target": "settings.py", "Secrets": [
            {"RuleID": "old", "Title": "t", "Severity": "HIGH", "StartLine": 1}]},
        {"Target": "notes.md", "Secrets": [
            {"RuleID": "new", "Title": "t", "Severity": "HIGH", "StartLine": 1}]},
    ]}
    findings = _run(fake_repo, monkeypatch, payload=payload, commit_range=f"{second}..{third}")
    assert [f.file for f in findings] == ["notes.md"]
    assert findings[0].commit == third[:8]


def test_missing_binary_exits_1(fake_repo, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SCAN_TRIVY_BIN", str(tmp_path / "no-such-trivy"))
    code = main([str(fake_repo), "--runners", "trivy", "--output", str(tmp_path / "r.json")])
    assert code == EXIT_ERROR and "not installed" in capsys.readouterr().err
    assert not (tmp_path / "r.json").exists()
