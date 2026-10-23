import json

import pytest

from scanner.cli import main
from scanner.gate import EXIT_ERROR, EXIT_FINDINGS
from scanner.normalizer import make_finding
from scanner.report import build_report, build_sarif, render_html, write_html
from scanner.runners import ScannerError
from tests.conftest import FAKE_SECRETS, requires_gitleaks


def _finding(rule="aws-access-token", file="a.py", line=3, severity="critical"):
    return make_finding(tool="gitleaks", rule=rule, file=file, line=line,
                        severity=severity, commit="abcdef123456")


def test_sarif_structure():
    findings = [_finding(), _finding(line=9), _finding(rule="github-pat", severity="high")]
    sarif = build_sarif(findings)
    assert sarif["version"] == "2.1.0" and sarif["$schema"].endswith("sarif-2.1.0.json")
    (run,) = sarif["runs"]
    rules, results = run["tool"]["driver"]["rules"], run["results"]
    assert [r["id"] for r in rules] == ["gitleaks/aws-access-token", "gitleaks/github-pat"]
    assert len(results) == 3
    for result in results:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        assert result["partialFingerprints"]["scannerFingerprint/v1"]
    assert {r["level"] for r in results} == {"error"}
    assert rules[0]["properties"]["security-severity"] == "9.5"
    assert "rotate" in rules[0]["help"]["text"].lower()


@pytest.mark.parametrize("severity,level", [("low", "note"), ("medium", "warning"),
                                            ("high", "error"), ("critical", "error")])
def test_sarif_levels(severity, level):
    (result,) = build_sarif([_finding(severity=severity)])["runs"][0]["results"]
    assert result["level"] == level


def test_sarif_clamps_line_zero_and_handles_no_findings():
    assert build_sarif([_finding(line=0)])["runs"][0]["results"][0][
        "locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    empty = build_sarif([])["runs"][0]
    assert empty["results"] == [] and empty["tool"]["driver"]["rules"] == []


def test_html_escapes_untrusted_values():
    hostile = _finding(file="<script>alert(1)</script>.py", rule='"><img src=x onerror=alert(1)>')
    html = render_html(build_report('<b onmouseover=x>src</b>', [hostile], 0))
    assert "<script>alert(1)" not in html and "<img src=x" not in html
    assert "<b onmouseover" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;.py" in html


def test_html_shows_findings_and_empty_state():
    html = render_html(build_report("repo", [_finding()], 2))
    assert "aws-access-token" in html and "a.py:3" in html and "rotate" in html.lower()
    assert "No findings" in render_html(build_report("repo", [], 0))


def test_html_write_failure_is_a_safe_error(tmp_path):
    with pytest.raises(ScannerError):
        write_html(build_report("repo", [], 0), tmp_path / "missing-dir" / "r.html")


@requires_gitleaks
def test_cli_writes_all_formats_without_secrets(fake_repo, tmp_path):
    paths = {name: tmp_path / name for name in ("r.json", "r.sarif", "r.html")}
    code = main([str(fake_repo), "--output", str(paths["r.json"]),
                 "--sarif", str(paths["r.sarif"]), "--html", str(paths["r.html"])])
    assert code == EXIT_FINDINGS
    sarif = json.loads(paths["r.sarif"].read_text(encoding="utf-8"))
    assert len(sarif["runs"][0]["results"]) == 2
    assert "settings.py" in paths["r.html"].read_text(encoding="utf-8")
    for path in paths.values():
        text = path.read_text(encoding="utf-8")
        assert not any(secret in text or secret[:12] in text for secret in FAKE_SECRETS)


def test_unwritable_sarif_path_exits_1(fake_repo, tmp_path, monkeypatch):
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0))
    code = main([str(fake_repo), "--output", str(tmp_path / "r.json"),
                 "--sarif", str(tmp_path / "nope" / "r.sarif")])
    assert code == EXIT_ERROR
