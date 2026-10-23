import pytest

from scanner.cli import run_scan
from scanner.config import Config
from scanner.normalizer import make_finding, merge_findings
from scanner.runners import ScannerError


def _f(tool="gitleaks", rule="r", category="secret", file="a.py", line=1, severity="high",
       commit="c" * 40, pin=False):
    return make_finding(tool=tool, rule=rule, category=category, title=rule, file=file, line=line,
                        severity=severity, commit=commit, pin_commit=pin)


def test_same_secret_from_three_tools_becomes_one_finding():
    history = [_f("gitleaks", "generic-api-key", severity="high", pin=True)]
    current = [_f("trivy", "aws-key", severity="critical"),
               _f("semgrep", "detected-aws", severity="high")]
    (merged,) = merge_findings(history, current)
    assert merged.tool == "gitleaks, semgrep, trivy" and merged.severity == "critical"
    assert merged.fingerprint == history[0].fingerprint and merged.rule == "generic-api-key"


def test_history_findings_from_different_commits_are_all_kept():
    history = [_f(commit="1" * 40, pin=True), _f(commit="2" * 40, pin=True)]
    merged = merge_findings(history, [_f("trivy")])
    assert len(merged) == 2 and all(m.tool == "gitleaks, trivy" for m in merged)


def test_findings_from_the_same_tool_are_never_merged():
    assert len(merge_findings([], [_f("trivy", line=3), _f("trivy", line=3)])) == 2


def test_different_locations_or_rules_stay_separate():
    assert len(merge_findings([_f("gitleaks", line=1, pin=True)], [_f("trivy", line=2)])) == 2
    assert len(merge_findings([], [_f("trivy", category="code", rule="x", line=4),
                                   _f("semgrep", category="code", rule="y", line=4)])) == 2
    assert len(merge_findings([], [_f("trivy", category="code", rule="x", line=4),
                                   _f("semgrep", category="code", rule="x", line=4)])) == 1


def test_secret_and_code_finding_on_the_same_line_stay_separate():
    assert len(merge_findings([], [_f("trivy"), _f("semgrep", category="code")])) == 2


def test_working_tree_fingerprint_survives_new_commits_but_history_does_not():
    assert _f("trivy", commit="1" * 40).fingerprint == _f("trivy", commit="2" * 40).fingerprint
    assert _f(commit="1" * 40, pin=True).fingerprint != _f(commit="2" * 40, pin=True).fingerprint


def test_dependency_detail_is_part_of_the_fingerprint():
    def dep(package):
        return make_finding(tool="trivy", rule="CVE-1", category="vulnerability", title="t",
                            file="r.txt", line=0, severity="high", commit="c" * 8, detail=package)

    assert dep("flask").fingerprint != dep("jinja2").fingerprint


class _FakeRunner:
    def __init__(self, name, history, findings):
        self.name, self.history, self._findings = name, history, findings

    def run(self, repo, timeout, commit_range=None):
        return list(self._findings)


def test_run_scan_merges_across_runners_and_filters_by_name(fake_repo, monkeypatch):
    vuln = _f("trivy", category="vulnerability", rule="CVE-1", file="r.txt", line=0)
    runners = [_FakeRunner("gitleaks", True, [_f("gitleaks", pin=True)]),
               _FakeRunner("trivy", False, [_f("trivy"), vuln])]
    monkeypatch.setattr("scanner.cli.load_runners",
                        lambda names=None: [r for r in runners if names is None or r.name in names])
    findings, suppressed = run_scan(str(fake_repo), Config())
    assert sorted(f.tool for f in findings) == ["gitleaks, trivy", "trivy"] and suppressed == 0
    only, _ = run_scan(str(fake_repo), Config(), runner_names=["gitleaks"])
    assert [f.tool for f in only] == ["gitleaks"]


def test_unknown_or_empty_runner_selection_is_an_error(fake_repo):
    with pytest.raises(ScannerError, match="unknown runner"):
        run_scan(str(fake_repo), Config(), runner_names=["nope"])
    with pytest.raises(ScannerError, match="unknown runner"):
        run_scan(str(fake_repo), Config(), runner_names=[""])
