import pytest

from scanner.config import Allowlist
from scanner.gate import EXIT_CLEAN, EXIT_FINDINGS, apply_allowlist, exit_code
from scanner.normalizer import SEVERITIES, make_finding


def _finding(rule="aws-access-token", file="src/app.py", severity="high"):
    return make_finding(tool="gitleaks", rule=rule, file=file, line=1,
                        severity=severity, commit="abcdef123456")


@pytest.mark.parametrize("fail_on", SEVERITIES)
@pytest.mark.parametrize("severity", SEVERITIES)
def test_exit_code_at_every_level(fail_on, severity):
    expected = EXIT_FINDINGS if SEVERITIES.index(severity) >= SEVERITIES.index(fail_on) else EXIT_CLEAN
    assert exit_code([_finding(severity=severity)], fail_on) == expected


def test_no_findings_is_clean():
    assert exit_code([], "low") == EXIT_CLEAN


def test_allowlist_by_rule_path_and_fingerprint():
    target = _finding(rule="private-key", file="docs/example.pem")
    keep = _finding(rule="github-pat", file="src/real.py")
    for allowlist in (
        Allowlist(rules=frozenset({"private-key"})),
        Allowlist(paths=("docs/*",)),
        Allowlist(fingerprints=frozenset({target.fingerprint})),
    ):
        kept, suppressed = apply_allowlist([target, keep], allowlist)
        assert kept == [keep] and suppressed == 1


def test_empty_allowlist_suppresses_nothing():
    findings = [_finding()]
    assert apply_allowlist(findings, Allowlist()) == (findings, 0)
