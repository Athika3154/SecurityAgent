import pytest

from scanner.normalizer import REMEDIATION, make_finding
from scanner.runners.gitleaks import _to_finding

COMMIT = "0123456789abcdef0123456789abcdef01234567"


def _make(**overrides):
    args = dict(tool="gitleaks", rule="aws-access-token", category="secret", title="AWS key",
                file="a/b.py", line=3,
                severity="high", commit=COMMIT)
    return make_finding(**{**args, **overrides})


def test_finding_has_required_fields_and_rotation_advice():
    finding = _make()
    assert (finding.file, finding.line, finding.rule) == ("a/b.py", 3, "aws-access-token")
    assert finding.severity == "high" and finding.tool == "gitleaks"
    assert finding.commit == COMMIT[:8]
    assert finding.remediation == REMEDIATION and "rotate" in finding.remediation.lower()


def test_fingerprint_is_stable_and_salted(monkeypatch):
    monkeypatch.setenv("SCAN_FP_SALT", "one")
    first, again = _make(), _make()
    monkeypatch.setenv("SCAN_FP_SALT", "two")
    other_salt = _make()
    assert first.fingerprint == again.fingerprint
    assert first.fingerprint != other_salt.fingerprint
    assert first.fingerprint != _make(line=4).fingerprint


@pytest.mark.parametrize("overrides", [
    {"severity": "urgent"}, {"rule": ""}, {"file": None}, {"commit": 5},
    {"line": -1}, {"line": "3"}, {"line": True},
])
def test_malformed_fields_are_rejected(overrides):
    with pytest.raises(ValueError):
        _make(**overrides)


def test_gitleaks_normalizer_drops_secret_fields():
    raw = {
        "RuleID": "github-pat", "File": "n.md", "StartLine": 1, "Commit": COMMIT,
        "Secret": "REDACTED-SECRET-VALUE", "Match": "token: SECRET-MATCH", "Line": "SECRET-LINE",
    }
    rendered = repr(_to_finding(raw).to_dict())
    for leaked in ("SECRET-VALUE", "SECRET-MATCH", "SECRET-LINE"):
        assert leaked not in rendered


def test_gitleaks_normalizer_rejects_non_object():
    with pytest.raises(ValueError):
        _to_finding("not a dict")
