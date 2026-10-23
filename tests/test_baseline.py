import json
import shutil
import subprocess

import pytest

from scanner.baseline import VERSION, apply_baseline, load_baseline, write_baseline
from scanner.cli import main
from scanner.config import ConfigError
from scanner.gate import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS
from scanner.normalizer import make_finding
from scanner.runners import ScannerError
from tests.conftest import FAKE_SECRETS, requires_gitleaks


def _finding(file="a.py", line=1):
    return make_finding(tool="gitleaks", rule="r", category="secret", title="t", file=file,
                        line=line, severity="high", commit="c" * 40, pin_commit=True)


def _baseline_file(tmp_path, document):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_write_then_load_roundtrip_is_sorted_and_unique(tmp_path):
    findings = [_finding(line=2), _finding(line=1), _finding(line=1)]
    path = tmp_path / "baseline.json"
    write_baseline(findings, path)
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["version"] == VERSION
    assert document["fingerprints"] == sorted({f.fingerprint for f in findings})
    assert load_baseline(path) == {f.fingerprint for f in findings}


def test_apply_baseline_ignores_only_known_fingerprints():
    known, new = _finding(line=1), _finding(line=2)
    kept, ignored = apply_baseline([known, new], frozenset({known.fingerprint}))
    assert kept == [new] and ignored == 1


@pytest.mark.parametrize("document", [
    [], {}, {"version": 2, "fingerprints": []}, {"version": 1}, {"version": 1, "fingerprints": "x"},
    {"version": 1, "fingerprints": [1]}, {"version": 1, "fingerprints": ["not-hex"]},
    {"version": 1, "fingerprints": ["A" * 32]}, {"version": 1, "fingerprints": ["a" * 31]},
])
def test_invalid_baselines_are_rejected(tmp_path, document):
    with pytest.raises(ConfigError):
        load_baseline(_baseline_file(tmp_path, document))


def test_missing_or_unparseable_baseline_is_rejected(tmp_path):
    with pytest.raises(ConfigError):
        load_baseline(tmp_path / "nope.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{oops", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_baseline(bad)


def test_unwritable_baseline_path_is_a_safe_error(tmp_path):
    with pytest.raises(ScannerError):
        write_baseline([_finding()], tmp_path / "missing-dir" / "b.json")


def test_baseline_and_write_baseline_are_mutually_exclusive(fake_repo, tmp_path, capsys):
    with pytest.raises(SystemExit) as info:
        main([str(fake_repo), "--baseline", str(tmp_path / "a"), "--write-baseline", str(tmp_path / "b")])
    assert info.value.code == EXIT_ERROR and "cannot be used together" in capsys.readouterr().err


@requires_gitleaks
def test_only_new_findings_fail_once_a_baseline_exists(fake_repo, tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(fake_repo, repo)
    baseline = tmp_path / "baseline.json"
    common = ["--runners", "gitleaks", "--output", str(tmp_path / "report.json")]

    # 1. Record today's findings: exits 0 even though secrets exist, writes no secrets.
    assert main([str(repo), *common, "--write-baseline", str(baseline)]) == EXIT_CLEAN
    text = baseline.read_text(encoding="utf-8")
    assert len(json.loads(text)["fingerprints"]) == 2
    assert not any(secret in text for secret in FAKE_SECRETS)

    # 2. Same repo, with the baseline: nothing new, so the gate passes.
    assert main([str(repo), *common, "--baseline", str(baseline)]) == EXIT_CLEAN
    summary = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["summary"]
    assert summary["total"] == 0 and summary["baselined"] == 2

    # 3. A new secret in a new commit is not in the baseline, so only it fails the gate.
    new_secret = "AKIA" + "ZXCVBNM5QWERTY47"
    (repo / "extra.py").write_text(f'KEY = "{new_secret}"\n', encoding="utf-8")
    for args in (["add", "-A"], ["-c", "user.name=T", "-c", "user.email=t@example.com",
                                 "-c", "commit.gpgsign=false", "commit", "-q", "-m", "more"]):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    assert main([str(repo), *common, "--baseline", str(baseline)]) == EXIT_FINDINGS
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert [f["file"] for f in report["findings"]] == ["extra.py"]
    assert report["summary"]["baselined"] == 2
    assert new_secret not in (tmp_path / "report.json").read_text(encoding="utf-8")


def test_invalid_baseline_fails_before_scanning(fake_repo, tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("scanner was run"))
    bad = _baseline_file(tmp_path, {"version": 9})
    assert main([str(fake_repo), "--runners", "gitleaks", "--baseline", str(bad),
                 "--output", str(tmp_path / "r.json")]) == EXIT_ERROR


def test_failed_baseline_write_exits_1(fake_repo, tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0))
    code = main([str(fake_repo), "--runners", "gitleaks",
                 "--write-baseline", str(tmp_path / "nope" / "b.json")])
    assert code == EXIT_ERROR
