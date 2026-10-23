"""Gitleaks runner: secrets across the full Git history."""
import json
import os
import tempfile
from pathlib import Path

from scanner.normalizer import Finding, make_finding
from scanner.runners import ScannerError, run_quiet

# Gitleaks exits 1 on errors and on leaks by default. A distinct code for leaks
# means a crash can never be mistaken for "findings" or for "clean".
_LEAKS_EXIT = 3
_RULES_ONLY_CONFIG = "[extend]\nuseDefault = true\n"
_CRITICAL_RULES = frozenset({"private-key", "aws-access-token"})
# Only these report fields are ever read; Secret, Match and Line are never touched.
_FIELDS = ("RuleID", "Description", "File", "StartLine", "Commit")


def _severity(rule: object) -> str:
    return "critical" if rule in _CRITICAL_RULES else "high"


def _to_finding(raw: object) -> Finding:
    if not isinstance(raw, dict):
        raise ValueError("report entry is not an object")
    safe = {name: raw.get(name) for name in _FIELDS}
    return make_finding(
        tool="gitleaks",
        rule=safe["RuleID"],
        category="secret",
        title=safe["Description"] or safe["RuleID"],
        file=safe["File"],
        line=safe["StartLine"],
        severity=_severity(safe["RuleID"]),
        commit=safe["Commit"],
        pin_commit=True,
    )


def _read_report(report: Path) -> list[Finding]:
    try:
        with report.open(encoding="utf-8") as handle:
            raw = json.load(handle)
        if not isinstance(raw, list):
            raise ValueError("report is not a list")
        return [_to_finding(entry) for entry in raw]
    except (OSError, ValueError):
        raise ScannerError("gitleaks produced an unreadable or malformed report") from None


class GitleaksRunner:
    name = "gitleaks"
    history = True

    def run(self, repo: Path, timeout: int, commit_range: str | None = None) -> list[Finding]:
        binary = os.environ.get("SCAN_GITLEAKS_BIN", "gitleaks")
        # Temp dir holds the raw report; it is removed on exit even if the scan fails.
        with tempfile.TemporaryDirectory(prefix="scanner-") as tmp:
            report = Path(tmp) / "report.json"
            # Our own config and an empty ignore file, so the scanned repo's
            # .gitleaks.toml / .gitleaksignore cannot weaken the scan.
            config = Path(tmp) / "gitleaks.toml"
            ignore = Path(tmp) / "gitleaksignore"
            try:
                config.write_text(_RULES_ONLY_CONFIG, encoding="utf-8")
                ignore.write_text("", encoding="utf-8")
            except OSError:
                raise ScannerError("could not prepare gitleaks configuration") from None
            cmd = [
                binary, "git", str(repo),
                "--config", str(config),
                "--gitleaks-ignore-path", str(ignore),
                "--report-format", "json",
                "--report-path", str(report),
                "--redact",
                "--no-banner",
                "--exit-code", str(_LEAKS_EXIT),
            ]
            if commit_range:
                cmd.append(f"--log-opts={commit_range}")
            code = run_quiet(cmd, timeout, "gitleaks")
            if code == 0:
                return _read_report(report) if report.exists() else []
            if code == _LEAKS_EXIT:
                return _read_report(report)
            raise ScannerError(f"gitleaks failed with exit code {code}")


RUNNER = GitleaksRunner()
