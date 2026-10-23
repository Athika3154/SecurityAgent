"""Semgrep Community runner: code flaws (and secrets Semgrep's registry rules recognize)."""
import json
import os
import tempfile
from pathlib import Path

from scanner.normalizer import Finding, make_finding
from scanner.runners import ScannerError, head_commit, restrict_to_range, run_quiet

# Rules are fetched from the Semgrep registry (rules only; no code is uploaded, metrics are off).
_RULESET = "p/default"
_SEVERITY = {"INFO": "low", "WARNING": "medium", "ERROR": "high"}


def _field(raw: object, *path: str) -> object:
    """Whitelisted read of a nested report field. Never touches extra.lines or extra.message,
    which can contain matched source text."""
    for key in path:
        raw = raw.get(key) if isinstance(raw, dict) else None
    return raw


def _to_finding(raw: object, commit: str) -> Finding:
    check_id = _field(raw, "check_id")
    severity = _SEVERITY.get(str(_field(raw, "extra", "severity")))
    if severity is None or not isinstance(check_id, str) or not check_id:
        raise ValueError("malformed semgrep result")
    name = check_id.rsplit(".", 1)[-1]
    is_secret = ".secrets." in check_id
    return make_finding(
        tool="semgrep",
        rule=check_id,
        category="secret" if is_secret else "code",
        title=name.replace("-", " ").replace("_", " "),
        file=_field(raw, "path"),
        line=_field(raw, "start", "line"),
        severity=severity,
        commit=commit,
        remediation=None if is_secret else (
            f"Fix the flagged code ({name}); see https://semgrep.dev/r/{check_id} for guidance."
        ),
    )


def _read_report(report: Path, commit: str) -> list[Finding]:
    try:
        with report.open(encoding="utf-8") as handle:
            raw = json.load(handle)
        results = raw["results"] if isinstance(raw, dict) else None
        if not isinstance(results, list):
            raise ValueError("report has no results list")
        return [_to_finding(entry, commit) for entry in results]
    except (OSError, ValueError, KeyError):
        raise ScannerError("semgrep produced an unreadable or malformed report") from None


class SemgrepRunner:
    name = "semgrep"
    history = False

    def run(self, repo: Path, timeout: int, commit_range: str | None = None) -> list[Finding]:
        binary = os.environ.get("SCAN_SEMGREP_BIN", "semgrep")
        commit = head_commit(repo, timeout, commit_range)
        env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "PYTHONUTF8": "1"}
        with tempfile.TemporaryDirectory(prefix="scanner-") as tmp:
            report = Path(tmp) / "report.json"
            code = run_quiet(
                [
                    binary, "scan",
                    "--config", _RULESET,
                    "--json", "--output", str(report),
                    "--metrics", "off",
                    "--disable-version-check",
                    # The scanned repo must not be able to hide findings from the scan.
                    "--disable-nosem",
                    "--no-git-ignore",
                    "--x-ignore-semgrepignore-files",
                    "--quiet",
                    ".",
                ],
                timeout,
                "semgrep",
                env=env,
                cwd=repo,
            )
            if code != 0:
                raise ScannerError(f"semgrep failed with exit code {code}")
            findings = _read_report(report, commit)
        return restrict_to_range(findings, repo, timeout, commit_range)


RUNNER = SemgrepRunner()
