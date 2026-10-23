"""Trivy runner: vulnerable dependencies, IaC misconfiguration and secrets in the working tree."""
import json
import os
import tempfile
from pathlib import Path

from scanner.normalizer import Finding, make_finding
from scanner.runners import ScannerError, head_commit, restrict_to_range, run_quiet

_SEVERITY = {
    "UNKNOWN": "low", "LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical",
}


def _severity(raw: object) -> str:
    level = _SEVERITY.get(str(raw))
    if level is None:
        raise ValueError("unknown trivy severity")
    return level


def _list(result: dict, key: str) -> list[dict]:
    items = result.get(key) or []
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise ValueError(f"{key} is not a list of objects")
    return items


def _vulnerability(item: dict, target: str, commit: str) -> Finding:
    package, installed, fixed = (str(item.get(k) or "") for k in ("PkgName", "InstalledVersion", "FixedVersion"))
    advice = (
        f"Upgrade {package} from {installed} to {fixed}."
        if fixed
        else f"No fixed version of {package} is published yet; replace it or mitigate."
    )
    return make_finding(
        tool="trivy", rule=item.get("VulnerabilityID"), category="vulnerability",
        title=f"{package} {installed}: {item.get('Title') or item.get('VulnerabilityID')}",
        file=target, line=0, severity=_severity(item.get("Severity")), commit=commit,
        remediation=advice, detail=package,
    )


def _misconfiguration(item: dict, target: str, commit: str) -> Finding:
    cause = item.get("CauseMetadata")
    line = cause.get("StartLine") if isinstance(cause, dict) else None
    return make_finding(
        tool="trivy", rule=item.get("ID"), category="misconfiguration", title=item.get("Title"),
        file=target, line=line or 0, severity=_severity(item.get("Severity")), commit=commit,
        remediation=item.get("Resolution") or None,
    )


def _secret(item: dict, target: str, commit: str) -> Finding:
    # Match and Code (the matched text) are never read.
    return make_finding(
        tool="trivy", rule=item.get("RuleID"), category="secret",
        title=item.get("Title") or item.get("RuleID"),
        file=target, line=item.get("StartLine"), severity=_severity(item.get("Severity")),
        commit=commit,
    )


def _to_findings(raw: object, commit: str) -> list[Finding]:
    if not isinstance(raw, dict):
        raise ValueError("report is not an object")
    findings: list[Finding] = []
    for result in raw.get("Results") or []:
        if not isinstance(result, dict) or not isinstance(result.get("Target"), str):
            raise ValueError("malformed trivy result")
        target = result["Target"]
        findings += [_vulnerability(i, target, commit) for i in _list(result, "Vulnerabilities")]
        findings += [_misconfiguration(i, target, commit) for i in _list(result, "Misconfigurations")]
        findings += [_secret(i, target, commit) for i in _list(result, "Secrets")]
    return findings


def _read_report(report: Path, commit: str) -> list[Finding]:
    try:
        with report.open(encoding="utf-8") as handle:
            return _to_findings(json.load(handle), commit)
    except (OSError, ValueError):
        raise ScannerError("trivy produced an unreadable or malformed report") from None


class TrivyRunner:
    name = "trivy"
    history = False

    def run(self, repo: Path, timeout: int, commit_range: str | None = None) -> list[Finding]:
        binary = os.environ.get("SCAN_TRIVY_BIN", "trivy")
        commit = head_commit(repo, timeout, commit_range)
        with tempfile.TemporaryDirectory(prefix="scanner-") as tmp:
            report = Path(tmp) / "report.json"
            # Empty config and ignore files, so the scanned repo's trivy.yaml and
            # .trivyignore cannot change the scan.
            empty = Path(tmp) / "empty"
            try:
                empty.write_text("", encoding="utf-8")
            except OSError:
                raise ScannerError("could not prepare trivy configuration") from None
            code = run_quiet(
                [
                    binary, "fs",
                    "--scanners", "vuln,secret,misconfig",
                    "--format", "json", "--output", str(report),
                    "--quiet", "--no-progress",
                    "--skip-dirs", ".git",
                    "--config", str(empty),
                    "--ignorefile", str(empty),
                    str(repo),
                ],
                timeout,
                "trivy",
            )
            if code != 0:
                raise ScannerError(f"trivy failed with exit code {code}")
            findings = _read_report(report, commit)
        return restrict_to_range(findings, repo, timeout, commit_range)


RUNNER = TrivyRunner()
