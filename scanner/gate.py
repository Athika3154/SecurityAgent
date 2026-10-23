"""Allowlist filtering and the pass/fail decision."""
from fnmatch import fnmatchcase

from scanner.config import Allowlist
from scanner.normalizer import SEVERITIES, Finding

EXIT_CLEAN = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 2


def _is_allowed(finding: Finding, allowlist: Allowlist) -> bool:
    return (
        finding.fingerprint in allowlist.fingerprints
        or finding.secret_type in allowlist.rules
        or any(fnmatchcase(finding.file, pattern) for pattern in allowlist.paths)
    )


def apply_allowlist(findings: list[Finding], allowlist: Allowlist) -> tuple[list[Finding], int]:
    """Return (kept findings, number suppressed)."""
    kept = [finding for finding in findings if not _is_allowed(finding, allowlist)]
    return kept, len(findings) - len(kept)


def exit_code(findings: list[Finding], fail_on: str) -> int:
    """EXIT_FINDINGS if any finding is at or above fail_on, else EXIT_CLEAN."""
    threshold = SEVERITIES.index(fail_on)
    if any(SEVERITIES.index(finding.severity) >= threshold for finding in findings):
        return EXIT_FINDINGS
    return EXIT_CLEAN
