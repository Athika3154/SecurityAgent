"""Normalized finding model: whitelisted fields only, salted fingerprints, remediation, merging."""
import hashlib
import hmac
import os
from dataclasses import asdict, dataclass, replace

SEVERITIES = ("low", "medium", "high", "critical")
CATEGORIES = ("secret", "vulnerability", "misconfiguration", "code")
DEFAULT_SALT = "scanner-default-salt"
SHORT_COMMIT_LEN = 8
MAX_TEXT_CHARS = 200
TOOL_SEPARATOR = ", "
REMEDIATION = (
    "Rotate or revoke this credential now and treat it as compromised. "
    "Then remove it from the code and, if it was committed, purge it from Git history. "
    "Deleting the line is not enough: the secret stays in history and in every clone."
)
_DEFAULT_REMEDIATION = {
    "secret": REMEDIATION,
    "vulnerability": "Upgrade the affected package to a fixed version, then re-run the scan.",
    "misconfiguration": "Fix the configuration as the rule describes, then re-run the scan.",
    "code": "Fix the flagged code pattern (see the rule's documentation) and add a test for it.",
}


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    rule: str
    category: str
    title: str
    severity: str
    tool: str
    commit: str
    fingerprint: str
    remediation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @property
    def location(self) -> str:
        """file:line, or just the file when the finding has no line (e.g. a dependency)."""
        return f"{self.file}:{self.line}" if self.line else self.file

    @property
    def tools(self) -> set[str]:
        return set(self.tool.split(TOOL_SEPARATOR))


def _clean(text: str) -> str:
    """One line, bounded length: scanner text is untrusted and ends up in reports."""
    return " ".join(text.split())[:MAX_TEXT_CHARS]


def _fingerprint(*parts: object) -> str:
    """Salted HMAC of the finding's identity. The secret value is never an input."""
    salt = (os.environ.get("SCAN_FP_SALT") or DEFAULT_SALT).encode("utf-8")
    message = "|".join(str(part) for part in parts).encode("utf-8")
    return hmac.new(salt, message, hashlib.sha256).hexdigest()[:32]


def _require_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing {name}")
    return value


def make_finding(
    *,
    tool: str,
    rule: object,
    category: str,
    title: object,
    file: object,
    line: object,
    severity: str,
    commit: object,
    remediation: object = None,
    detail: str = "",
    pin_commit: bool = False,
) -> Finding:
    """Validate whitelisted scanner fields and build a Finding. Raises ValueError if malformed.

    pin_commit: the finding belongs to one commit (history scan), so the commit is part of its
    fingerprint. Working-tree findings leave it out so the fingerprint survives new commits.
    detail: extra identity, e.g. the package name for a vulnerability.
    """
    if severity not in SEVERITIES:
        raise ValueError("unknown severity")
    if category not in CATEGORIES:
        raise ValueError("unknown category")
    if isinstance(line, bool) or not isinstance(line, int) or line < 0:
        raise ValueError("invalid line number")
    rule_text = _clean(_require_text("rule", rule))
    path = _require_text("file", file).replace("\\", "/")
    commit_text = _require_text("commit", commit)
    fixed = _DEFAULT_REMEDIATION[category] if remediation is None else _require_text(
        "remediation", remediation
    )
    return Finding(
        file=path,
        line=line,
        rule=rule_text,
        category=category,
        title=_clean(_require_text("title", title)),
        severity=severity,
        tool=tool,
        commit=commit_text[:SHORT_COMMIT_LEN],
        fingerprint=_fingerprint(
            tool, category, rule_text, path, line, detail, commit_text if pin_commit else ""
        ),
        remediation=_clean(fixed) if remediation is not None else fixed,
    )


def _merge_key(finding: Finding) -> tuple[object, ...]:
    # Different tools name the same secret differently, so secrets match on location only.
    if finding.category == "secret":
        return (finding.category, finding.file, finding.line)
    return (finding.category, finding.file, finding.line, finding.rule)


def _absorb(kept: Finding, other: Finding) -> Finding:
    """Combine two reports of the same issue: union of tools, highest severity, kept's identity."""
    tools = TOOL_SEPARATOR.join(sorted(kept.tools | other.tools))
    severity = max(kept.severity, other.severity, key=SEVERITIES.index)
    return replace(kept, tool=tools, severity=severity)


def merge_findings(history: list[Finding], current: list[Finding]) -> list[Finding]:
    """Dedupe across tools. History findings (one per commit) are all kept; working-tree
    findings fold into any matching finding from a different tool, or are added.
    Findings from the same tool are never merged."""
    merged = list(history)
    index: dict[tuple[object, ...], list[int]] = {}
    for position, finding in enumerate(merged):
        index.setdefault(_merge_key(finding), []).append(position)
    for finding in current:
        key = _merge_key(finding)
        matches = [i for i in index.get(key, []) if merged[i].tools.isdisjoint(finding.tools)]
        if matches:
            for position in matches:
                merged[position] = _absorb(merged[position], finding)
        else:
            merged.append(finding)
            index.setdefault(key, []).append(len(merged) - 1)
    return merged
