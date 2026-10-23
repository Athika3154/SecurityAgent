"""Normalized finding model: whitelisted fields only, salted fingerprints, remediation text."""
import hashlib
import hmac
import os
from dataclasses import asdict, dataclass

SEVERITIES = ("low", "medium", "high", "critical")
DEFAULT_SALT = "scanner-default-salt"
SHORT_COMMIT_LEN = 8
REMEDIATION = (
    "Rotate or revoke this credential now and treat it as compromised. "
    "Then remove it from the code and, if it was committed, purge it from Git history. "
    "Deleting the line is not enough: the secret stays in history and in every clone."
)


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    secret_type: str
    severity: str
    tool: str
    commit: str
    fingerprint: str
    remediation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _fingerprint(tool: str, rule: str, file: str, line: int, commit: str) -> str:
    """Salted HMAC of the finding location. The secret value is never an input."""
    salt = (os.environ.get("SCAN_FP_SALT") or DEFAULT_SALT).encode("utf-8")
    message = "|".join((tool, rule, file, str(line), commit)).encode("utf-8")
    return hmac.new(salt, message, hashlib.sha256).hexdigest()[:32]


def make_finding(
    *, tool: str, rule: object, file: object, line: object, severity: str, commit: object
) -> Finding:
    """Validate whitelisted scanner fields and build a Finding. Raises ValueError if malformed."""
    if severity not in SEVERITIES:
        raise ValueError("unknown severity")
    for name, value in (("rule", rule), ("file", file), ("commit", commit)):
        if not isinstance(value, str) or not value:
            raise ValueError(f"missing {name}")
    if isinstance(line, bool) or not isinstance(line, int) or line < 0:
        raise ValueError("invalid line number")
    path = file.replace("\\", "/")
    return Finding(
        file=path,
        line=line,
        secret_type=rule,
        severity=severity,
        tool=tool,
        commit=commit[:SHORT_COMMIT_LEN],
        fingerprint=_fingerprint(tool, rule, path, line, commit),
        remediation=REMEDIATION,
    )
