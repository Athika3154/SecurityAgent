"""Baseline of known findings, stored as fingerprints only (never secret values)."""
import json
import re
from pathlib import Path

from scanner.config import ConfigError
from scanner.normalizer import Finding
from scanner.runners import ScannerError

VERSION = 1
_FINGERPRINT = re.compile(r"[0-9a-f]{32}")


def load_baseline(path: Path) -> frozenset[str]:
    """Read the fingerprints of accepted findings. A missing or invalid file is an error,
    so a broken baseline can never silently hide (or reveal) findings."""
    try:
        with path.open(encoding="utf-8") as handle:
            raw = json.load(handle)
    except OSError:
        raise ConfigError(f"cannot read baseline file {path}") from None
    except ValueError:
        raise ConfigError(f"baseline file {path} is not valid JSON") from None
    fingerprints = raw.get("fingerprints") if isinstance(raw, dict) else None
    if (
        not isinstance(raw, dict)
        or raw.get("version") != VERSION
        or not isinstance(fingerprints, list)
        or not all(isinstance(item, str) and _FINGERPRINT.fullmatch(item) for item in fingerprints)
    ):
        raise ConfigError(f"baseline file {path} has an unexpected format")
    return frozenset(fingerprints)


def apply_baseline(findings: list[Finding], known: frozenset[str]) -> tuple[list[Finding], int]:
    """Return (findings not in the baseline, number ignored)."""
    kept = [finding for finding in findings if finding.fingerprint not in known]
    return kept, len(findings) - len(kept)


def write_baseline(findings: list[Finding], path: Path) -> None:
    document = {"version": VERSION, "fingerprints": sorted({f.fingerprint for f in findings})}
    try:
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    except OSError:
        raise ScannerError(f"could not write baseline to {path}") from None
