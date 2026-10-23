"""Resolve the scan target: a local Git repo or an https repo URL cloned with full history."""
import os
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from scanner.config import Config
from scanner.runners import ScannerError, run_quiet


_COMMIT_RANGE = re.compile(r"[0-9a-f]{7,40}\.\.[0-9a-f]{7,40}")


def validate_commit_range(commit_range: str) -> str:
    """Accept only <sha>..<sha>; the value is handed to git log, so nothing else may pass."""
    if not _COMMIT_RANGE.fullmatch(commit_range):
        raise ScannerError("commit range must look like <base-sha>..<head-sha>")
    return commit_range


def _validate_url(source: str, allowed_hosts: tuple[str, ...]) -> str:
    parts = urlsplit(source)
    if any(ord(char) < 33 for char in source):
        raise ScannerError("repository URL contains whitespace or control characters")
    if parts.scheme != "https":
        raise ScannerError("only https repository URLs are supported")
    if parts.username or parts.password:
        raise ScannerError("repository URL must not contain credentials")
    if (parts.hostname or "").lower() not in allowed_hosts:
        raise ScannerError("repository host is not in allowed_hosts")
    if parts.path in ("", "/"):
        raise ScannerError("repository URL has no path")
    return source


def _clone(url: str, dest: Path, timeout: int) -> None:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    code = run_quiet(
        [
            "git", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
            "clone", "--quiet", "--", url, str(dest),
        ],
        timeout,
        "git clone",
        env=env,
    )
    if code != 0:
        raise ScannerError("could not clone the repository (check the URL and your access)")


def _validate_local(source: str) -> Path:
    path = Path(source).expanduser().resolve()
    if not path.is_dir():
        raise ScannerError("scan target is not a directory")
    if not (path / ".git").exists():
        raise ScannerError("scan target is not a Git repository (history cannot be scanned)")
    return path


@contextmanager
def open_source(source: str, config: Config) -> Iterator[Path]:
    """Yield a local repo path; a cloned copy is deleted when the block exits."""
    if "://" not in source:
        yield _validate_local(source)
        return
    url = _validate_url(source, config.allowed_hosts)
    with tempfile.TemporaryDirectory(prefix="scanner-clone-") as tmp:
        dest = Path(tmp) / "repo"
        _clone(url, dest, config.timeout)
        yield dest
