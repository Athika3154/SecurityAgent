"""Runner interface and discovery. Adding a scanner means adding one module with a RUNNER."""
import importlib
import pkgutil
import subprocess
from pathlib import Path
from typing import Mapping, Protocol, Sequence

from scanner.normalizer import Finding


class ScannerError(Exception):
    """A scanner or its input failed. Messages must be safe to print (no secrets)."""


class Runner(Protocol):
    name: str
    # True if the runner reads Git history (findings belong to commits), False if it
    # scans the checked-out working tree.
    history: bool

    def run(self, repo: Path, timeout: int, commit_range: str | None = None) -> list[Finding]:
        """Scan the repo (only commit_range, if given) and return normalized findings."""


def _run(
    cmd: Sequence[str],
    timeout: int,
    label: str,
    env: Mapping[str, str] | None,
    cwd: Path | None,
    stdout: int,
) -> subprocess.CompletedProcess:
    """Run a command; stderr is always discarded because it can echo secrets."""
    try:
        return subprocess.run(
            list(cmd),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            env=env,
            cwd=cwd,
            check=False,
        )
    except FileNotFoundError:
        raise ScannerError(f"{label} is not installed or not on PATH") from None
    except subprocess.TimeoutExpired:
        raise ScannerError(f"{label} timed out after {timeout}s") from None
    except OSError:
        raise ScannerError(f"{label} could not be started") from None


def run_quiet(
    cmd: Sequence[str],
    timeout: int,
    label: str,
    env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
) -> int:
    """Run a command with all output discarded; return its exit code."""
    return _run(cmd, timeout, label, env, cwd, subprocess.DEVNULL).returncode


def run_capture(cmd: Sequence[str], timeout: int, label: str) -> str:
    """Run a command and return its stdout. Only for commands whose output is never secret."""
    done = _run(cmd, timeout, label, None, None, subprocess.PIPE)
    if done.returncode != 0:
        raise ScannerError(f"{label} failed with exit code {done.returncode}")
    return done.stdout.decode("utf-8", errors="replace")


def head_commit(repo: Path, timeout: int, commit_range: str | None) -> str:
    """The commit a working-tree scan describes: the range head, else the repo's HEAD."""
    if commit_range:
        return commit_range.split("..")[1]
    return run_capture(["git", "-C", str(repo), "rev-parse", "HEAD"], timeout, "git").strip()


def restrict_to_range(
    findings: list[Finding], repo: Path, timeout: int, commit_range: str | None
) -> list[Finding]:
    """In PR mode keep only findings in files the PR touched (working-tree scanners see all)."""
    if not commit_range:
        return findings
    base, head = commit_range.split("..")
    names = run_capture(
        ["git", "-C", str(repo), "diff", "--name-only", "-z", base, head, "--"], timeout, "git"
    )
    touched = {name for name in names.split("\0") if name}
    return [finding for finding in findings if finding.file in touched]


def load_runners(names: Sequence[str] | None = None) -> list[Runner]:
    """Import every module in this package, collect its RUNNER, optionally filter by name."""
    modules = (
        importlib.import_module(f"{__name__}.{info.name}")
        for info in pkgutil.iter_modules(__path__)
    )
    runners = [module.RUNNER for module in modules]
    if names is None:
        return runners
    unknown = set(names) - {runner.name for runner in runners}
    if unknown:
        raise ScannerError(f"unknown runner(s): {', '.join(sorted(unknown))}")
    return [runner for runner in runners if runner.name in names]
