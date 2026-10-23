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

    def run(self, repo: Path, timeout: int, commit_range: str | None = None) -> list[Finding]:
        """Scan the repo's Git history (only commit_range, if given); return findings."""


def run_quiet(
    cmd: Sequence[str], timeout: int, label: str, env: Mapping[str, str] | None = None
) -> int:
    """Run a command with all output discarded (it can echo secrets); return its exit code."""
    try:
        return subprocess.run(
            list(cmd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            env=env,
            check=False,
        ).returncode
    except FileNotFoundError:
        raise ScannerError(f"{label} is not installed or not on PATH") from None
    except subprocess.TimeoutExpired:
        raise ScannerError(f"{label} timed out after {timeout}s") from None
    except OSError:
        raise ScannerError(f"{label} could not be started") from None


def load_runners() -> list[Runner]:
    """Import every module in this package and collect its RUNNER."""
    modules = (
        importlib.import_module(f"{__name__}.{info.name}")
        for info in pkgutil.iter_modules(__path__)
    )
    return [module.RUNNER for module in modules]
