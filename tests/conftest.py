import os
import shutil
import subprocess
from pathlib import Path

import pytest

# Fake secrets, assembled at runtime so this source file never contains a full token.
FAKE_AWS = "AKIA" + "QYLPMN5HFIQR7XYZ"
FAKE_GITHUB = "ghp_" + "R4nD0mT0k3nV4lu3AbCdEfGhIjKlMnOpQr12"
FAKE_SECRETS = (FAKE_AWS, FAKE_GITHUB)

requires_gitleaks = pytest.mark.skipif(
    shutil.which(os.environ.get("SCAN_GITLEAKS_BIN", "gitleaks")) is None,
    reason="gitleaks binary not found (install it or set SCAN_GITLEAKS_BIN)",
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
         "-c", "commit.gpgsign=false", *args],
        cwd=repo, check=True, capture_output=True,
    )


@pytest.fixture(scope="session")
def fake_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Git repo: AWS key added then deleted (history only), GitHub token still in HEAD."""
    repo = tmp_path_factory.mktemp("fake_repo")
    _git(repo, "init", "-q", "-b", "main")
    (repo / "settings.py").write_text(f'AWS_KEY = "{FAKE_AWS}"\n', encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add settings")
    (repo / "settings.py").unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "remove settings")
    (repo / "notes.md").write_text(f"token: {FAKE_GITHUB}\n", encoding="utf-8")
    (repo / "readme.txt").write_text("nothing secret here\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add notes")
    return repo
