import pytest

from scanner.config import Config
from scanner.runners import ScannerError
from scanner.sources import open_source


@pytest.mark.parametrize("url", [
    "http://github.com/o/r",
    "git://github.com/o/r",
    "https://user:pw@github.com/o/r",
    "https://evil.example.com/o/r",
    "https://github.com/",
    "https://github.com/o/r --upload-pack=x",
])
def test_bad_urls_are_rejected_before_any_clone(url, monkeypatch):
    monkeypatch.setattr("scanner.sources.run_quiet", lambda *a, **k: pytest.fail("cloned"))
    with pytest.raises(ScannerError):
        with open_source(url, Config()):
            pass


def test_non_git_directory_is_rejected(tmp_path):
    with pytest.raises(ScannerError):
        with open_source(str(tmp_path), Config()):
            pass


def test_missing_path_is_rejected(tmp_path):
    with pytest.raises(ScannerError):
        with open_source(str(tmp_path / "nope"), Config()):
            pass


def test_failed_clone_is_a_safe_error_and_cleans_up(monkeypatch, tmp_path):
    import tempfile
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr("scanner.sources.run_quiet", lambda *a, **k: 128)
    with pytest.raises(ScannerError):
        with open_source("https://github.com/o/r", Config()):
            pass
    assert list(tmp_path.iterdir()) == []


def test_local_git_repo_is_accepted(tmp_path):
    (tmp_path / ".git").mkdir()
    with open_source(str(tmp_path), Config()) as repo:
        assert repo == tmp_path.resolve()
