from pathlib import Path

import pytest

from scanner.config import Config, ConfigError, load_config


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "scan.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_config(tmp_path):
    config = load_config(_write(tmp_path, (
        "fail_on: medium\ntimeout: 30\nallowed_hosts: [GitHub.com]\n"
        "allowlist:\n  rules: [private-key]\n  paths: ['docs/*']\n  fingerprints: [abc]\n"
    )))
    assert config.fail_on == "medium" and config.timeout == 30
    assert config.allowed_hosts == ("github.com",)
    assert config.allowlist.rules == {"private-key"} and config.allowlist.paths == ("docs/*",)


def test_empty_file_gives_defaults(tmp_path):
    assert load_config(_write(tmp_path, "")) == Config()


def test_missing_default_file_gives_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert load_config(None) == Config()


@pytest.mark.parametrize("text", [
    "fail_on: severe", "timeout: 0", "timeout: 99999", "timeout: true", "bogus: 1",
    "allowlist: [a]", "allowlist: {rules: nope}", "allowed_hosts: [1]", "- a\n- b", "a: [unclosed",
])
def test_invalid_config_is_rejected(tmp_path, text):
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, text))


def test_explicit_missing_file_is_an_error(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.yaml")
