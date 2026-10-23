"""Load and validate scan.yaml."""
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from scanner.normalizer import SEVERITIES

DEFAULT_PATH = Path("scan.yaml")
MAX_TIMEOUT = 3600
_TOP_KEYS = {"fail_on", "timeout", "allowed_hosts", "allowlist"}
_ALLOWLIST_KEYS = {"fingerprints", "rules", "paths"}


class ConfigError(Exception):
    """scan.yaml is missing or invalid."""


@dataclass(frozen=True)
class Allowlist:
    fingerprints: frozenset[str] = frozenset()
    rules: frozenset[str] = frozenset()
    paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class Config:
    fail_on: str = "high"
    timeout: int = 600
    allowed_hosts: tuple[str, ...] = ("github.com",)
    allowlist: Allowlist = field(default_factory=Allowlist)


def _str_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ConfigError(f"{name} must be a list of non-empty strings")
    return value


def _parse_allowlist(raw: object) -> Allowlist:
    if not isinstance(raw, dict) or set(raw) - _ALLOWLIST_KEYS:
        raise ConfigError(f"allowlist must be a mapping with keys {sorted(_ALLOWLIST_KEYS)}")
    return Allowlist(
        fingerprints=frozenset(_str_list(raw.get("fingerprints", []), "allowlist.fingerprints")),
        rules=frozenset(_str_list(raw.get("rules", []), "allowlist.rules")),
        paths=tuple(_str_list(raw.get("paths", []), "allowlist.paths")),
    )


def _parse(raw: object) -> Config:
    if raw is None:
        return Config()
    if not isinstance(raw, dict) or set(raw) - _TOP_KEYS:
        raise ConfigError(f"config must be a mapping with keys {sorted(_TOP_KEYS)}")
    defaults = Config()
    fail_on = raw.get("fail_on", defaults.fail_on)
    if fail_on not in SEVERITIES:
        raise ConfigError(f"fail_on must be one of {list(SEVERITIES)}")
    timeout = raw.get("timeout", defaults.timeout)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= MAX_TIMEOUT:
        raise ConfigError(f"timeout must be an integer between 1 and {MAX_TIMEOUT}")
    hosts = _str_list(raw.get("allowed_hosts", list(defaults.allowed_hosts)), "allowed_hosts")
    return Config(
        fail_on=fail_on,
        timeout=timeout,
        allowed_hosts=tuple(host.lower() for host in hosts),
        allowlist=_parse_allowlist(raw.get("allowlist", {})),
    )


def load_config(path: Path | None) -> Config:
    """Load config from an explicit path (must exist) or ./scan.yaml (optional)."""
    if path is None:
        if not DEFAULT_PATH.is_file():
            return Config()
        path = DEFAULT_PATH
    try:
        with path.open(encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
    except OSError:
        raise ConfigError(f"cannot read config file {path}") from None
    except yaml.YAMLError:
        raise ConfigError(f"config file {path} is not valid YAML") from None
    return _parse(raw)
