"""Configuration: `.env` (secrets, endpoints) + a network profile (devnet/mainnet TOML)."""

from __future__ import annotations

import os
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from cdz.crypto import SigningKey

NETWORKS_DIR = Path(__file__).parent / "networks"
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


class ConfigError(ValueError):
    pass


def load_env_file(path: str | os.PathLike = ".env", override: bool = False) -> dict[str, str]:
    """Minimal dotenv: KEY=VALUE, optional quotes, '#' comments. Process env wins unless override."""
    values: dict[str, str] = {}
    p = Path(path)
    if not p.is_file():
        return values
    if p.stat().st_mode & 0o077:
        print(f"warning: {p} is readable by group/others; chmod 600 {p}", file=sys.stderr)
    for raw in p.read_text().splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = _ENV_LINE.match(raw)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
            val = val[1:-1]
        elif val.startswith("#"):
            val = ""  # empty value followed by a comment
        elif " #" in val:
            val = val.split(" #", 1)[0].rstrip()
        values[key] = val
    for k, v in values.items():
        if override or k not in os.environ:
            os.environ[k] = v
    return values


def load_network(name: str) -> dict:
    p = Path(name)
    if not p.is_file():
        p = NETWORKS_DIR / f"{name}.toml"
    if not p.is_file():
        raise ConfigError(f"unknown network {name!r} (expected devnet, mainnet or a TOML path)")
    with p.open("rb") as f:
        net = tomllib.load(f)
    net.setdefault("name", p.stem)
    return net


def _read_secret(value: str) -> str:
    if value.startswith("file:"):
        return Path(value[5:]).expanduser().read_text()
    return value


def keys_from_env(prefix: str, env=None) -> list[SigningKey]:
    """Keys from `<prefix>1..n` (gaps allowed) or `<prefix><NAME>`; value = PEM/PKCS#8/seed or file:PATH."""
    env = os.environ if env is None else env
    out = []
    for k in sorted(env, key=_natural):
        if k.startswith(prefix) and env[k].strip():
            out.append(SigningKey.parse(_read_secret(env[k]), name=k[len(prefix):].lower() or k))
    return out


def _natural(s: str):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


@dataclass
class Settings:
    network: dict
    ledger_url: str | None = None
    ledger_user: str | None = None
    admin_addr: str | None = None
    admin_tls: bool = False
    admin_ca: str | None = None
    synchronizer_id: str | None = None
    party_file: str = "party.json"
    env: dict = field(default_factory=dict)

    @classmethod
    def load(cls, env_file: str = ".env", network: str | None = None) -> "Settings":
        load_env_file(env_file)
        e = os.environ
        net = load_network(network or e.get("CDZ_NETWORK", "devnet"))
        return cls(
            network=net,
            ledger_url=e.get("CDZ_LEDGER_URL"),
            ledger_user=e.get("CDZ_LEDGER_USER"),
            admin_addr=e.get("CDZ_ADMIN_ADDR"),
            admin_tls=e.get("CDZ_ADMIN_TLS", "false").lower() in ("1", "true", "yes"),
            admin_ca=e.get("CDZ_ADMIN_CA") or None,
            synchronizer_id=e.get("CDZ_SYNCHRONIZER_ID") or net.get("synchronizer_id") or None,
            party_file=e.get("CDZ_PARTY_FILE", "party.json"),
            env=dict(e),
        )

    def namespace_keys(self) -> list[SigningKey]:
        return keys_from_env("CDZ_NS_KEY_", self.env)

    def protocol_keys(self) -> list[SigningKey]:
        return keys_from_env("CDZ_TX_KEY_", self.env)

    def all_keys(self) -> list[SigningKey]:
        return self.namespace_keys() + self.protocol_keys()

    def require(self, attr: str, env_name: str) -> str:
        v = getattr(self, attr)
        if not v:
            raise ConfigError(f"{env_name} is not set (see .env.example)")
        return v
