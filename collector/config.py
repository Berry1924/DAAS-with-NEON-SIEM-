"""Configuration loading and validation for the CyberWolf collector."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
from urllib.parse import urlparse

import yaml


_ENV = re.compile(r"\$\{([A-Z0-9_]+)\}")
_SOURCES = {"linux_auth", "json"}


@dataclass(frozen=True)
class WatchedPath:
    path: Path
    source_type: str


@dataclass(frozen=True)
class CollectorConfig:
    api_url: str
    jwt_token: str
    watched_paths: tuple[WatchedPath, ...]
    collector_id: str = "collector-demo"
    batch_size: int = 25
    flush_interval_seconds: float = 5.0
    retry_count: int = 3
    heartbeat_interval_seconds: float = 60.0
    offset_path: Path = Path("collector/offsets.json")


def _expand(value: object) -> object:
    if isinstance(value, str):
        return _ENV.sub(lambda match: os.environ.get(match.group(1), ""), value)
    return value


def load_config(path: str | Path) -> CollectorConfig:
    """Load a YAML configuration without ever logging its token."""
    config_path = Path(path)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("collector configuration must be a mapping")

    api_url = str(_expand(raw.get("api_url", ""))).rstrip("/")
    parsed = urlparse(api_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("api_url must be an absolute HTTP(S) URL")
    token = str(_expand(raw.get("jwt_token", ""))).strip()
    if not token or token.lower() in {"changeme", "replace-me", "example"}:
        raise ValueError("jwt_token must be supplied through configuration or environment")

    watched_raw = raw.get("watched_paths", [])
    if not isinstance(watched_raw, list) or not watched_raw:
        raise ValueError("watched_paths must contain at least one path")
    watched: list[WatchedPath] = []
    for item in watched_raw:
        if not isinstance(item, dict):
            raise ValueError("each watched path must be a mapping")
        source_type = str(item.get("source_type", ""))
        if source_type not in _SOURCES:
            raise ValueError(f"unsupported source_type: {source_type}")
        watched_path = str(_expand(item.get("path", ""))).strip()
        if not watched_path:
            raise ValueError("watched path cannot be empty")
        watched.append(WatchedPath(Path(watched_path), source_type))

    def positive(name: str, default: object, maximum: int | None = None) -> float:
        value = float(raw.get(name, default))
        if value <= 0 or (maximum is not None and value > maximum):
            raise ValueError(f"{name} is outside its supported range")
        return value

    batch_size = int(positive("batch_size", 25, 100))
    retry_count = int(positive("retry_count", 3, 3))
    return CollectorConfig(
        api_url=api_url,
        jwt_token=token,
        watched_paths=tuple(watched),
        collector_id=str(raw.get("collector_id", "collector-demo")),
        batch_size=batch_size,
        flush_interval_seconds=positive("flush_interval_seconds", 5),
        retry_count=retry_count,
        heartbeat_interval_seconds=positive("heartbeat_interval_seconds", 60),
        offset_path=Path(str(raw.get("offset_path", "collector/offsets.json"))),
    )
