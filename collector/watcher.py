"""Tail only new Linux-auth and JSON log entries."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from .models import TelemetryRecord
from .offsets import OffsetStore

logger = logging.getLogger(__name__)


class FileWatcher:
    def __init__(self, offsets: OffsetStore, collector_id: str) -> None:
        self.offsets = offsets
        self.collector_id = collector_id

    def read_new(self, path: Path, source_type: str) -> list[TelemetryRecord]:
        """Return appended valid entries; first observation deliberately starts at EOF."""
        if not path.is_file():
            logger.warning("watched log is unavailable: %s", path.name)
            return []
        size = path.stat().st_size
        stored = self.offsets.get(path)
        if stored is None:
            self.offsets.set(path, size)
            return []
        start = 0 if stored > size else stored
        records: list[TelemetryRecord] = []
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            stream.seek(start)
            while True:
                byte_offset = stream.tell()
                line = stream.readline()
                if not line:
                    break
                text = line.rstrip("\r\n")
                if not text:
                    continue
                payload = self._payload(text, source_type, path)
                if payload is None:
                    continue
                digest = hashlib.sha256(
                    f"{self.collector_id}:{path.resolve()}:{byte_offset}".encode("utf-8")
                ).hexdigest()
                records.append(TelemetryRecord(source_type, digest, payload))
            self.offsets.set(path, stream.tell())
        return records

    @staticmethod
    def _payload(line: str, source_type: str, path: Path) -> dict[str, object] | None:
        if source_type == "linux_auth":
            return {"message": line}
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("ignoring malformed JSON record from %s", path.name)
            return None
        if not isinstance(value, dict):
            logger.warning("ignoring non-object JSON record from %s", path.name)
            return None
        return value
