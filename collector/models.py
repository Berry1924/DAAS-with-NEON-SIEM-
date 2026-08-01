from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TelemetryRecord:
    source_type: str
    source_event_id: str
    payload: dict[str, Any]

    def as_ingestion_request(self) -> dict[str, Any]:
        return {"source_type": self.source_type, "source_event_id": self.source_event_id, "payload": self.payload}
