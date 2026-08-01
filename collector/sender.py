"""Authenticated, bounded-retry sender for the existing M03 batch endpoint."""

from __future__ import annotations

import logging
import time
from typing import Callable, Sequence

import httpx

from .models import TelemetryRecord

logger = logging.getLogger(__name__)


class BatchSender:
    def __init__(self, api_url: str, jwt_token: str, retry_count: int = 3,
                 client: httpx.Client | None = None, sleep: Callable[[float], None] = time.sleep) -> None:
        self.endpoint = f"{api_url.rstrip('/')}/api/v1/events/batch"
        self.jwt_token = jwt_token
        self.retry_count = retry_count
        self.client = client or httpx.Client(timeout=10.0)
        self._owns_client = client is None
        self.sleep = sleep

    def send(self, records: Sequence[TelemetryRecord]) -> bool:
        if not records:
            return True
        headers = {"Authorization": f"Bearer {self.jwt_token}"}
        payload = [record.as_ingestion_request() for record in records]
        for attempt in range(self.retry_count):
            try:
                response = self.client.post(self.endpoint, headers=headers, json=payload)
                if response.status_code == 202:
                    return True
                logger.warning("batch upload failed with HTTP %s", response.status_code)
            except httpx.HTTPError as exc:
                logger.warning("batch upload transport failure: %s", type(exc).__name__)
            if attempt + 1 < self.retry_count:
                self.sleep(2 ** attempt)
        return False

    def close(self) -> None:
        if self._owns_client:
            self.client.close()
