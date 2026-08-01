"""Minimal process-local live telemetry collector entry point."""

from __future__ import annotations

import argparse
import logging
import signal
import time

from .config import CollectorConfig, load_config
from .heartbeat import heartbeat_payload
from .offsets import OffsetStore
from .queue import MemoryQueue
from .sender import BatchSender
from .watcher import FileWatcher

logger = logging.getLogger(__name__)


class Collector:
    def __init__(self, config: CollectorConfig) -> None:
        self.config = config
        self.queue = MemoryQueue()
        self.watcher = FileWatcher(OffsetStore(config.offset_path), config.collector_id)
        self.sender = BatchSender(config.api_url, config.jwt_token, config.retry_count)
        self.running = True
        self._last_flush = time.monotonic()
        self._last_heartbeat = 0.0

    def poll_once(self) -> None:
        for watched in self.config.watched_paths:
            for record in self.watcher.read_new(watched.path, watched.source_type):
                self.queue.put(record)
        now = time.monotonic()
        if len(self.queue) >= self.config.batch_size or (
            len(self.queue) and now - self._last_flush >= self.config.flush_interval_seconds
        ):
            self.flush()
        if now - self._last_heartbeat >= self.config.heartbeat_interval_seconds:
            # There is no M00-M05 heartbeat API: emit a sanitized local operational heartbeat.
            logger.info("collector heartbeat: %s", heartbeat_payload(self.config.collector_id))
            self._last_heartbeat = now

    def flush(self) -> bool:
        batch = self.queue.take(self.config.batch_size)
        if not batch:
            return True
        self._last_flush = time.monotonic()
        if self.sender.send(batch):
            return True
        self.queue.requeue_front(batch)
        logger.error("batch retained in memory after upload failure")
        return False

    def shutdown(self) -> None:
        self.running = False
        self.sender.close()

    def run(self) -> None:
        while self.running:
            self.poll_once()
            time.sleep(min(1.0, self.config.flush_interval_seconds))


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberWolf live telemetry collector")
    parser.add_argument("--config", default="collector/config.yaml")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    collector = Collector(load_config(args.config))
    signal.signal(signal.SIGINT, lambda *_: collector.shutdown())
    signal.signal(signal.SIGTERM, lambda *_: collector.shutdown())
    try:
        collector.run()
    finally:
        collector.shutdown()


if __name__ == "__main__":
    main()
