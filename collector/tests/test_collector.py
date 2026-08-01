from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from collector.config import CollectorConfig, WatchedPath, load_config
from collector.heartbeat import heartbeat_payload
from collector.main import Collector
from collector.models import TelemetryRecord
from collector.offsets import OffsetStore
from collector.queue import MemoryQueue
from collector.sender import BatchSender
from collector.watcher import FileWatcher


def make_record(identifier: str = "one") -> TelemetryRecord:
    return TelemetryRecord("linux_auth", identifier, {"message": "Accepted password for alice"})


def test_watcher_detects_only_appended_linux_lines(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("old line\n")
    watcher = FileWatcher(OffsetStore(tmp_path / "offsets.json"), "demo")
    assert watcher.read_new(log, "linux_auth") == []
    log.write_text("old line\nJul 31 10:20:01 server sshd: Failed password for root from 192.168.1.20 port 40322 ssh2\n")
    records = watcher.read_new(log, "linux_auth")
    assert len(records) == 1
    assert records[0].payload["message"].startswith("Jul 31 10:20:01")


def test_offsets_survive_watcher_restart(tmp_path: Path) -> None:
    log, offsets = tmp_path / "events.log", tmp_path / "offsets.json"
    log.write_text("")
    first = FileWatcher(OffsetStore(offsets), "demo")
    first.read_new(log, "linux_auth")
    log.write_text("first\n")
    assert len(first.read_new(log, "linux_auth")) == 1
    second = FileWatcher(OffsetStore(offsets), "demo")
    assert second.read_new(log, "linux_auth") == []
    with log.open("a") as stream:
        stream.write("second\n")
    assert [r.payload["message"] for r in second.read_new(log, "linux_auth")] == ["second"]


def test_malformed_json_is_ignored_safely(tmp_path: Path) -> None:
    log = tmp_path / "events.json"
    log.write_text("")
    watcher = FileWatcher(OffsetStore(tmp_path / "offsets.json"), "demo")
    watcher.read_new(log, "json")
    log.write_text("not-json\n[1, 2]\n{\"host\": \"ok\"}\n")
    records = watcher.read_new(log, "json")
    assert len(records) == 1 and records[0].payload == {"host": "ok"}


def test_memory_queue_batches_and_requeues_in_order() -> None:
    queue = MemoryQueue()
    records = [make_record(str(index)) for index in range(3)]
    for record in records:
        queue.put(record)
    batch = queue.take(2)
    assert [item.source_event_id for item in batch] == ["0", "1"]
    queue.requeue_front(batch)
    assert [item.source_event_id for item in queue.take(3)] == ["0", "1", "2"]


def test_sender_upload_success_and_authenticated_payload() -> None:
    observed: dict[str, object] = {}
    def handler(request: httpx.Request) -> httpx.Response:
        observed["url"] = str(request.url)
        observed["authorization"] = request.headers["Authorization"]
        observed["payload"] = json.loads(request.content)
        return httpx.Response(202)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    sender = BatchSender("https://siem.example", "jwt-value", client=client)
    assert sender.send([make_record()]) is True
    assert observed["url"] == "https://siem.example/api/v1/events/batch"
    assert observed["authorization"] == "Bearer jwt-value"
    assert observed["payload"] == [make_record().as_ingestion_request()]


def test_sender_retries_exponentially_and_retains_caller_control() -> None:
    calls, delays = [], []
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(500 if len(calls) < 3 else 202)
    sender = BatchSender("http://siem", "jwt", retry_count=3,
                         client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=delays.append)
    assert sender.send([make_record()]) is True
    assert len(calls) == 3 and delays == [1, 2]


def test_heartbeat_payload_is_safe_and_complete() -> None:
    payload = heartbeat_payload("collector-demo")
    assert payload["collector_id"] == "collector-demo"
    assert payload["status"] == "ONLINE" and payload["version"] == "1.0"
    assert isinstance(payload["hostname"], str) and payload["hostname"]


def test_config_loads_environment_token_and_validates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("api_url: https://siem.example\njwt_token: ${COLLECTOR_TOKEN}\nwatched_paths:\n  - path: /tmp/a\n    source_type: linux_auth\n")
    monkeypatch.setenv("COLLECTOR_TOKEN", "safe-token")
    loaded = load_config(config)
    assert loaded.jwt_token == "safe-token" and loaded.watched_paths[0].source_type == "linux_auth"


def test_config_rejects_missing_token(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text("api_url: http://localhost:8000\njwt_token: ''\nwatched_paths: [{path: /tmp/a, source_type: json}]\n")
    with pytest.raises(ValueError, match="jwt_token"):
        load_config(path)


def test_collector_keeps_failed_batch_in_memory(tmp_path: Path) -> None:
    config = CollectorConfig("http://siem", "jwt", (WatchedPath(tmp_path / "missing", "linux_auth"),),
                             batch_size=1, offset_path=tmp_path / "offsets.json")
    collector = Collector(config)
    collector.queue.put(make_record())
    collector.sender.send = lambda records: False  # type: ignore[method-assign]
    assert collector.flush() is False
    assert len(collector.queue) == 1
    collector.shutdown()


def test_collector_shutdown_closes_sender(tmp_path: Path) -> None:
    config = CollectorConfig("http://siem", "jwt", (WatchedPath(tmp_path / "missing", "linux_auth"),),
                             offset_path=tmp_path / "offsets.json")
    collector = Collector(config)
    closed = []
    collector.sender.close = lambda: closed.append(True)  # type: ignore[method-assign]
    collector.shutdown()
    assert collector.running is False and closed == [True]
