# M06 live telemetry collector

This is a deliberately small, single-process collector for the CyberWolf M03 batch-ingestion API. It tails only appended records from Linux authentication logs and newline-delimited JSON logs. Existing content is skipped on its first observation; byte offsets are persisted in `collector/offsets.json` and are not committed.

## Run locally

From the repository root, after starting the M00–M05 backend and obtaining an existing JWT:

```powershell
$env:COLLECTOR_JWT_TOKEN = '<access token>'
py -3.12 -m collector.main --config collector/config.yaml
```

The config uses `http://localhost:8000` for a local stack. Set an HTTPS URL in deployments requiring transport security. It accepts a token only from configuration/environment and never logs it.

## Operational behavior and limits

- The collector sends authenticated JSON batches to `POST /api/v1/events/batch`; it does not implement a new backend route.
- Failed batches retry up to the configured count with 1, 2, then 4 second backoff. They remain in the process-local memory queue after failure.
- The 60-second heartbeat is a sanitized local application log record because M00–M05 exposes no collector-heartbeat API. It is not a server-side liveness record.
- Offset and retry state are local to one collector process. Rotation/truncation restarts reading from the beginning of the current file; multi-replica coordination and durable queueing are explicitly out of scope.
- JSON must be one object per line. Malformed or non-object records are ignored safely and only the filename is logged.
