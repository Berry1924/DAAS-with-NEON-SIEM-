# CYBERWOLF SIEM — TELEMETRY INGESTION ARCHITECTURE (M03)

**Document Version**: 1.0  
**Date**: 31 July 2026  
**Module**: `M03 — Secure Telemetry Ingestion`  
**Specification Reference**: `CWS-PRD-001`, `CWS-TRD-001`, `CWS-AF-001`, `CWS-BE-001`, `CWS-IP-001`  

---

## 1. Executive Summary & Purpose

Module M03 establishes Cyberwolf's secure, high-throughput intake boundary for external security telemetry. It accepts raw events from telemetry producers, enforces authentication/RBAC, validates payload schemas, bounds request size and batch limits, handles idempotency, and constructs internal `IngestionEnvelope` structures to hand off telemetry safely to the downstream M04 Parsing & Normalization module.

---

## 2. System Architecture & Intake Pipeline

```
Telemetry Producer
        │
        ▼  (Content-Type: application/json)
[ RequestSizeLimitMiddleware ]  --->  413 Payload Too Large / 415 Unsupported Media Type
        │
        ▼
[ RequestIDMiddleware ]         --->  X-Request-ID propagation
        │
        ▼
[ Auth & RBAC Guard ]           --->  401 Unauthorized / 403 Forbidden (ADMIN, ANALYST allowed; VIEWER denied)
        │
        ▼
[ Schema Validation ]           --->  422 Unprocessable Entity (Strict Pydantic: extra fields forbidden)
        │
        ▼
[ IngestionService ]            --->  Idempotency Check (`source_type` + `source_event_id`)
        │
        ▼
[ IngestionEnvelope Buffer ]    --->  Hand-off to M04 Parsing & Normalization
```

---

## 3. Ingestion API Contracts

### 3.1 Single Telemetry Ingestion
- **Endpoint**: `POST /api/v1/events`
- **Content-Type**: `application/json`
- **Status Code**: `202 Accepted`
- **Request Body**:
```json
{
  "source_type": "linux_auth",
  "payload": {
    "message": "Accepted password for ubuntu from 192.168.1.50 port 54322 ssh2"
  },
  "timestamp": "2026-07-31T22:00:00Z",
  "hostname": "auth-server-01",
  "source_ip": "192.168.1.50",
  "source_event_id": "EVT-AUTH-1001"
}
```
- **Response Body**:
```json
{
  "status": "accepted",
  "request_id": "9a3f2b87-1234-4567-89ab-cdef01234567",
  "accepted": 1,
  "envelope_id": "c1f2e3d4-5678-90ab-cdef-1234567890ab",
  "is_duplicate": false
}
```

### 3.2 Batch Telemetry Ingestion
- **Endpoint**: `POST /api/v1/events/batch`
- **Content-Type**: `application/json`
- **Status Code**: `202 Accepted`
- **Batch Bounds**: `1 <= batch_size <= 100` (`MAX_BATCH_SIZE`)
- **Response Body**:
```json
{
  "status": "accepted",
  "request_id": "9a3f2b87-1234-4567-89ab-cdef01234567",
  "accepted": 20,
  "rejected": 0,
  "duplicates": 0
}
```

---

## 4. Controlled Source Types
Initial supported telemetry source types in `settings.SUPPORTED_SOURCE_TYPES`:
- `linux_auth`: Linux authentication logs (SSHD, PAM, auth.log).
- `json`: Generic structured JSON security telemetry.

*Unknown source types are rejected cleanly with `HTTP 422 Unprocessable Entity`.*

---

## 5. Security & Resource Boundaries

1. **Request Body Limit (`MAX_REQUEST_BODY_BYTES`)**: Default `1,048,576` bytes (1 MiB). Enforced early in `RequestSizeLimitMiddleware`. Exceeding payload size returns `HTTP 413 Payload Too Large`.
2. **Batch Limit (`MAX_BATCH_SIZE`)**: Default `100` events. Empty batches (`len == 0`) or oversized batches (`len > 100`) return `HTTP 400 Bad Request`.
3. **Strict Pydantic Contracts**: `extra = "forbid"` prevents clients from injecting internal/reserved model attributes (e.g. `id`, `created_at`, `risk_score`, `incident_id`).
4. **Raw Telemetry Inertness**: Attacks inside telemetry payloads (e.g., `<script>`, `' OR 1=1 --`, `$(whoami)`) are treated strictly as inert data strings without dynamic evaluation (`eval`/`exec`).
5. **Rate Limiting**: `slowapi` rate limiter on ingestion routes (`500/minute`). Exceeding throughput returns `HTTP 429 Too Many Requests`.

---

## 6. Internal Envelope & M04 Boundary

M03 does not populate normalized `Event` ORM models with synthetic data. Instead, accepted telemetry is wrapped in an `IngestionEnvelope`:

```python
class IngestionEnvelope(BaseModel):
    envelope_id: str
    request_id: str
    received_at: datetime
    ingested_by: str
    source_type: str
    source_event_id: Optional[str]
    raw_payload: Dict[str, Any]
    provided_timestamp: Optional[datetime]
    provided_hostname: Optional[str]
    provided_source_ip: Optional[str]
    provided_destination_ip: Optional[str]
    provided_event_type: Optional[str]
    is_duplicate: bool
```

`IngestionEnvelope` objects buffer in memory (`IngestionService._envelope_buffer`) and provide a clean processing boundary for M04 Parsing & Normalization.
