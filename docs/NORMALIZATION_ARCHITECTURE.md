# CYBERWOLF SIEM — TELEMETRY PARSING, NORMALIZATION & EVENT PERSISTENCE ARCHITECTURE (M04)

**Document Version**: 1.0  
**Date**: 31 July 2026  
**Module**: `M04 — Parsing, Normalization & Event Persistence`  
**Specification Reference**: `CWS-PRD-001`, `CWS-TRD-001`, `CWS-AF-001`, `CWS-BE-001`, `CWS-IP-001`  

---

## 1. Executive Summary & Purpose

Module M04 transforms accepted M03 `IngestionEnvelope` telemetry into validated, canonical Cyberwolf `Event` records and persists them to PostgreSQL/SQLite via `EventRepository`.

```
IngestionEnvelope
        │
        ▼
[ ParserRegistry ]  --->  Selects registered parser (linux_auth, json)
        │
        ▼
[ BaseParser ]      --->  Produces intermediate ParsedEvent
        │
        ▼
[ EventNormalizer ] --->  UTC timestamp coercion, IP validation, enum mapping, metadata redaction
        │
        ▼
[ EventRepository ] --->  Persists canonical Event entity to Database
```

---

## 2. Canonical Event Contract

The canonical `Event` ORM entity represents normalized security evidence:

| Canonical Field | Type | Description |
|---|---|---|
| `id` | `UUID` | Unique Cyberwolf Event primary key |
| `timestamp` | `DateTime(UTC)` | Normalized UTC event occurrence timestamp |
| `ingested_at` | `DateTime(UTC)` | System intake timestamp recorded during M03 ingestion |
| `source_type` | `String(80)` | Controlled telemetry source category (e.g. `linux_auth`, `json`) |
| `event_type` | `String(120)` | Controlled event category (e.g. `authentication`, `network_connection`) |
| `source_ip` | `String(45)` | Validated IPv4 or IPv6 source address (or `NULL`) |
| `destination_ip` | `String(45)` | Validated IPv4 or IPv6 destination address (or `NULL`) |
| `hostname` | `String(255)` | Source hostname/system identity |
| `username` | `String(255)` | Subject user identity |
| `action` | `String(120)` | Operational action (e.g. `login`, `session_open`, `session_close`) |
| `outcome` | `EventOutcome` | `SUCCESS`, `FAILURE`, or `UNKNOWN` |
| `severity` | `Severity` | Controlled telemetry severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `raw_event` | `JSON` | Original, unmutated raw telemetry evidence |
| `event_metadata` | `JSON` | Noncanonical metadata dictionary with sensitive keys redacted |
| `source_event_id` | `String(255)` | Upstream source event identifier (for idempotency tracking) |

---

## 3. Parsers & Registry (`security_engine/parsers/`)

- **Parser Registry (`ParserRegistry`)**: Maintains explicit mapping between `source_type` strings and concrete parser instances. Throws `ValueError` for unregistered source types.
- **Linux Auth Parser (`LinuxAuthParser`)**: Parses SSHD and PAM syslog authentication telemetry. Extracts username, source IP, port, action (`login`, `session_open`, `session_close`), and outcome (`SUCCESS`/`FAILURE`).
- **JSON Parser (`JsonParser`)**: Deterministically maps standard JSON telemetry key aliases (`@timestamp`, `src_ip`, `user`, `status`, `level`). Unknown payload keys are retained safely in `metadata`.

---

## 4. Normalization Engine (`EventNormalizer`)

1. **UTC Timestamp Normalization**: All timestamps are converted or coerced into UTC timezone-aware `datetime` objects. Missing timestamps fall back to `envelope.received_at`. Invalid timestamp strings raise `ValueError`.
2. **IP Validation**: Standard `ipaddress.ip_address()` validation. Invalid IP formats raise `ValueError`. Unknown IPs remain `None` (never defaulted to `0.0.0.0`).
3. **Defensive Metadata Redaction**: Sensitive credential keys (`password`, `password_hash`, `token`, `access_token`, `refresh_token`, `authorization`, `cookie`, `secret`, `api_key`) inside metadata dictionaries are automatically sanitized to `"[REDACTED]"`.
4. **Data Inertness**: Telemetry strings containing script tags, SQL injection syntax, shell commands, or path traversal vectors are handled purely as inert data without code execution (`eval`/`exec`).

---

## 5. End-to-End Pipeline (`ProcessingService`)

`ProcessingService.process(envelope, db)` coordinates parser lookup, parsing, normalization, and repository persistence. Processing returns a `ProcessingResult` with status `NORMALIZED`, `PARSE_FAILED`, `VALIDATION_FAILED`, or `DUPLICATE`.
