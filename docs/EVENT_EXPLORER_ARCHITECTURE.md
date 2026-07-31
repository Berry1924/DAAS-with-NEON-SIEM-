# CYBERWOLF SIEM — EVENT STORAGE, SEARCH & EVIDENCE EXPLORER (M05)

**Document Version**: 1.0  
**Date**: 31 July 2026  
**Module**: `M05 — Event Storage, Search & Evidence Explorer`  
**Specification Reference**: `CWS-PRD-001`, `CWS-TRD-001`, `CWS-AF-001`, `CWS-BE-001`, `CWS-IP-001`  

---

## 1. Executive Summary & Purpose

Module M05 exposes the canonical `Event` database store as a secure, bounded, queryable evidence API for SOC analysts and security applications.

```
Telemetry Intake (M03) -> Normalization (M04) -> PostgreSQL Event Store (M01)
                                                         │
                                                         ▼
                                       [ EventRepository.search() ]
                                                         │
                                                         ▼
                                       [ EventService.search_events() ]
                                                         │
                                                         ▼
                                       [ GET /api/v1/events ]
                                       [ GET /api/v1/events/{id} ]
                                       [ GET /api/v1/events/stats ]
```

---

## 2. API Contracts & Endpoints

### 2.1 Bounded Event List & Search
- **Endpoint**: `GET /api/v1/events`
- **Authorization**: `RequireRole([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])`
- **Query Parameters**:
  - `source_type`: Filter by source string (e.g. `linux_auth`, `json`)
  - `event_type`: Filter by category (e.g. `authentication`, `network_connection`)
  - `severity`: Filter by `Severity` enum (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  - `outcome`: Filter by `EventOutcome` enum (`SUCCESS`, `FAILURE`, `UNKNOWN`)
  - `hostname`: Exact hostname match
  - `username`: Exact username match
  - `source_ip` / `destination_ip`: Exact IP match
  - `asset_id`: Asset UUID
  - `start_time` / `end_time`: ISO8601 UTC time range boundary
  - `q`: Bounded text search across `hostname`, `username`, `event_type`, `source_type`
  - `sort_by`: Sort column from allowlist (`timestamp`, `ingested_at`, `severity`, `source_type`, `event_type`)
  - `sort_order`: `asc` or `desc` (default: `desc` with tie-breaker `id desc`)
  - `page`: Page number (default: `1`, minimum: `1`)
  - `page_size`: Page size (default: `50`, maximum limit: `100` via `MAX_PAGE_SIZE`)

### 2.2 Event Detail Retrieval
- **Endpoint**: `GET /api/v1/events/{event_id}`
- **Authorization**: `RequireRole([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])`
- **Response**: Returns canonical `EventRead` schema (`200 OK`) or `404 Not Found` if UUID is unknown.

### 2.3 Event Statistics Summary
- **Endpoint**: `GET /api/v1/events/stats`
- **Authorization**: `RequireRole([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])`
- **Response**: Aggregated counts by `severity`, `outcome`, `source_type`, and `total_events`.

---

## 3. Evidence Safety & Immutability

1. **Read-Only API**: Canonical security evidence is strictly immutable. M05 does NOT implement `PUT`, `PATCH`, or `DELETE` endpoints for `/events`.
2. **Raw Evidence Integrity**: `raw_event` is returned as untrusted serialized data. SOC frontends must render evidence as escaped text (zero script/HTML execution).
3. **Redacted Metadata**: Sensitive credential metadata (`password`, `access_token`, `authorization`) remains redacted (`"[REDACTED]"`).

---

## 4. Query Bounds & Performance

- **Bounded Pagination**: Enforces `1 <= page_size <= 100` (`MAX_PAGE_SIZE`). Bulk table dumps are blocked.
- **SQL Safety**: Parameterized SQLAlchemy `select(Event)` queries prevent SQL injection.
- **Database Indexes**: Indexed on `(event_type, timestamp)`, `(source_ip, timestamp)`, `(username, timestamp)`, and `(hostname, timestamp)`.
