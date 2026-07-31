# CYBERWOLF SIEM — TEST SUITE SPECIFICATION & VERIFICATION GUIDE

**Document Version**: 1.0  
**Date**: 31 July 2026  
**Test Framework**: `pytest` 9.1+ / `Python 3.12`  
**Coverage Scope**: `M00 Foundation` & `M01 Database & Persistence`  

---

## 1. Test Suite Overview & Architecture

The Cyberwolf SIEM verification suite is built on `pytest` using isolated test strategy fixtures. Every module implementation requires explicit test verification before advancing to subsequent modules.

```text
                               ┌────────────────────────────────┐
                               │     pytest Test Runner         │
                               └───────────────┬────────────────┘
                                               │
                       ┌───────────────────────┴───────────────────────┐
                       ▼                                               ▼
        ┌─────────────────────────────┐                 ┌─────────────────────────────┐
        │     API & Health Tests      │                 │   Database & Evidence Tests │
        │    (tests/test_health.py)   │                 │   (tests/test_database.py)  │
        └──────────────┬──────────────┘                 └──────────────┬──────────────┘
                       │                                               │
                       ▼                                               ▼
         FastAPI Async TestClient                         SQLAlchemy In-Memory Engine
         (GET /, /health, /api/v1/health)                 (Models, Repositories, Constraints)
```

---

## 2. Test Execution Commands

### Run Full Test Suite (Verbose Mode)
```bash
py -3.12 -m pytest tests/test_database.py tests/test_health.py -v
```

### Run Specific Test File
```bash
py -3.12 -m pytest tests/test_database.py -v
```

### Run Specific Test Case
```bash
py -3.12 -m pytest tests/test_database.py -k test_evidence_chain_and_traversal -v
```

---

## 3. Test Catalog & Detailed Specifications

### Module M00 — Health & API Tests (`tests/test_health.py`)

#### `TC-M00-01`: Root Welcome Endpoint Test (`test_root_endpoint`)
- **Target**: `GET /`
- **Purpose**: Verifies that the FastAPI application boots and responds to root queries.
- **Expected Outcome**: HTTP `200 OK` with JSON response containing `"message": "Welcome to Cyberwolf SIEM"`.

#### `TC-M00-02`: System Health Endpoint Test (`test_health_endpoint`)
- **Target**: `GET /health`
- **Purpose**: Verifies operational readiness of the application container.
- **Expected Outcome**: HTTP `200 OK` with JSON response containing `"status": "ok"`, `"app": "Cyberwolf SIEM"`, and `"version": "1.0.0-hackathon-mvp"`.

#### `TC-M00-03`: API Version 1 Health Endpoint Test (`test_api_v1_health_endpoint`)
- **Target**: `GET /api/v1/health`
- **Purpose**: Verifies routing under the `/api/v1` API prefix.
- **Expected Outcome**: HTTP `200 OK` matching `/health`.

---

### Module M01 — Database & Evidence Persistence Tests (`tests/test_database.py`)

#### `TC-M01-01`: Alembic Metadata Table Enumeration (`test_alembic_metadata_tables`)
- **Target**: `Base.metadata.tables`
- **Purpose**: Verifies that all 11 required Cyberwolf SIEM database tables are registered in the SQLAlchemy metadata registry.
- **Tables Verified**: `users`, `assets`, `events`, `detection_rules`, `alerts`, `alert_events`, `incidents`, `incident_alerts`, `incident_timeline`, `incident_notes`, `audit_logs`.
- **Expected Outcome**: All 11 tables present in `Base.metadata.tables.keys()`.

#### `TC-M01-02`: User Model Persistence & Username Uniqueness (`test_user_creation_and_uniqueness`)
- **Target**: `User` model (`users` table)
- **Purpose**: Verifies user entity instantiation, role enum assignment (`UserRole.ANALYST`), and database-level unique constraint on `username`.
- **Expected Outcome**: Primary key `id` generated as UUID; inserting duplicate `username` raises `sqlalchemy.exc.IntegrityError`.

#### `TC-M01-03`: UserRead Schema Password Hash Exclusion (`test_user_schema_excludes_password_hash`)
- **Target**: `UserRead` Pydantic schema ([backend/app/schemas/user.py](file:///e:/neonprojects/backend/app/schemas/user.py))
- **Security Invariant**: **SEC-07** — `password_hash` must **NEVER** be exposed in public API response schemas.
- **Expected Outcome**: Validating a `User` instance into `UserRead.model_validate(user)` produces a serialized dictionary without `password_hash` or `password` keys.

#### `TC-M01-04`: Evidence Chain Graph Traversal (`test_evidence_chain_and_traversal`)
- **Target**: `Incident` $\rightarrow$ `IncidentAlert` $\rightarrow$ `Alert` $\rightarrow$ `AlertEvent` $\rightarrow$ `Event`
- **Architectural Invariant**: **INCIDENT $\rightarrow$ ALERT $\rightarrow$ EVENT** evidence chain traceability.
- **Purpose**: Verifies that a correlated Incident can be traversed across junction tables down to the primary raw security event (`raw_event`).
- **Expected Outcome**:
  1. `Incident` (`CW-INC-0042`) links to `Alert` (`Brute Force Auth Failure`).
  2. `Alert` links to `Event` (`authentication_failure`, `source_ip: 192.168.1.100`).
  3. All relational foreign keys resolve correctly without lazy-load issues.

#### `TC-M01-05`: Evidence Deletion Policy Protection (`test_evidence_deletion_policy`)
- **Target**: Foreign Key `ON DELETE RESTRICT` constraints on `AlertEvent` and `IncidentAlert`
- **Security Invariant**: **SEC-03** — Deleting higher-level analytical objects (`Incident` or `Alert`) MUST **NEVER** destroy underlying raw `Event` evidence.
- **Purpose**: Create an Incident, Alert, and Event chain, delete the Incident, and verify the Alert and Event remain intact.
- **Expected Outcome**: Deleting `Incident` succeeds; `Alert` and `Event` remain present in the database.

#### `TC-M01-06`: Repository Layer Abstraction (`test_repository_pattern_basics`)
- **Target**: `EventRepository`, `AlertRepository`, `IncidentRepository`
- **Purpose**: Verifies CRUD operations across repository abstraction classes.
- **Expected Outcome**: Repository `create()` and `link_alert()` methods persist entities and return refreshed instances.

#### `TC-M01-07`: Audit Log Persistence (`test_audit_log_creation`)
- **Target**: `AuditLog` model (`audit_logs` table)
- **Purpose**: Verifies recording of operational security actions (`INCIDENT_STATUS_CHANGE`) with `AuditResult.SUCCESS`.
- **Expected Outcome**: Audit entry created with timestamp and metadata dictionary.

---

## 4. Test Results Summary Matrix

```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1, pluggy-1.6.0
rootdir: E:\neonprojects
collected 10 items

tests/test_database.py::test_alembic_metadata_tables PASSED              [ 10%]
tests/test_database.py::test_user_creation_and_uniqueness PASSED         [ 20%]
tests/test_database.py::test_user_schema_excludes_password_hash PASSED   [ 30%]
tests/test_database.py::test_evidence_chain_and_traversal PASSED         [ 40%]
tests/test_database.py::test_evidence_deletion_policy PASSED             [ 50%]
tests/test_database.py::test_repository_pattern_basics PASSED            [ 60%]
tests/test_database.py::test_audit_log_creation PASSED                   [ 70%]
tests/test_health.py::test_root_endpoint PASSED                          [ 80%]
tests/test_health.py::test_health_endpoint PASSED                        [ 90%]
tests/test_health.py::test_api_v1_health_endpoint PASSED                 [100%]

============================= 10 passed in 0.97s ==============================
```

---

## 5. Future Module Test Roadmap (M02 - M18)

| Module ID | Module Name | Planned Test Coverage |
|---|---|---|
| **M02** | Authentication / RBAC | Password hashing with `bcrypt`, JWT token issuance, login rate limiting, role authorization guards (`ADMIN`, `ANALYST`, `VIEWER`). |
| **M03** | Ingestion | REST payload validation, single & batch event limits, rate limiting. |
| **M04** | Parsing & Normalization | Linux auth log parser, JSON parser, canonical field mapping, malformed log quarantine. |
| **M05** | Event Storage | Paginated search queries, filter combinations (time, source_type, IP). |
| **M06** | Detection Engine | Declarative rule predicate evaluation, threshold counters, window expiry. |
| **M07** | Alerts | Alert generation, lifecycle state machine (`NEW` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `RESOLVED`). |
| **M08** | Correlation Engine | Golden sequence matching (`CW-NET-001` $\rightarrow$ `CW-AUTH-001` $\rightarrow$ `CW-LOGIN-001` $\rightarrow$ `CW-PRIV-001`), deduplication. |
| **M09** | Risk Engine | Deterministic risk score clamping (0-100), factor breakdown validation. |
| **M10** | Incidents | Incident creation, evidence timeline generation, analyst notes. |
| **M15** | Golden Path | Full end-to-end telemetry replay to incident investigation integration test. |
