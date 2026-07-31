# CYBERWOLF SIEM — DATABASE ARCHITECTURE & EVIDENCE PERSISTENCE

**Document Version**: 1.0  
**Date**: 31 July 2026  
**Module**: `M01 — Database & Persistence`  
**System of Record**: PostgreSQL 15+  
**ORM / Validation**: SQLAlchemy 2.0 / Pydantic v2  

---

## 1. Overview & Architectural Invariants

PostgreSQL is the authoritative system of record for Cyberwolf SIEM. The persistence layer enforces the **Evidence Chain Invariant**:

$$\text{INCIDENT} \longrightarrow \text{ALERT} \longrightarrow \text{EVENT}$$

More specifically, the evidence relationship is implemented via relational junction tables:

```text
User
 │
 ├──── IncidentNote (author_id)
 └──── AuditLog (actor_id)

Asset
 │
 ├──── Event (asset_id)
 └──── Incident (primary_asset_id)

DetectionRule
 │
 └──── Alert (rule_id)
        │
        ├── AlertEvent (alert_id, event_id) ─── Event
        │
        └── IncidentAlert (incident_id, alert_id) ─── Incident
                                                       │
                                                       ├── IncidentTimeline (incident_id)
                                                       └── IncidentNote (incident_id)
```

---

## 2. Table Schemas & Definitions

### `users`
System user identities and Role-Based Access Control (RBAC) roles.
- `id` (UUID, PK)
- `username` (VARCHAR(120), UNIQUE, NOT NULL, INDEX)
- `email` (VARCHAR(255), UNIQUE, NULLABLE, INDEX)
- `display_name` (VARCHAR(120), NOT NULL)
- `password_hash` (TEXT, NOT NULL) — *Never serialized in public Pydantic schemas*
- `role` (`UserRole` Enum: `ADMIN`, `ANALYST`, `VIEWER`, NOT NULL)
- `is_active` (BOOLEAN, DEFAULT True, NOT NULL)
- `last_login_at` (TIMESTAMPTZ, NULLABLE)
- `created_at` / `updated_at` (TIMESTAMPTZ, NOT NULL)

### `assets`
Monitored infrastructure nodes and target hosts.
- `id` (UUID, PK)
- `hostname` (VARCHAR(255), NULLABLE, INDEX)
- `ip_address` (VARCHAR(45), NULLABLE, INDEX)
- `os` (VARCHAR(120), NULLABLE)
- `asset_type` (VARCHAR(80), NULLABLE)
- `criticality` (SMALLINT, 0-100, DEFAULT 50, NOT NULL)
- `status` (`AssetStatus` Enum: `ACTIVE`, `INACTIVE`, `UNKNOWN`, NOT NULL)
- `last_seen_at` (TIMESTAMPTZ, NULLABLE, INDEX)
- `metadata` (JSONB, DEFAULT {}, NOT NULL)
- `created_at` / `updated_at` (TIMESTAMPTZ, NOT NULL)

### `events`
Normalized security telemetry evidence layer (IMMUTABLE).
- `id` (UUID, PK) — Canonical event ID
- `timestamp` (TIMESTAMPTZ, NOT NULL, INDEX)
- `ingested_at` (TIMESTAMPTZ, NOT NULL)
- `source_type` (VARCHAR(80), NOT NULL, INDEX) — e.g. `linux_auth`, `suricata`
- `event_type` (VARCHAR(120), NOT NULL, INDEX) — e.g. `authentication_failure`
- `source_ip` (VARCHAR(45), NULLABLE, INDEX)
- `destination_ip` (VARCHAR(45), NULLABLE, INDEX)
- `hostname` (VARCHAR(255), NULLABLE, INDEX)
- `username` (VARCHAR(255), NULLABLE, INDEX)
- `asset_id` (UUID, FK `assets.id` ON DELETE SET NULL, NULLABLE, INDEX)
- `action` (VARCHAR(120), NULLABLE)
- `outcome` (`EventOutcome` Enum: `SUCCESS`, `FAILURE`, `UNKNOWN`, NOT NULL)
- `severity` (`Severity` Enum: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, NOT NULL)
- `raw_event` (JSONB, NOT NULL) — Raw un-tampered event payload
- `metadata` (JSONB, DEFAULT {}, NOT NULL)
- `source_event_id` (VARCHAR(255), NULLABLE, INDEX)
- `created_at` (TIMESTAMPTZ, NOT NULL)

### `detection_rules`
Declarative detection rule specifications.
- `id` (UUID, PK)
- `rule_id` (VARCHAR(80), UNIQUE, NOT NULL, INDEX) — e.g. `CW-AUTH-001`
- `name` (VARCHAR(255), NOT NULL)
- `description` (TEXT, NOT NULL)
- `category` (VARCHAR(80), NULLABLE)
- `event_types` (JSONB, NOT NULL)
- `conditions` (JSONB, NOT NULL) — Declarative predicate conditions only
- `group_by` (VARCHAR(80), NULLABLE)
- `threshold` (INTEGER, NULLABLE)
- `window_seconds` (INTEGER, NULLABLE)
- `severity` (`Severity` Enum, NOT NULL)
- `risk_weight` (SMALLINT, 0-100, DEFAULT 50, NOT NULL)
- `mitre_metadata` (JSONB, DEFAULT {}, NOT NULL)
- `enabled` (BOOLEAN, DEFAULT True, NOT NULL)
- `version` (INTEGER, DEFAULT 1, NOT NULL)
- `created_at` / `updated_at` (TIMESTAMPTZ, NOT NULL)

### `alerts`
Detections triggered by rule matches against events.
- `id` (UUID, PK)
- `rule_id` (UUID, FK `detection_rules.id` ON DELETE RESTRICT, NOT NULL, INDEX)
- `primary_event_id` (UUID, FK `events.id` ON DELETE RESTRICT, NOT NULL, INDEX)
- `title` (VARCHAR(255), NOT NULL)
- `description` (TEXT, NULLABLE)
- `severity` (`Severity` Enum, NOT NULL)
- `risk_score` (SMALLINT, CHECK `0 <= risk_score <= 100`, DEFAULT 50, NOT NULL)
- `status` (`AlertStatus` Enum: `NEW`, `ACKNOWLEDGED`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`, NOT NULL, INDEX)
- `source_ip` / `destination_ip` (VARCHAR(45), NULLABLE)
- `username` / `hostname` (VARCHAR(255), NULLABLE)
- `evidence` (JSONB, DEFAULT {}, NOT NULL)
- `first_seen_at` / `last_seen_at` / `created_at` / `updated_at` (TIMESTAMPTZ, NOT NULL)

### `alert_events` (Junction)
Many-to-many junction linking Alerts to supporting Events.
- `alert_id` (UUID, FK `alerts.id` ON DELETE CASCADE, NOT NULL)
- `event_id` (UUID, FK `events.id` ON DELETE RESTRICT, NOT NULL)
- `evidence_role` (VARCHAR(80), DEFAULT 'supporting', NOT NULL)
- `created_at` (TIMESTAMPTZ, NOT NULL)
- Primary Key: `(alert_id, event_id)`

### `incidents`
Correlated high-priority security incidents.
- `id` (UUID, PK)
- `incident_key` (VARCHAR(80), UNIQUE, NOT NULL, INDEX) — e.g. `CW-INC-0042`
- `title` (VARCHAR(255), NOT NULL)
- `incident_type` (VARCHAR(120), NOT NULL) — e.g. `Potential Host Compromise`
- `description` (TEXT, NULLABLE)
- `severity` (`Severity` Enum, NOT NULL)
- `risk_score` (SMALLINT, CHECK `0 <= risk_score <= 100`, DEFAULT 50, NOT NULL)
- `status` (`IncidentStatus` Enum: `NEW`, `ACKNOWLEDGED`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`, NOT NULL, INDEX)
- `assigned_to` (UUID, FK `users.id` ON DELETE SET NULL, NULLABLE, INDEX)
- `primary_asset_id` (UUID, FK `assets.id` ON DELETE SET NULL, NULLABLE, INDEX)
- `source_ip` / `destination_ip` (VARCHAR(45), NULLABLE)
- `username` (VARCHAR(255), NULLABLE)
- `correlation_rule` (VARCHAR(120), NULLABLE)
- `risk_explanation` (JSONB, DEFAULT {}, NOT NULL)
- `first_seen_at` / `last_seen_at` / `created_at` / `updated_at` (TIMESTAMPTZ, NOT NULL)
- `resolved_at` (TIMESTAMPTZ, NULLABLE)

### `incident_alerts` (Junction)
Many-to-many junction linking Incidents to contributing Alerts.
- `incident_id` (UUID, FK `incidents.id` ON DELETE CASCADE, NOT NULL)
- `alert_id` (UUID, FK `alerts.id` ON DELETE RESTRICT, NOT NULL)
- `correlation_role` (VARCHAR(80), DEFAULT 'contributing', NOT NULL)
- `added_at` (TIMESTAMPTZ, NOT NULL)
- Primary Key: `(incident_id, alert_id)`

### `incident_timeline`
Chronological evidence timeline entries for incident investigation.
- `id` (UUID, PK)
- `incident_id` (UUID, FK `incidents.id` ON DELETE CASCADE, NOT NULL, INDEX)
- `timestamp` (TIMESTAMPTZ, NOT NULL, INDEX)
- `entry_type` (VARCHAR(80), NOT NULL) — `EVENT`, `ALERT`, `STATUS`, `NOTE`
- `event_id` (UUID, FK `events.id` ON DELETE SET NULL, NULLABLE)
- `alert_id` (UUID, FK `alerts.id` ON DELETE SET NULL, NULLABLE)
- `title` (VARCHAR(255), NOT NULL)
- `summary` (TEXT, NULLABLE)
- `metadata` (JSONB, DEFAULT {}, NOT NULL)
- `created_at` (TIMESTAMPTZ, NOT NULL)

### `incident_notes`
Analyst investigation notes attached to incidents.
- `id` (UUID, PK)
- `incident_id` (UUID, FK `incidents.id` ON DELETE CASCADE, NOT NULL, INDEX)
- `author_id` (UUID, FK `users.id` ON DELETE RESTRICT, NOT NULL, INDEX)
- `body` (TEXT, NOT NULL)
- `created_at` / `updated_at` (TIMESTAMPTZ, NOT NULL)

### `audit_logs`
Immutable, append-only operational audit trail for system mutations.
- `id` (UUID, PK)
- `timestamp` (TIMESTAMPTZ, NOT NULL, INDEX)
- `actor_id` (UUID, FK `users.id` ON DELETE SET NULL, NULLABLE, INDEX)
- `action` (VARCHAR(120), NOT NULL, INDEX) — e.g. `INCIDENT_STATUS_CHANGE`
- `target_type` (VARCHAR(80), NULLABLE)
- `target_id` (VARCHAR(255), NULLABLE)
- `result` (`AuditResult` Enum: `SUCCESS`, `FAILURE`, `DENIED`, NOT NULL)
- `request_id` (VARCHAR(120), NULLABLE, INDEX)
- `source_ip` (VARCHAR(45), NULLABLE)
- `metadata` (JSONB, DEFAULT {}, NOT NULL) — *Strictly forbids password/token keys*

---

## 3. Foreign Key Deletion & Evidence Policy

| Higher-Level Object | Child Object | FK Constraint | Behavior Rationale |
|---|---|---|---|
| `Incident` | `IncidentAlert` | `ON DELETE CASCADE` | Deleting an Incident removes junction links only. |
| `IncidentAlert` | `Alert` | `ON DELETE RESTRICT` | Deleting an Alert referenced by an Incident is blocked. |
| `Alert` | `AlertEvent` | `ON DELETE CASCADE` | Deleting an Alert removes evidence links only. |
| `AlertEvent` | `Event` | `ON DELETE RESTRICT` | **CRITICAL**: Raw Event evidence is **IMMUTABLE** and cannot be deleted while referenced by active alerts. |
| `Asset` | `Event` | `ON DELETE SET NULL` | Removing an Asset preserves historical security event evidence. |

---

## 4. Migration & Verification Commands

To run baseline migration on a clean PostgreSQL database:
```bash
alembic -c backend/alembic.ini upgrade head
```

To run test suite verification:
```bash
py -3.12 -m pytest tests/test_database.py tests/test_health.py
```
