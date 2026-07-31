CYBERWOLF SIEM

Backend & Data Schema Specification

PostgreSQL • FastAPI • Security Analytics Data ModelVersion 1.0 • 31 July 2026

Document ID

CWS-BE-001

Parent Documents

CWS-PRD-001, CWS-TRD-001, CWS-AF-001, CWS-UX-001

Project

Cyberwolf SIEM

Backend

Python + FastAPI

Primary Database

PostgreSQL

ORM / Validation

SQLAlchemy + Pydantic

Scope

Hackathon MVP backend source of truth

1. Purpose

This document defines the backend domain model, PostgreSQL schema, relationships, API data contracts, indexing strategy, state transitions, validation rules, security boundaries, and migration requirements for Cyberwolf SIEM. It is the implementation contract between the FastAPI backend, security analytics engine, database, and React frontend.

2. Backend Design Principles

PostgreSQL is the authoritative system of record for the MVP.

Normalized events are immutable security evidence except for explicitly controlled enrichment metadata.

Alerts reference the rules and events that caused them.

Incidents reference contributing alerts rather than storing unsupported conclusions.

Authorization is enforced server-side.

Frequently queried security fields are relational; extensible source context uses JSONB.

All schema changes are versioned through migrations.

Security evidence remains traceable from incident → alert → event.

3. Domain Model

USER ──< AUDIT_LOG  │  └── role / permissionsASSET ──< EVENT >── USERNAME/IP CONTEXT             │             └──< ALERT >── DETECTION_RULE                    │                    └──< INCIDENT_ALERT >── INCIDENT                                              │                                              ├──< INCIDENT_TIMELINE                                              └──< INCIDENT_NOTEEVENT ── optional relationships ── ASSET

The key evidence chain is: Event → Alert → Incident. This chain must remain queryable and auditable.

4. Database Conventions

Convention

Requirement

Primary keys

UUID preferred for externally visible/domain objects

Time

TIMESTAMPTZ stored in UTC

Names

snake_case

Enums

Controlled application/database values

Metadata

JSONB for extensible safe context

Deletion

Avoid hard deletion of security evidence in MVP

Migrations

Alembic version-controlled migrations

Foreign keys

Explicit constraints and indexed where useful

Pagination

Bounded list queries

Secrets

Never store plaintext passwords/tokens

5. Enumerations

Enum

Values

user_role

ADMIN, ANALYST, VIEWER

severity

INFO, LOW, MEDIUM, HIGH, CRITICAL

alert_status

NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE

incident_status

NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE

event_outcome

SUCCESS, FAILURE, UNKNOWN

asset_status

ACTIVE, INACTIVE, UNKNOWN

audit_result

SUCCESS, FAILURE, DENIED

6. Table: users

Column

Type

Constraints / Meaning

id

UUID

PK

email

VARCHAR(255)

UNIQUE, NOT NULL, normalized

display_name

VARCHAR(120)

NOT NULL

password_hash

TEXT

NOT NULL; never plaintext

role

user_role

NOT NULL

is_active

BOOLEAN

NOT NULL DEFAULT TRUE

last_login_at

TIMESTAMPTZ

NULL

created_at

TIMESTAMPTZ

NOT NULL

updated_at

TIMESTAMPTZ

NOT NULL

Indexes: unique(email); optional index(role, is_active). Password hash is excluded from all normal API response models.

7. Table: assets

Column

Type

Constraints / Meaning

id

UUID

PK

hostname

VARCHAR(255)

NULL/INDEX

ip_address

INET

NULL/INDEX

os

VARCHAR(120)

NULL

asset_type

VARCHAR(80)

NULL

criticality

SMALLINT

0–100 or configured scale

status

asset_status

NOT NULL DEFAULT UNKNOWN

last_seen_at

TIMESTAMPTZ

NULL/INDEX

metadata

JSONB

NOT NULL DEFAULT {}

created_at

TIMESTAMPTZ

NOT NULL

updated_at

TIMESTAMPTZ

NOT NULL

Asset identity rules must avoid accidental duplication. For MVP, hostname/IP matching is explicit and conservative.

8. Table: events

Column

Type

Constraints / Meaning

id

UUID

PK; canonical event_id

timestamp

TIMESTAMPTZ

NOT NULL, INDEX

ingested_at

TIMESTAMPTZ

NOT NULL

source_type

VARCHAR(80)

NOT NULL, INDEX

event_type

VARCHAR(120)

NOT NULL, INDEX

source_ip

INET

NULL, INDEX

destination_ip

INET

NULL, INDEX

hostname

VARCHAR(255)

NULL, INDEX

username

VARCHAR(255)

NULL, INDEX

asset_id

UUID

NULL FK assets.id

action

VARCHAR(120)

NULL

outcome

event_outcome

NOT NULL DEFAULT UNKNOWN

severity

severity

NOT NULL DEFAULT INFO

raw_event

JSONB/TEXT

NOT NULL

metadata

JSONB

NOT NULL DEFAULT {}

source_event_id

VARCHAR(255)

NULL

created_at

TIMESTAMPTZ

NOT NULL

Events are the normalized evidence layer. raw_event preserves source evidence in a safe representation. Credentials, tokens, keys, and other prohibited secrets must be filtered before persistence where applicable.

Recommended indexes: timestamp DESC; (event_type, timestamp DESC); (source_ip, timestamp DESC); (username, timestamp DESC); (hostname, timestamp DESC); asset_id; optional source_event_id for deduplication.

9. Table: detection_rules

Column

Type

Constraints / Meaning

id

UUID

PK

rule_id

VARCHAR(80)

UNIQUE, NOT NULL; e.g. CW-AUTH-001

name

VARCHAR(255)

NOT NULL

description

TEXT

NOT NULL

category

VARCHAR(80)

NULL

event_types

JSONB

NOT NULL

conditions

JSONB

NOT NULL; declarative only

group_by

VARCHAR(80)

NULL

threshold

INTEGER

NULL

window_seconds

INTEGER

NULL

severity

severity

NOT NULL

risk_weight

SMALLINT

0–100

mitre_metadata

JSONB

NOT NULL DEFAULT {}

enabled

BOOLEAN

NOT NULL DEFAULT TRUE

version

INTEGER

NOT NULL DEFAULT 1

created_at

TIMESTAMPTZ

NOT NULL

updated_at

TIMESTAMPTZ

NOT NULL

conditions must use a restricted declarative schema. Do not store or execute arbitrary Python/JavaScript supplied through the UI.

10. Table: alerts

Column

Type

Constraints / Meaning

id

UUID

PK

rule_id

UUID

NOT NULL FK detection_rules.id

primary_event_id

UUID

NOT NULL FK events.id

title

VARCHAR(255)

NOT NULL

description

TEXT

NULL

severity

severity

NOT NULL

risk_score

SMALLINT

CHECK 0–100

status

alert_status

NOT NULL DEFAULT NEW

source_ip

INET

NULL

destination_ip

INET

NULL

username

VARCHAR(255)

NULL

hostname

VARCHAR(255)

NULL

evidence

JSONB

NOT NULL DEFAULT {}

first_seen_at

TIMESTAMPTZ

NOT NULL

last_seen_at

TIMESTAMPTZ

NOT NULL

created_at

TIMESTAMPTZ

NOT NULL

updated_at

TIMESTAMPTZ

NOT NULL

Recommended indexes: (status, severity, created_at DESC), risk_score DESC, rule_id, primary_event_id, source_ip, username.

11. Table: alert_events

Many alerts, especially threshold detections, may depend on more than one event. This junction table preserves the full evidence set.

Column

Type

Constraints / Meaning

alert_id

UUID

PK part, FK alerts.id

event_id

UUID

PK part, FK events.id

evidence_role

VARCHAR(80)

e.g. trigger/supporting

created_at

TIMESTAMPTZ

NOT NULL

12. Table: incidents

Column

Type

Constraints / Meaning

id

UUID

PK

incident_key

VARCHAR(80)

UNIQUE; display ID such as CW-INC-0042

title

VARCHAR(255)

NOT NULL

incident_type

VARCHAR(120)

NOT NULL

description

TEXT

NULL

severity

severity

NOT NULL

risk_score

SMALLINT

CHECK 0–100

status

incident_status

NOT NULL DEFAULT NEW

assigned_to

UUID

NULL FK users.id

primary_asset_id

UUID

NULL FK assets.id

source_ip

INET

NULL

destination_ip

INET

NULL

username

VARCHAR(255)

NULL

correlation_rule

VARCHAR(120)

NULL

risk_explanation

JSONB

NOT NULL DEFAULT {}

first_seen_at

TIMESTAMPTZ

NOT NULL

last_seen_at

TIMESTAMPTZ

NOT NULL

created_at

TIMESTAMPTZ

NOT NULL

updated_at

TIMESTAMPTZ

NOT NULL

resolved_at

TIMESTAMPTZ

NULL

Indexes: (status, risk_score DESC), severity, created_at DESC, assigned_to, primary_asset_id, source_ip, username.

13. Table: incident_alerts

Column

Type

Constraints / Meaning

incident_id

UUID

PK part, FK incidents.id

alert_id

UUID

PK part, FK alerts.id

correlation_role

VARCHAR(80)

e.g. scan/auth/privilege/supporting

added_at

TIMESTAMPTZ

NOT NULL

This relationship is essential for explainability. Correlation never destroys standalone alert evidence.

14. Table: incident_timeline

Column

Type

Constraints / Meaning

id

UUID

PK

incident_id

UUID

NOT NULL FK incidents.id

timestamp

TIMESTAMPTZ

NOT NULL, INDEX

entry_type

VARCHAR(80)

EVENT, ALERT, STATUS, NOTE

event_id

UUID

NULL FK events.id

alert_id

UUID

NULL FK alerts.id

title

VARCHAR(255)

NOT NULL

summary

TEXT

NULL

metadata

JSONB

NOT NULL DEFAULT {}

created_at

TIMESTAMPTZ

NOT NULL

Evidence timeline entries should reference source objects. Human-readable summaries must not replace evidence links.

15. Table: incident_notes

Column

Type

Constraints / Meaning

id

UUID

PK

incident_id

UUID

NOT NULL FK incidents.id

author_id

UUID

NOT NULL FK users.id

body

TEXT

NOT NULL

created_at

TIMESTAMPTZ

NOT NULL

updated_at

TIMESTAMPTZ

NOT NULL

Notes are analyst context and must be visually distinguished from machine-generated security evidence.

16. Table: audit_logs

Column

Type

Constraints / Meaning

id

UUID

PK

timestamp

TIMESTAMPTZ

NOT NULL, INDEX

actor_id

UUID

NULL FK users.id

action

VARCHAR(120)

NOT NULL, INDEX

target_type

VARCHAR(80)

NULL

target_id

VARCHAR(255)

NULL

result

audit_result

NOT NULL

request_id

VARCHAR(120)

NULL, INDEX

source_ip

INET

NULL

metadata

JSONB

NOT NULL DEFAULT {}

Audit metadata must not contain passwords, access tokens, secret keys, or raw authorization headers. Application workflows should treat audit records as append-only.

17. Optional Table: ingestion_sources

Column

Type

Constraints / Meaning

id

UUID

PK

name

VARCHAR(120)

UNIQUE, NOT NULL

source_type

VARCHAR(80)

NOT NULL

enabled

BOOLEAN

DEFAULT TRUE

last_seen_at

TIMESTAMPTZ

NULL

configuration

JSONB

Safe non-secret configuration only

created_at

TIMESTAMPTZ

NOT NULL

updated_at

TIMESTAMPTZ

NOT NULL

Secrets for integrations should use environment/secret storage, not plaintext configuration JSON.

18. Entity Relationship Summary

Parent

Relationship

Child

users

1:N

audit_logs

users

1:N

incident_notes

users

1:N assigned

incidents

assets

1:N

events

assets

1:N primary

incidents

detection_rules

1:N

alerts

events

N:M via alert_events

alerts

alerts

N:M via incident_alerts

incidents

incidents

1:N

incident_timeline

incidents

1:N

incident_notes

19. Canonical Event API Schema

EventCreate:{  "timestamp": "ISO-8601 UTC/offset",  "source_type": "linux_auth",  "event_type": "authentication_failure",  "source_ip": "192.0.2.10",  "destination_ip": "192.0.2.20",  "hostname": "server-01",  "username": "admin",  "action": "login",  "outcome": "FAILURE",  "severity": "MEDIUM",  "raw_event": {...},  "metadata": {...}}

The API assigns canonical event ID and ingested_at. Client-supplied IDs are treated only as source_event_id when allowed.

20. Alert API Schema

AlertRead:{  "id": "uuid",  "rule": {"rule_id": "CW-AUTH-001", "name": "..."},  "primary_event_id": "uuid",  "title": "Repeated Authentication Failures",  "severity": "HIGH",  "risk_score": 68,  "status": "NEW",  "entities": {...},  "evidence": {...},  "first_seen_at": "...",  "last_seen_at": "..."}

21. Incident API Schema

IncidentRead:{  "id": "uuid",  "incident_key": "CW-INC-0042",  "title": "Potential Host Compromise",  "severity": "CRITICAL",  "risk_score": 94,  "status": "NEW",  "affected_entities": {...},  "risk_explanation": {...},  "linked_alerts": [...],  "timeline": [...],  "first_seen_at": "...",  "last_seen_at": "..."}

22. Risk Explanation Schema

{  "base_risk": 45,  "factors": [    {"type": "correlation", "label": "Scan + authentication sequence", "points": 15},    {"type": "compromise_indicator", "label": "Success after failures", "points": 20},    {"type": "privilege_event", "label": "Privilege activity followed login", "points": 14}  ],  "final_score": 94}

Risk explanation is generated by deterministic backend logic and shown in the incident UI.

23. Detection Rule Conditions Contract

A restricted rule condition format should support safe comparisons without arbitrary code.

Example:{  "all": [    {"field": "event_type", "operator": "eq", "value": "authentication_failure"}  ],  "group_by": "source_ip",  "threshold": 5,  "window_seconds": 60}

Allowed operators may include eq, neq, in, contains for safe string/list fields, and numeric comparisons where type-valid. Field names must come from an allowlist.

24. API Response Envelope

Success:{  "data": ...,  "meta": {"request_id": "..."}}List:{  "data": [...],  "meta": {    "request_id": "...",    "page": 1,    "page_size": 50,    "total": 123  }}Error:{  "error": {    "code": "VALIDATION_ERROR",    "message": "Request could not be processed"  },  "meta": {"request_id": "..."}}

Do not return internal stack traces or secrets.

25. Pagination & Filtering

Default page size is bounded; maximum page size is configured.

Event filters: time range, source_type, event_type, severity, source_ip, destination_ip, hostname, username, outcome.

Alert filters: time, severity, risk range, status, rule, source entities.

Incident filters: time, severity, risk range, status, assignee, affected entity.

Sorting fields use an allowlist to prevent arbitrary query construction.

26. Authentication Data Rules

Normalize email/username identifiers consistently.

Password_hash is write-only from the API perspective.

Authentication responses never serialize password_hash.

Session/token expiry is configured.

Disabled users cannot authenticate.

Authorization checks use current persisted role/permission state where architecture requires it.

27. State Transition Validation

Alert and incident status transitions are validated in the service layer. Invalid transitions return a safe conflict/validation response. Every successful status mutation writes an audit record and may add an incident timeline entry.

Terminal states should not silently return to active states without an explicitly defined reopen workflow.

28. Transaction Boundaries

User/role mutation + audit should be transactionally consistent where practical.

Alert status mutation + audit should commit together.

Incident status mutation + audit/timeline should commit together.

Incident creation + incident_alert links should commit atomically.

Failure after event persistence must not falsely report an unpersisted event; analytics failure is separately observable.

29. Idempotency & Deduplication

When a source provides a stable source_event_id, the backend may enforce uniqueness within a source namespace. Demo replay must explicitly control whether duplicate runs create new data or reset a demo dataset.

Correlation must prevent duplicate incidents for the same active correlation key/window by updating an existing matching incident when appropriate.

30. Data Integrity Constraints

risk_score CHECK 0 <= risk_score <= 100.

criticality constrained to configured range.

rule_id unique.

incident_key unique.

junction tables use composite uniqueness.

required timestamps are NOT NULL.

foreign-key deletion behavior must not orphan evidence.

security evidence should not cascade-delete because a user or asset is removed.

31. Index Strategy

Table

Priority Indexes

events

timestamp; event_type+timestamp; source_ip+timestamp; username+timestamp; hostname+timestamp

alerts

status+severity+created_at; risk_score; rule_id; primary_event_id

incidents

status+risk_score; severity; created_at; assigned_to; primary_asset_id

incident_timeline

incident_id+timestamp

audit_logs

timestamp; actor_id; action; request_id

assets

hostname; ip_address; last_seen_at

Indexes should be measured against actual demo queries. Avoid indexing every JSON field.

32. JSONB Usage

Use JSONB for metadata, evidence summaries, MITRE metadata, declarative conditions, and risk explanation. Core query/filter fields remain typed columns. JSONB must not become a substitute for a coherent relational schema.

33. Retention

MVP retention is configurable and intended for synthetic/controlled hackathon telemetry. A future retention job may delete/archive old raw events according to policy while preserving required incident/audit evidence. No production retention claim should be made without implementation and testing.

34. Repository Layer

FastAPI routes should call services; services call repositories/ORM. Routes should not contain detection logic or raw SQL business logic.

API Route   ↓Pydantic Request Schema   ↓Service / Authorization   ↓Repository / SQLAlchemy   ↓PostgreSQL

35. Backend Package Guidance

backend/app/├── api/│   ├── auth.py│   ├── events.py│   ├── alerts.py│   ├── incidents.py│   ├── rules.py│   ├── assets.py│   └── dashboard.py├── core/│   ├── config.py│   ├── security.py│   └── logging.py├── models/├── schemas/├── repositories/├── services/├── db/└── main.pysecurity_engine/├── parsers/├── normalization/├── detection/├── correlation/└── risk/

36. Migration Plan

0001: users + enums

0002: assets

0003: events

0004: detection_rules

0005: alerts + alert_events

0006: incidents + incident_alerts + timeline + notes

0007: audit_logs

0008: indexes/constraints refinements

Optional later: ingestion_sources/search integration

Actual migration numbering may differ, but dependency order should be preserved.

37. Seed Data

Demo seed may create detection rules, a controlled set of assets, and explicitly configured demo users. Demo credentials must not be used as production defaults.

Initial CW-* detection rule definitions

SERVER-01 and optional demo assets

Known baseline events if needed for dashboard visualization

Golden-path telemetry should be generated/replayed separately so judges can observe state change

38. Security Requirements

Use parameterized ORM operations.

Validate all Pydantic request models.

Bound payload, batch, page, and query sizes.

Rate-limit authentication and ingestion.

Escape/safely serialize raw event content for frontend consumption.

Never expose password_hash or secrets.

Restrict CORS.

Use least-privilege DB credentials.

Audit privileged mutations.

Do not accept arbitrary executable detection rules.

39. Backend Acceptance Tests

BE-AC-01: migrations create schema on a clean database.

BE-AC-02: user authentication never returns password hashes.

BE-AC-03: RBAC blocks unauthorized mutations.

BE-AC-04: valid event persists canonical fields.

BE-AC-05: invalid event returns safe validation error.

BE-AC-06: threshold rule links all supporting events to alert.

BE-AC-07: correlation links alerts into one expected incident.

BE-AC-08: unrelated alerts are not incorrectly merged.

BE-AC-09: risk remains within 0–100 and explanation matches factors.

BE-AC-10: incident timeline references underlying evidence.

BE-AC-11: status mutations create audit records.

BE-AC-12: list APIs paginate and enforce maximum page size.

BE-AC-13: golden replay produces expected incident through public application APIs.

40. Golden Data Relationship

events  ├── scan_event(s)  ├── authentication_failure_event(s)  ├── authentication_success_event  └── privilege_event        ↓alerts  ├── CW-NET-001  ├── CW-AUTH-001  ├── CW-LOGIN-001  └── CW-PRIV-001        ↓incident_alerts        ↓incident  CW-INC-0042  Potential Host Compromise  CRITICAL / Risk 94        ↓incident_timeline  evidence in chronological order

41. Codex / Backend Agent Contract

Implement this schema as typed SQLAlchemy models, Alembic migrations, Pydantic request/response models, repositories, and services. Preserve the evidence chain and avoid shortcutting relationships for demo convenience.

Do not put authoritative business logic in API route handlers.

Do not store passwords or tokens in plaintext.

Do not make events, alerts, and incidents the same object.

Do not create incidents without linked alert evidence.

Do not calculate risk in the frontend.

Do not use arbitrary executable code for detection-rule conditions.

Add indexes only for actual query patterns and validate with tests.

Every critical mutation must include authorization, validation, transaction handling, audit, and tests.

42. Backend Definition of Done

The backend schema is complete when a clean PostgreSQL instance can be migrated, seeded in controlled demo mode, and used through FastAPI to authenticate users, ingest and normalize events, generate evidence-linked alerts, correlate alerts into incidents, calculate explainable risk, query dashboard/queues, update investigation state under RBAC, and record audit history.