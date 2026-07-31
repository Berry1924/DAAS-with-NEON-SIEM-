CYBERWOLF SIEM

Technical Requirements Document (TRD)

Engineering Specification for Hackathon MVPVersion 1.0 • 31 July 2026

Document ID

CWS-TRD-001

Parent Document

CWS-PRD-001

Architecture

Secure Modular Monolith

Backend

Python + FastAPI

Frontend

React + TypeScript

Primary Database

PostgreSQL

1. Purpose

This TRD converts the Cyberwolf SIEM PRD into an implementable engineering specification. It defines system boundaries, components, data flow, APIs, security controls, storage, detection, correlation, deployment, testing, and operational requirements. The hackathon priority is a reliable end-to-end pipeline rather than unnecessary distributed complexity.

2. Technical Objectives

Implement telemetry ingestion → parsing → normalization → detection → correlation → risk scoring → alert/incident → investigation.

Provide a secure REST API and live dashboard updates.

Keep detection evidence deterministic and explainable.

Use modular boundaries so collectors, rules, storage, and analytics can evolve independently.

Provide reproducible local deployment and automated tests.

Support controlled synthetic/replayed events for safe judging demonstrations.

3. Architecture Decision

Cyberwolf v1 uses a modular monolith. FastAPI hosts API, authentication, ingestion, analytics orchestration, and application services. PostgreSQL is the system of record. React/TypeScript provides the SOC interface. Components are logically separated so they can later become independent services.

OpenSearch is an optional extension for higher-volume full-text event search; it is not a dependency for the MVP golden path.

4. High-Level Architecture

Security Sources / Demo Generator        ↓Ingestion API        ↓Validation & Parser        ↓Normalizer        ↓Event Repository (PostgreSQL)        ↓Detection Engine        ↓Alerts        ↓Correlation Engine        ↓Risk Engine        ↓Incident Manager        ↓REST API / WebSocket        ↓React SOC Dashboard

5. Technology Stack

Layer

MVP Technology

Purpose

Frontend

React + TypeScript

SOC dashboard and analyst workflows

UI

Tailwind CSS or equivalent component styling

Responsive design system

Backend

Python + FastAPI

API and application runtime

Validation

Pydantic

Typed request/event contracts

ORM

SQLAlchemy

Persistence abstraction

Database

PostgreSQL

System of record

Migrations

Alembic

Versioned schema changes

Authentication

Secure password hashing + signed access/session tokens

Identity

Testing

pytest + backend test client; frontend test tooling

Automated verification

Containerization

Docker / Docker Compose

Reproducible local runtime

Search extension

OpenSearch — optional

Large-volume event search

6. Repository Structure

cyberwolf-siem/├── frontend/│   ├── src/components/│   ├── src/pages/│   ├── src/services/│   ├── src/types/│   └── src/hooks/├── backend/│   ├── app/api/│   ├── app/core/│   ├── app/models/│   ├── app/schemas/│   ├── app/services/│   ├── app/repositories/│   └── app/main.py├── security_engine/│   ├── parsers/│   ├── normalization/│   ├── detection/│   ├── correlation/│   └── risk/├── rules/├── tests/├── demo/├── docs/├── docker-compose.yml├── .env.example└── README.md

7. Core Components

ID

Component

Responsibility

C01

Identity Service

Authentication, users, roles and authorization

C02

Ingestion Service

Receive and validate telemetry

C03

Parser Registry

Select source-specific parser

C04

Normalizer

Convert parsed records into canonical events

C05

Event Repository

Persist/query normalized events

C06

Detection Engine

Evaluate rules and generate findings/alerts

C07

Correlation Engine

Associate related alerts into attack sequences

C08

Risk Engine

Calculate explainable severity/risk

C09

Incident Service

Create/update incidents and timelines

C10

Audit Service

Record security-relevant application actions

C11

Realtime Gateway

Push dashboard updates

C12

Demo Generator

Produce deterministic controlled event sequences

8. Canonical Event Contract

Every parser must output the same canonical event contract before analytics execution.

Field

Type

Requirement

event_id

UUID

Required

timestamp

UTC datetime

Required

source_type

string/enum

Required

event_type

string

Required

source_ip

IP/string

Optional

destination_ip

IP/string

Optional

hostname

string

Optional

username

string

Optional

action

string

Optional

outcome

enum/string

Optional

severity

enum

Required/default INFO

raw_event

text/JSON

Required

metadata

JSON object

Required/default {}

Unknown fields must be retained safely in metadata when useful. Invalid required fields are rejected or quarantined; malformed events must never crash the ingestion worker/request.

9. Ingestion Pipeline

POST /api/v1/events receives one event; POST /api/v1/events/batch accepts bounded batches. Payload size and batch size are configurable and rate-limited.

Processing sequence: Authenticate source/user → validate envelope → identify source type → parse → normalize → persist event → run detection → persist alerts → run correlation → update/create incidents → publish UI update.

MVP processing may run synchronously or through an in-process background queue, but each event must have an observable processing result. Future architecture may introduce Kafka/Redis streams without changing the canonical event contract.

10. Parser Architecture

Parsers implement a common interface: supports(source_type), parse(raw_payload) → ParsedEvent. Parser failures return structured errors and are logged without exposing secrets.

JSON/application parser

Linux/auth parser

Synthetic demo parser

Optional Suricata EVE JSON parser

Optional Windows/Zeek parser

11. Normalization

Normalization maps source-specific names to canonical event types. Example: Linux 'Failed password' and an application login failure both become authentication_failure while preserving the original record in raw_event.

Timestamps are normalized to UTC. IP values are validated. Severity and outcome use controlled enumerations. The normalizer must be deterministic and unit tested.

12. Detection Engine

Detection rules are data-driven where practical and evaluated against canonical events. Rule execution must not execute arbitrary user-supplied code.

Rule Attribute

Description

rule_id

Stable identifier, e.g. CW-AUTH-001

name

Human-readable title

event_types

Applicable canonical event types

conditions

Field predicates

group_by

Entity such as source_ip or username

threshold

Required count

window_seconds

Time window

severity

LOW/MEDIUM/HIGH/CRITICAL

risk_weight

Risk contribution

mitre

Optional ATT&CK technique metadata

enabled

Runtime state

Threshold rules maintain bounded state per grouping key and time window. Expired observations must be removed to prevent unbounded memory growth.

13. Initial Rules

CW-AUTH-001 — repeated authentication failures from one source within a time window.

CW-AUTH-002 — one source targeting multiple accounts.

CW-NET-001 — scan-like activity across multiple target ports/services.

CW-WEB-001 — suspicious web-request pattern from controlled demo/application telemetry.

CW-PRIV-001 — privilege-related event following suspicious authentication activity.

CW-LOGIN-001 — successful login after a threshold of failures.

CW-IDS-001 — high-severity normalized IDS finding.

14. Correlation Engine

Correlation operates on alerts/findings, not raw strings. It groups evidence using entity relationships and bounded time windows. Correlation rules describe prerequisite alert types, shared entities, maximum time gap, minimum confidence, resulting incident type, and risk bonus.

Golden correlation: scan finding + authentication failures + successful login + privilege event on related entities → Potential Host Compromise.

The engine must retain IDs of all contributing alerts so every incident is explainable and auditable.

15. Risk Scoring

Risk is deterministic and clamped to 0–100. The MVP uses configurable weighted contributions rather than ML.

Reference model: base rule risk + correlation bonuses + compromise indicator bonuses + asset criticality modifier, capped at 100. Exact weights live in configuration and are included in incident evidence.

Range

Severity

0–24

LOW

25–49

MEDIUM

50–74

HIGH

75–100

CRITICAL

16. Alert Lifecycle

NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED. FALSE_POSITIVE is an allowed terminal classification. Status changes record actor, timestamp, previous state, new state, and optional analyst note.

17. Incident Model

Incidents contain ID, title, type, severity, risk score, status, source entities, affected assets/users, timestamps, correlation rule, evidence summary, assigned analyst, and linked alerts.

Incident timeline entries reference source events/alerts instead of duplicating unverifiable descriptions.

18. API Design

Method

Endpoint

Purpose

Access

POST

/api/v1/auth/login

Authenticate user

Public/rate limited

POST

/api/v1/auth/logout

End session

Authenticated

GET

/api/v1/me

Current identity/role

Authenticated

POST

/api/v1/events

Ingest event

Authorized source/admin

POST

/api/v1/events/batch

Ingest bounded batch

Authorized source/admin

GET

/api/v1/events

Search/filter events

Viewer+

GET

/api/v1/alerts

List/filter alerts

Viewer+

PATCH

/api/v1/alerts/{id}

Update alert status

Analyst+

GET

/api/v1/incidents

List incidents

Viewer+

GET

/api/v1/incidents/{id}

Incident evidence/timeline

Viewer+

PATCH

/api/v1/incidents/{id}

Manage incident

Analyst+

GET

/api/v1/rules

List rules

Viewer+

PATCH

/api/v1/rules/{id}

Enable/disable rule

Admin

GET

/api/v1/assets

List assets

Viewer+

GET

/api/v1/dashboard/summary

SOC metrics

Viewer+

GET

/api/v1/audit

Audit records

Admin

API responses use versioned JSON contracts. Pagination is mandatory for list endpoints. Filter values are validated. Internal exceptions are mapped to safe error responses.

19. Authentication & Authorization

Passwords are stored only as modern password hashes. Tokens/session identifiers are signed/validated, expire, and must not contain secrets. Authorization is enforced server-side on every protected route; hiding UI controls is not authorization.

ADMIN — users, rules, settings, full operational access.

ANALYST — investigate and manage alerts/incidents.

VIEWER — read-only monitoring and reports.

20. Database Architecture

PostgreSQL is authoritative for users, roles, assets, events, rules, alerts, incidents, relationships, and audit records. Foreign keys and indexes protect integrity and query performance.

Index events by timestamp, event_type, source_ip, hostname, and username as required.

Index alerts by created_at, severity, status, rule_id, and risk score.

Index incidents by created_at, severity, status, and risk score.

Use JSONB for extensible metadata while keeping frequently queried security fields relational.

Use migrations; do not mutate production schema manually.

21. Realtime Updates

The dashboard may use WebSocket or server-sent events for new alerts/incidents and metric refreshes. Authentication is required for realtime connections. Reconnect logic must not duplicate incident records. Polling is an acceptable fallback for the hackathon.

22. Frontend Architecture

React pages: Login, Dashboard, Events, Alerts, Incident Detail, Rules, Assets, Reports, Settings. API access is centralized in a typed service layer. Authentication state and role checks are shared, while the backend remains the authorization authority.

Reusable severity badges and metric cards

Paginated/filterable event and alert tables

Incident evidence timeline

Loading, empty, error and unauthorized states

Responsive layout suitable for laptop demo

23. Security Controls

Validate all inbound data with typed schemas.

Rate-limit authentication and ingestion endpoints.

Use least-privilege database credentials.

Keep credentials and API keys outside Git; commit only .env.example.

Restrict CORS to known frontend origins.

Do not log passwords, tokens, secrets, or sensitive authorization headers.

Audit privileged actions.

Use parameterized ORM/database operations.

Limit batch sizes, payload sizes, query page sizes, and expensive filters.

Return generic authentication failures to clients.

Keep demo attack generation isolated to synthetic/local test data.

24. Audit Requirements

Audit records contain immutable logical facts: audit_id, timestamp, actor_id, action, target_type, target_id, result, request correlation ID, and safe metadata. Security-relevant mutations must produce an audit record.

25. Observability

Structured application logs with timestamp, level, component, request/correlation ID, and message.

Health endpoint for application/database readiness.

Metrics: ingested events, parse failures, detections, alerts, incidents, API errors, processing latency.

Never expose sensitive configuration through health or debug endpoints.

26. Failure Handling

Failure

Expected Behavior

Malformed event

Reject/quarantine; record safe error; service remains healthy

Unknown source type

Return supported-source error or preserve as generic JSON if configured

Database unavailable

Fail safely; health becomes unhealthy; no fabricated success

Detection rule error

Isolate rule failure and log it; do not crash entire pipeline

Correlation error

Retain alerts; report correlation failure

Unauthorized API call

401/403 without protected data

Frontend API failure

Show recoverable error state

27. Performance Targets for MVP

Dashboard API should feel interactive under hackathon demo load.

List endpoints use pagination and bounded page sizes.

Single-event processing should complete fast enough for visible near-real-time demonstration.

Batch ingestion is bounded to protect memory/CPU.

Detection/correlation state is bounded by time windows and grouping limits.

These are MVP engineering objectives, not claims of enterprise-scale throughput. Performance claims shown to judges must be measured on the actual demo environment.

28. Testing Strategy

Test Layer

Coverage

Unit

Parsers, normalizer, rule predicates, thresholds, risk scoring

API

Authentication, authorization, validation, pagination, CRUD/status flows

Integration

Ingestion through persistence and analytics

Correlation

Known sequences create expected incidents; unrelated alerts do not

Security

RBAC, rate limits, malformed payloads, secret/logging checks

Frontend

Critical rendering and analyst workflows

Golden Path

Deterministic replay produces expected incident and timeline

Round 3 verification should use a clean automated command and produce zero failing required tests.

29. Golden Path Acceptance Test

Given controlled telemetry representing scanning, repeated authentication failures, a successful login, and a privilege event, Cyberwolf must persist normalized events, generate the expected detections, correlate related findings, calculate risk, create a Potential Host Compromise incident, and expose its evidence/timeline through the API and SOC dashboard.

30. Deployment

MVP deployment uses Docker Compose with frontend, backend, and PostgreSQL services. Optional OpenSearch is isolated behind a profile or separate compose configuration.

Startup sequence: configure .env from .env.example → start database → run migrations → start backend → seed rules/demo user where explicitly enabled → start frontend → verify health → run golden demo.

Production-like defaults must not automatically create known credentials unless explicitly in demo mode.

31. Configuration

DATABASE_URL

Authentication signing/session configuration

Allowed frontend origins

Rate limits

Detection thresholds/windows

Risk weights

Demo mode flag

Log level

Optional search-engine connection

32. Data Retention & Privacy

The hackathon uses synthetic or intentionally supplied telemetry. Retention is configurable. Raw events are retained only as necessary for evidence and debugging. Credentials, access tokens, encryption keys, and unnecessary sensitive data must not be placed into event logs.

33. Development Sequence

P0: project bootstrap → database/migrations → authentication/RBAC → event contract → ingestion → normalization → event persistence → detection → alerts → correlation → risk → incidents → dashboard → golden test.

P1: event search → asset model → MITRE metadata → audit improvements → realtime updates → reports.

P2: optional OpenSearch, Suricata/Zeek adapters, threat intelligence, AI analyst.

34. Hackathon Round Mapping

Round

Engineering Gate

1

TRD, architecture, flow, repository skeleton, technical decisions documented

2

Application boots; auth, DB, ingestion, normalization, basic dashboard operational

3

Detection/correlation/risk/security implemented and automated verification passes

4

Golden telemetry replay generates correct evidence-backed incident

5

Stable full demo, measured metrics, architecture explanation, roadmap

35. Technical Definition of Done

docker compose starts the required MVP services from documented instructions.

Database migrations complete successfully.

Authentication and server-side RBAC pass tests.

Events validate, normalize, persist, and remain searchable.

Required detection rules generate evidence-backed alerts.

Correlation creates expected incidents without merging unrelated evidence.

Risk score is deterministic and explainable.

Dashboard displays real backend data.

Incident view exposes linked evidence and timeline.

Audit records cover privileged actions.

Golden-path automated/integration test passes.

No required secrets are committed.

README documents setup, test, demo, and architecture.

36. Codex / Engineering Agent Contract

Treat CWS-PRD-001 and this TRD as authoritative. Preserve the canonical event contract and end-to-end golden path. Do not introduce Kafka, Kubernetes, autonomous response, ML detection, or other scope expansions before P0 is complete.

Before modifying architecture, identify the affected requirement/component and preserve backward-compatible API/data contracts where possible. Each implementation change must include validation, error handling, tests, and documentation.

Security findings must originate from deterministic evidence. AI features, if added later, may summarize or recommend investigation steps but must not silently create unsupported incident facts.