CYBERWOLF SIEM

Application Flow Specification

User Journeys • Security Event Pipeline • Incident InvestigationVersion 1.0 • 31 July 2026

Document ID

CWS-AF-001

Parent Documents

CWS-PRD-001, CWS-TRD-001

Project

Cyberwolf SIEM

Scope

Hackathon MVP

Primary User

SOC Analyst

Golden Flow

Telemetry → Detection → Correlation → Incident → Investigation

1. Purpose

This document defines how users and security data move through Cyberwolf SIEM. It is the behavioral bridge between the PRD, TRD, UI/UX brief, backend schema, and implementation plan. Development agents should use these flows to determine required screens, API transitions, validation points, status changes, and acceptance tests.

2. Application Flow Principles

Every user journey begins from an authenticated identity unless the route is explicitly public.

Authorization is enforced by the backend at every protected action.

Every security finding must be traceable to normalized evidence.

Events, alerts, and incidents are separate objects with explicit relationships.

Failures must produce recoverable states rather than breaking the workflow.

The hackathon golden path must be deterministic and reproducible.

3. Master User Flow

START  ↓Login  ↓Authentication  ├── Invalid → Error / retry  └── Valid        ↓      Role resolved        ↓      SOC Dashboard        ├── Events        ├── Alerts        ├── Incidents        ├── Rules        ├── Assets        ├── Reports        └── Settings              ↓      Analyst investigation              ↓      Acknowledge / Investigate / Resolve              ↓            Audit              ↓            Logout

4. Master Security Data Flow

SECURITY SOURCE / DEMO GENERATOR            ↓      Event Ingestion            ↓        Validation       ├── Invalid → Reject/Quarantine + safe error       └── Valid            ↓          Parser            ↓       Normalization            ↓         Enrichment            ↓        Event Storage            ↓      Detection Engine       ├── No match → Event remains searchable       └── Match            ↓           Alert            ↓     Correlation Engine       ├── No correlation → Standalone alert       └── Correlated            ↓        Risk Scoring            ↓          Incident            ↓      Dashboard Update            ↓    Analyst Investigation

5. Flow AF-01 — Login & Session

Step

Actor/System

Action

Result

1

User

Open Cyberwolf

Login page

2

User

Enter credentials

Login request

3

Backend

Validate schema and rate limit

Request accepted/rejected

4

Identity Service

Verify account/password

Identity result

5

Backend

Resolve role/permissions

Authorized session/token

6

Frontend

Request current-user context

Role-aware UI

7

System

Record successful/failed login

Audit record

8

User

Enter dashboard

Authenticated workflow

Failure paths: malformed input → validation error; invalid credentials → generic authentication error; rate limit exceeded → retry-later response; disabled/unauthorized account → access denied. Sensitive authentication details must never appear in client errors.

6. Flow AF-02 — Dashboard

After authentication, the dashboard requests summary metrics and recent incidents/alerts. It must show real backend data, not hard-coded demo cards.

Events in selected period

Active alerts

Open incidents

Critical/high severity counts

Monitored assets

Event trend

Severity distribution

Recent incidents

Top detections/source entities

Selecting a dashboard item navigates to a filtered Events, Alerts, or Incident view. Live updates use WebSocket/SSE where implemented; polling is an acceptable fallback.

7. Flow AF-03 — Event Ingestion

Source  ↓POST /api/v1/events or bounded batch  ↓Source/user authorization  ↓Payload-size / rate-limit check  ↓Schema validation  ↓Source-type selection  ↓Parser  ↓Canonical Normalizer  ↓Persist normalized event  ↓Analytics pipeline

The ingestion response returns a processing identifier/result without leaking internal exceptions. Duplicate handling and idempotency may be added where source identifiers are available.

8. Flow AF-04 — Parsing & Normalization

Stage

Input

Output

Source identification

Raw envelope

Known source type

Parsing

Raw event

Structured source-specific fields

Timestamp normalization

Source timestamp

UTC timestamp

Field mapping

Source-specific names

Canonical names

Validation

Mapped fields

Valid canonical event

Preservation

Original record

raw_event + metadata

Example: a Linux failed-password record and an application login failure both normalize to event_type=authentication_failure while retaining original evidence.

9. Flow AF-05 — Detection

Normalized Event      ↓Select enabled rules for event_type      ↓Evaluate field conditions      ↓Update bounded threshold/window state if required      ↓Rule satisfied?   ├── No → End detection for rule   └── Yes        ↓Create evidence-backed alert        ↓Persist alert        ↓Publish alert update        ↓Send to correlation

Rule execution must be deterministic. A rule failure is isolated and logged; it must not crash the complete analytics pipeline.

10. Flow AF-06 — Alert Lifecycle

NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED. FALSE_POSITIVE is an allowed terminal classification.

Transition

Who

Required Behavior

NEW → ACKNOWLEDGED

Analyst/Admin

Record actor and timestamp

ACKNOWLEDGED → INVESTIGATING

Analyst/Admin

Allow investigation note

INVESTIGATING → RESOLVED

Analyst/Admin

Record resolution context

Any valid active state → FALSE_POSITIVE

Analyst/Admin

Record classification/note

Every mutation generates an audit record.

11. Flow AF-07 — Correlation

New Alert   ↓Extract entities:source_ip / destination_ip / username / hostname / asset   ↓Find candidate alerts within bounded time window   ↓Evaluate correlation rule   ├── Not satisfied → keep standalone alert   └── Satisfied          ↓      Link evidence          ↓      Calculate correlation confidence/bonus          ↓      Create or update incident

Correlation never deletes the original alerts. The incident stores references to contributing evidence so the analyst can inspect the full chain.

12. Flow AF-08 — Risk Scoring

Risk calculation occurs when an alert is created and when an incident gains new evidence. Inputs can include base rule risk, correlation bonus, compromise indicators, and asset criticality. Output is clamped to 0–100.

Severity mapping: 0–24 LOW; 25–49 MEDIUM; 50–74 HIGH; 75–100 CRITICAL. The UI must be able to show why the score was assigned.

13. Flow AF-09 — Incident Creation

Correlation satisfied      ↓Determine incident type      ↓Collect linked alerts/events      ↓Calculate risk + severity      ↓Identify affected entities      ↓Build chronological timeline      ↓Persist incident      ↓Publish dashboard update      ↓Incident appears in SOC queue

14. Flow AF-10 — Incident Investigation

Step

Analyst Action

System Response

1

Open incident

Load summary, status, risk, severity

2

Review affected entities

Show source/target/user/asset context

3

Review timeline

Show chronological linked evidence

4

Open related alert

Show rule and trigger evidence

5

Open source event

Show normalized + permitted raw event

6

Acknowledge/Investigate

Persist status and audit

7

Add note

Attach analyst context

8

Resolve/classify

Persist final state and audit

9

Return to queue

Updated metrics/status visible

15. Flow AF-11 — Event Explorer

Dashboard/Navigation → Events → apply filters → paginated query → event table → select event → event detail.

Time range

Source type

Event type

Severity

Source IP

Destination IP

Hostname

Username

Outcome

Optional free-text query

Event detail should expose canonical fields, safe metadata, related alerts/incidents, and raw evidence where permitted.

16. Flow AF-12 — Alert Center

Navigation/Dashboard → Alerts → filter/sort → select alert → inspect detection evidence → view related event → view/open related incident → update permitted status.

Viewer role is read-only. Analyst/Admin may perform allowed lifecycle changes.

17. Flow AF-13 — Rule Management

Admin → Rules → list enabled/disabled rules → inspect rule → enable/disable → backend authorization → persist state → audit action → update UI.

Rule editing/creation is optional for MVP. Arbitrary executable code must not be accepted as rule content.

18. Flow AF-14 — Asset Flow

Events may identify assets by hostname/IP. Known assets enrich event/incident context. Authorized users can view asset details including criticality, status, last seen, related events, alerts, and incidents.

19. Flow AF-15 — Audit Flow

Security-relevant user action → backend authorization → business mutation → audit event → persistent audit store. Audit records contain actor, action, target, timestamp, result, request/correlation ID, and safe metadata.

20. Flow AF-16 — Logout

User selects Logout → frontend calls logout/session invalidation → local authentication state cleared → user redirected to Login → audit record created where supported.

21. Role-Based Navigation

Area

Admin

Analyst

Viewer

Dashboard

Full

Full

Read

Events

Read

Read

Read

Alerts

Manage

Manage

Read

Incidents

Manage

Manage

Read

Rules

Manage

Read/Limited

Read

Assets

Manage

Read

Read

Audit

Read

No/limited

No

Users/Settings

Manage

No

No

22. Golden Demo Flow

1. Analyst logs in.2. Dashboard initially shows normal/known demo state.3. Controlled telemetry replay starts.4. Scan-like event is ingested and normalized.5. Authentication failures arrive from a related source.6. A successful authentication event follows.7. A privilege-related event arrives.8. Detection rules create alerts.9. Correlation links the related findings.10. Risk engine produces a high/critical score.11. Potential Host Compromise incident is created.12. Dashboard updates.13. Analyst opens the incident.14. Timeline shows scan → failures → success → privilege event.15. Analyst acknowledges and investigates the incident.16. Status change is audited.

This is the primary Round 4 output-validation and Round 5 presentation path.

23. UI Route Map

Route

Screen

Primary Data

/login

Login

Authentication

/

Dashboard

Metrics, recent alerts/incidents

/events

Event Explorer

Normalized events

/events/:id

Event Detail

Event + relationships

/alerts

Alert Center

Alerts

/alerts/:id

Alert Detail

Rule + evidence

/incidents

Incident Queue

Incidents

/incidents/:id

Investigation

Timeline + evidence

/rules

Detection Rules

Rule metadata/state

/assets

Assets

Asset context

/reports

Reports

Aggregated security data

/settings

Settings

Authorized configuration

24. Backend Sequence — Single Event

Client/Collector → API GatewayAPI Gateway → Auth/Rate LimitAuth → Ingestion ServiceIngestion → ValidatorValidator → ParserParser → NormalizerNormalizer → Event RepositoryEvent Repository → Detection EngineDetection Engine → Alert Repository (if matched)Alert → Correlation EngineCorrelation → Risk EngineRisk → Incident Service (if correlated)Incident Service → DatabaseBackend → Realtime GatewayRealtime Gateway → SOC UI

25. Error & Recovery Flow

Condition

User/System Flow

Invalid credentials

Remain on login; generic error; audit failure

Malformed event

Reject/quarantine; pipeline stays healthy

Unknown source

Safe unsupported-source response or configured generic parser

Rule error

Log/isolate failed rule; continue other rules

No rule match

Persist event; no false alert generated

No correlation

Alert remains standalone

Database unavailable

Health failure; no fabricated success

Realtime connection lost

Reconnect or fallback polling

Unauthorized action

403; no mutation; audit where appropriate

26. State Ownership

Object

Created By

Updated By

Consumed By

User/Role

Admin/seed

Admin

Auth/UI

Event

Ingestion pipeline

Immutable except controlled metadata

Detection/Search

Alert

Detection engine

Analyst/Admin status

Correlation/UI

Incident

Correlation/Incident service

Analyst/Admin + correlation

Investigation/UI

Rule

Seed/Admin

Admin

Detection engine

Asset

Seed/discovery/admin

Authorized services/admin

Enrichment/UI

Audit Record

Backend

Logically immutable

Admin/audit review

27. Acceptance Criteria

AF-01: Valid login reaches the role-appropriate dashboard; invalid login does not.

AF-02: A valid event traverses ingestion, normalization, and persistence.

AF-03: Malformed telemetry does not crash the application.

AF-04: A matching event sequence generates expected alerts.

AF-05: Related alerts correlate while unrelated alerts remain separate.

AF-06: Incident risk/severity are deterministic and explainable.

AF-07: Dashboard and queues display backend state.

AF-08: Incident detail exposes linked evidence and timeline.

AF-09: Role restrictions are enforced by backend APIs.

AF-10: Alert/incident state mutations generate audit records.

AF-11: Golden demo is reproducible from documented commands/data.

28. Codex / Developer Handoff Rules

Implement flows in the order defined by the golden path before optional screens.

Do not bypass backend authorization because the frontend hides a control.

Do not create alerts without rule/evidence references.

Do not create incidents without linked alert evidence.

Keep event normalization deterministic and source-independent.

Represent loading, empty, error, unauthorized, and success states in the UI.

Add automated tests for each critical transition and failure path.

Do not add autonomous offensive actions; demo telemetry must remain controlled/local/synthetic.

29. Relationship to Remaining Documents

The UI/UX Design Brief must translate these journeys into screens and components. The Backend Schema must implement the objects, relationships, status transitions, and API contracts defined here. The Implementation Plan must schedule these flows in dependency order.

30. Application Flow Definition of Done

The Application Flow specification is satisfied when a developer can trace every critical user action and every security event from entry to final state without undefined transitions. The implemented MVP must reproduce the complete login → dashboard → telemetry → detection → correlation → incident → investigation → audit workflow.