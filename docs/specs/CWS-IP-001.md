CYBERWOLF SIEM

Implementation Plan

Hackathon Build Strategy • Team Execution • Verification • DemoVersion 1.0 • 31 July 2026

Document ID

CWS-IP-001

Parent Documents

CWS-PRD-001, CWS-TRD-001, CWS-AF-001, CWS-UX-001, CWS-BE-001

Project

Cyberwolf SIEM

Architecture

Secure Modular Monolith

Delivery Model

Five-round hackathon execution

Primary Goal

Reproducible end-to-end SIEM golden path

Core Pipeline

Collect → Normalize → Detect → Correlate → Prioritize → Investigate

1. Purpose

This plan converts the five preceding Cyberwolf specifications into an ordered engineering program for the hackathon. It defines scope priorities, dependencies, team workstreams, implementation phases, security gates, verification, Git workflow, demo preparation, and acceptance criteria.

Implementation rule: complete and verify the end-to-end golden path before adding optional complexity.

2. Delivery Objective

The MVP succeeds when controlled telemetry enters Cyberwolf, is normalized and stored, triggers evidence-backed detections, correlates into a prioritized incident, appears in the SOC interface, and can be investigated by an authenticated analyst.

Golden path: Login → Dashboard → Telemetry Replay → Ingestion → Normalization → Detection → Alerts → Correlation → Risk → Incident → Evidence Timeline → Analyst Status Update → Audit.

3. Scope Priority

Priority

Meaning

Capabilities

P0

Required

Repo, DB, auth/RBAC, ingestion, normalization, events, detection, alerts, correlation, risk, incidents, dashboard, investigation, audit, golden test

P1

After P0 stable

Search improvements, assets, MITRE metadata, rule management, realtime updates, reports

P2

Only if time remains

Suricata/Zeek adapters, OpenSearch, threat intelligence, AI analyst, advanced analytics

No P2 feature may delay or destabilize a P0 capability.

4. Team Workstreams

Workstream

Responsibility

Deliverables

WS1 Architecture/Security

Requirements, detection design, correlation, review

Architecture, rules, risk logic, demo narrative

WS2 Backend

FastAPI, auth, services, APIs

Secure backend runtime

WS3 Data/Analytics

PostgreSQL, normalization, evidence model

Data layer and analytics pipeline

WS4 Frontend

React SOC workflows

Dashboard, events, alerts, investigation

WS5 QA/DevOps

Tests, Docker, security verification

Reproducible validated build

5. Suggested Four-Person Ownership

Owner

Primary

Secondary

A — Security/Architecture

Detection, correlation, risk, architecture

Presentation/security review

B — Backend

FastAPI, auth/RBAC, services/API

Database integration

C — Frontend

Dashboard, queues, incident UX

API integration

D — Data/QA/DevOps

PostgreSQL, migrations, tests, Docker, demo generator

Observability/docs

With a different team size, preserve module ownership and review boundaries rather than dividing work only by frontend/backend.

6. Phase 0 — Repository Bootstrap

Create GitHub repository and README.

Create frontend/, backend/, security_engine/, rules/, tests/, demo/, docs/.

Add .gitignore and .env.example; never commit real secrets.

Create Docker Compose baseline.

Configure Python/frontend dependency manifests.

Configure test, formatting, and lint commands.

Place/link the six specifications in docs/.

Exit gate: a new developer can clone the repository and understand how the product is structured.

7. Phase 1 — Database Foundation

Start PostgreSQL.

Configure SQLAlchemy and Alembic.

Implement enums/users, assets, events, detection rules, alerts/evidence links, incidents/evidence links, timelines, notes, audit logs.

Add constraints and priority indexes.

Create controlled seed command for rules and demo assets.

Exit gate: clean migration from an empty database succeeds and schema tests pass.

8. Phase 2 — Authentication & RBAC

Implement user models/schemas and secure password hashing.

Implement login, logout, current-user/session flow.

Implement ADMIN, ANALYST, VIEWER.

Enforce reusable server-side authorization.

Rate-limit authentication.

Audit login and privileged actions.

Build frontend login/authenticated routing.

Exit gate: protected APIs reject invalid identity/roles and authorization tests pass.

9. Phase 3 — Canonical Event Pipeline

Implement EventCreate/EventRead contracts.

Implement parser interface/registry and demo/generic JSON parsers.

Implement deterministic normalization, UTC timestamps, IP/enumeration validation.

Persist canonical event plus safe raw evidence/metadata.

Implement single and bounded batch ingestion.

Limit payload/batch sizes.

Implement event query API and basic Event Explorer.

Exit gate: valid events persist/search; malformed telemetry returns safe errors without crashing.

10. Phase 4 — Detection Engine

Define restricted declarative rule schema.

Implement event-type selection and allowlisted safe operators.

Implement bounded threshold/time-window state.

Create alerts and alert-event evidence links.

Seed initial CW-* rules.

Add positive and negative unit tests.

Exit gate: deterministic fixtures produce expected evidence-backed alerts.

11. Phase 5 — Correlation Engine

Define correlation configuration.

Extract source IP, destination IP, username, hostname and asset entities.

Search bounded candidate windows.

Implement golden correlation sequence.

Prevent duplicate active incidents for the same key/window.

Create incident-alert links and chronological timeline.

Exit gate: related alerts form one expected incident; unrelated alerts stay separate.

12. Phase 6 — Risk Engine

Implement configurable base risk.

Add correlation and compromise-indicator bonuses.

Add asset criticality modifier where available.

Clamp 0–100 and map severity.

Persist risk explanation.

Exit gate: identical evidence yields identical explainable risk.

13. Phase 7 — Alert & Incident Services

Implement list/detail APIs.

Validate lifecycle transitions.

Implement analyst notes and optional assignment.

Audit status mutations.

Add relevant timeline entries.

Implement bounded pagination/filtering/sorting.

Exit gate: analyst can triage and investigate through application APIs.

14. Phase 8 — SOC Frontend

Build App Shell and Login.

Build Dashboard.

Build Event Explorer/Detail.

Build Alert Center/Detail.

Build Incident Queue.

Build flagship Incident Investigation.

Build Rules/Assets after core flow.

Build Reports/Settings only after core flow is stable.

Exit gate: core pages use real backend state and include loading, empty, error and unauthorized states.

15. Phase 9 — Dashboard Integration

Implement dashboard summary API.

Expose event/alert/incident metrics, severity distribution, trends, priority incidents.

Add WebSocket/SSE only if stable; keep polling fallback.

Ensure replay visibly changes dashboard state.

Exit gate: judges can observe backend security activity through the UI.

16. Phase 10 — Security Hardening

Review every protected endpoint for authorization.

Review password/token/secret handling.

Restrict CORS.

Rate-limit authentication and ingestion.

Bound payload, batch, page and query sizes.

Safely render raw events.

Remove unsafe debug output/stack traces.

Use least-privilege database configuration.

Verify privileged actions are audited.

Exit gate: security checklist passes and no known secret is committed.

17. Phase 11 — Automated Verification

Suite

Coverage

Unit

Parsers, normalizer, rules, thresholds, correlation, risk

API

Auth, RBAC, validation, pagination, lifecycle

Integration

Ingestion → persistence → detection → alert

Correlation

Golden sequence plus unrelated negative case

Security

Unauthorized access, rate limits, malformed payloads, safe errors

Database

Migrations, constraints, evidence relationships

Golden Path

Controlled replay → expected incident

Round 3 must have a documented verification command and zero required failing tests.

18. Phase 12 — Demo Generator

Create deterministic baseline telemetry.

Create scan-like events.

Create repeated authentication failures.

Create successful authentication event.

Create privilege-related event.

Provide reset/reseed/replay commands.

Keep all demo activity local, synthetic, or intentionally supplied.

The generator validates Cyberwolf; it is not an external attack tool.

19. Round 1 — PPT, Flow & Architecture

Finalize the five-slide PPT.

Present problem, architecture, proposed solution, selection rationale and vision.

Show Collect → Normalize → Detect → Correlate → Prioritize → Investigate.

Create GitHub foundation and README.

Keep all six engineering documents available as supporting evidence.

Gate: judges understand exactly what will be built and how data flows.

20. Round 2 — Base Code, Idea & Solution

Application boots.

PostgreSQL migrations run.

Login/RBAC works.

Ingestion, normalization and event persistence work.

Dashboard/Event Explorer use backend data.

At least one real detection rule generates an alert.

README startup instructions work.

Gate: demonstrate working software, not mock-only screens.

21. Round 3 — Code Verification

Complete detection, correlation and risk pipeline.

Complete alert/incident services.

Run automated tests.

Show clean setup/migrations.

Demonstrate authorization and malformed-input handling.

Review repository for secrets and accidental artifacts.

Document architecture and verification commands.

Gate: reproducible verification with zero required failing tests.

22. Round 4 — Output Validation

Baseline Dashboard → Replay Controlled Telemetry → Events → Rules → Alerts → Correlation → Risk → Incident → Timeline/Evidence.

Record expected event/alert/incident outcomes for the golden fixture.

Verify exact rule IDs.

Verify risk explanation and timeline order.

Verify unrelated control event is not correlated.

Prepare screenshot/video only as backup evidence; live system remains primary.

Gate: input → processing → output is measurable and reproducible.

23. Round 5 — Final Presentation

30–45 seconds: problem and proposition.

45–60 seconds: architecture.

2–3 minutes: live golden-path demo.

45 seconds: detection/correlation/risk evidence.

30–45 seconds: security engineering and tests.

30 seconds: roadmap and closing.

Closing proposition: Cyberwolf converts fragmented security events into prioritized, explainable security incidents.

24. Git & GitHub Workflow

Keep main stable; use short-lived branches such as feat/auth, feat/ingestion, feat/detection, feat/dashboard.

Pull/rebase appropriately before integration.

Commit small coherent changes with descriptive messages.

Merge after relevant tests pass.

Avoid large last-minute merges.

Never commit .env, credentials, tokens, sensitive dumps, or generated build artifacts.

Suggested prefixes: feat:, fix:, test:, docs:, refactor:, chore:.

25. Integration Order

1 Repo/bootstrap → 2 Database → 3 Auth/RBAC → 4 Event schema → 5 Ingestion → 6 Normalization → 7 Event storage/search → 8 Detection → 9 Alerts → 10 Correlation → 11 Risk → 12 Incidents → 13 Dashboard → 14 Investigation UI → 15 Audit/security → 16 Golden tests → 17 Optional features.

26. API Integration Strategy

Backend publishes typed/versioned contracts.

Frontend uses one typed API service layer.

Do not duplicate authoritative detection/risk logic in the browser.

Mocks are temporary and must be replaced before feature completion.

Integrate each page when its backend endpoint is available instead of waiting for the entire backend.

27. Definition of Feature Complete

Implementation exists.

Validation exists.

Authorization exists where required.

Persistence/relationships are correct.

Frontend is connected where applicable.

Loading/error/empty states exist.

Automated tests exist.

Privileged mutations are audited.

Documentation is updated.

Feature works without manual database editing.

28. Engineering Loop

Select highest-priority incomplete P0 task → implement smallest vertical slice → run focused tests → integrate → run regression → commit → update task board → repeat.

Prefer demonstrable vertical slices over large isolated subsystems.

29. Task Board

Column

Meaning

BACKLOG

Approved work not started

READY

Dependencies satisfied

IN PROGRESS

One owner actively implementing

REVIEW

Code/test/security review

VERIFY

Integrated acceptance test

DONE

Feature-complete definition satisfied

30. Risk Register

Risk

Impact

Mitigation

Over-scoping

Core demo unfinished

Freeze P2 until P0 passes

Frontend/backend mismatch

Broken demo

Typed contracts + early integration

Detection false positives

Weak credibility

Deterministic fixtures + negative tests

Correlation duplicates

Confusing incidents

Key/window + idempotency tests

Secret leakage

Security failure

Environment handling + repository review

Migration failure

Setup failure

Repeated clean migration tests

Realtime instability

Demo disruption

Polling fallback

External integration failure

Blocked demo

Synthetic/local telemetry primary

Late merge conflicts

Lost time

Small branches, frequent integration

Unmeasured claims

Judge challenge

Present only measured evidence

31. Security Checklist

No plaintext passwords or committed secrets.

RBAC enforced server-side.

Authentication/ingestion rate limited.

Input schemas and size limits enforced.

Raw event content safely rendered.

ORM/parameterized database operations.

CORS restricted.

Debug mode reviewed.

Audit trail operational.

Demo telemetry controlled/local/synthetic.

32. Pre-Round Verification Checklist

git status understood and intentional.

Application starts from documented commands.

Database migrations succeed.

Health checks succeed.

Login works.

Round-specific/golden tests pass.

No critical frontend runtime errors.

No unexpected backend exceptions.

Required files/links are accessible.

Presenter and demo operator roles are assigned.

33. Demo Recovery Plan

Keep deterministic reset/reseed command.

Document service restart commands.

Keep a known-good commit/tag.

Keep sample API requests and expected outputs.

Use screenshots/short recording only as transparent fallback evidence.

Assign one person to operate the demo and another to present.

34. Metrics to Capture

Automated test pass count.

Golden-path expected vs actual result.

Implemented event sources/parsers.

Tested detection rule count.

Expected vs actual alerts/incidents.

Measured latency/throughput only if benchmarked.

Security checklist completion.

Do not claim enterprise scale, AI accuracy, or zero false positives without measured evidence.

35. Optional AI Analyst — P2

After P0 is stable, an AI assistant may summarize existing incident evidence and suggest investigation steps. It must distinguish generated guidance from deterministic security facts and must not silently change risk, fabricate evidence, or autonomously remediate systems.

36. Documentation Package

README — overview, architecture, setup, run, test and demo.

PRD.

TRD.

Application Flow.

UI/UX Design Brief.

Backend & Data Schema.

Implementation Plan.

Optional architecture diagram/API reference.

Demo guide with reset, replay and expected results.

37. Final Acceptance Criteria

IP-AC-01: Repository starts from documented setup.

IP-AC-02: Clean database migration succeeds.

IP-AC-03: Authentication/RBAC pass.

IP-AC-04: Event ingestion/normalization/storage pass.

IP-AC-05: Required detection fixtures pass.

IP-AC-06: Correlation creates expected incident and rejects unrelated sequences.

IP-AC-07: Risk is deterministic and explained.

IP-AC-08: Dashboard uses live backend state.

IP-AC-09: Incident investigation exposes linked evidence/timeline.

IP-AC-10: Status changes persist and audit.

IP-AC-11: Required tests have zero failures.

IP-AC-12: No known secrets are committed.

IP-AC-13: Golden demo repeats successfully after reset.

IP-AC-14: Team can explain architecture, security, limitations and roadmap.

38. Codex / Engineering Agent Contract

Treat all six Cyberwolf documents as authoritative. Implement P0 dependency order before P1/P2. Before coding, identify the affected requirement, module, contract, tests and acceptance condition.

Never mark hard-coded UI data as a completed backend feature.

Never weaken authentication/RBAC for demo convenience.

Never invent security evidence.

Never execute arbitrary user-supplied detection code.

Never add major infrastructure before the golden path is stable.

Every critical change includes tests and safe error handling.

Preserve incident → alert → event traceability.

Keep the application runnable after each integrated milestone.

Report blockers and failures instead of hiding them.

39. Final Build Sequence for Codex

MILESTONE 1 — FOUNDATIONRepository + Docker + PostgreSQL + migrations + healthMILESTONE 2 — IDENTITYUsers + login + RBAC + auditMILESTONE 3 — TELEMETRYEvent contract + ingestion + parser + normalization + storageMILESTONE 4 — DETECTIONRules + threshold engine + evidence-linked alertsMILESTONE 5 — CORRELATIONEntity/time correlation + incident creationMILESTONE 6 — RISKDeterministic scoring + explanationMILESTONE 7 — SOCDashboard + events + alerts + incident investigationMILESTONE 8 — HARDENRate limits + validation + CORS + audit + safe errorsMILESTONE 9 — VERIFYUnit + API + integration + security + golden pathMILESTONE 10 — PRESENTResettable demo + measured evidence + PPT + rehearsal

40. Project Definition of Done

Cyberwolf SIEM Hackathon MVP is DONE when an authenticated analyst can open a real dashboard, replay controlled telemetry, observe normalized events and evidence-backed alerts, see related findings correlate into a deterministic high-risk incident, open the incident to understand the evidence timeline and risk explanation, update investigation state under RBAC, and verify the action in audit history — from a reproducible repository with passing required tests and no known committed secrets.

41. Six-Document Handoff Set

Document

Role

CWS-PRD-001 — Product Requirements Document

WHAT and WHY

CWS-TRD-001 — Technical Requirements Document

HOW the system is engineered

CWS-AF-001 — Application Flow Specification

User and system journeys

CWS-UX-001 — UI/UX Design Brief

SOC experience

CWS-BE-001 — Backend & Data Schema

Backend contracts/evidence model

CWS-IP-001 — Implementation Plan

Build order, verification and delivery

Together these documents form the Cyberwolf SIEM development handoff package.