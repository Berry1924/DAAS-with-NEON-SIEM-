# CYBERWOLF SIEM

> **Intelligent Security Information & Event Management Platform**  
> *Hackathon MVP Specification & Implementation*

[![Architecture](https://img.shields.io/badge/Architecture-Secure_Modular_Monolith-blue.svg)](#system-architecture)
[![Backend](https://img.shields.io/badge/Backend-FastAPI_%7C_Python_3.12-009688.svg)](file:///e:/neonprojects/backend)
[![Database](https://img.shields.io/badge/Database-PostgreSQL_15_%7C_SQLAlchemy_2.0-336791.svg)](file:///e:/neonprojects/docs/DATABASE_ARCHITECTURE.md)
[![Frontend](https://img.shields.io/badge/Frontend-React_18_%7C_TypeScript_%7C_Vite-61DAFB.svg)](file:///e:/neonprojects/frontend)
[![Status](https://img.shields.io/badge/Status-M01_Database_Verified-success.svg)](file:///e:/neonprojects/docs/IMPLEMENTATION_STATUS.md)

---

## 1. Executive Summary & Mission

Cyberwolf SIEM is a modern cybersecurity monitoring and incident-analysis platform designed to collect security telemetry from heterogeneous log sources, normalize raw logs into a common canonical schema, evaluate rule-based detections, correlate related findings across time and entities, calculate explainable risk scores (0–100), and present actionable incidents to SOC analysts through a dark-themed monitoring console.

---

## 2. Core Security Data Workflow

The complete end-to-end security analytics pipeline operates in 12 deterministic stages:

```text
  [ Telemetry Sources ] (Linux Auth, Syslog, Synthetic Replay)
            │
            ▼
  [ 01. Ingestion API ] (POST /api/v1/events, payload size & rate limits)
            │
            ▼
  [ 02. Validation ] (Envelope checks & quarantine)
            │
            ▼
  [ 03. Parsing ] (Source-specific format extraction)
            │
            ▼
  [ 04. Normalization ] (Coercion to Canonical Cyberwolf Event schema & UTC timestamps)
            │
            ▼
  [ 05. Event Storage ] (Immutable PostgreSQL event evidence store)
            │
            ▼
  [ 06. Detection Engine ] (Declarative rule predicate evaluation & windowed thresholds)
            │
            ▼
  [ 07. Alert Engine ] (Evidence-backed alert generation & alert_events linking)
            │
            ▼
  [ 08. Correlation Engine ] (Entity & time-bounded multi-alert sequence matching)
            │
            ▼
  [ 09. Risk Engine ] (Deterministic 0-100 scoring & factor explanation)
            │
            ▼
  [ 10. Incident Manager ] (Creation of Potential Host Compromise incidents & timeline)
            │
            ▼
  [ 11. SOC Investigation ] (Analyst queue, timeline review, status transitions)
            │
            ▼
  [ 12. Audit Trail ] (Append-only security action audit logging)
```

### The Core Evidence Invariant

$$\text{INCIDENT} \longrightarrow \text{ALERT} \longrightarrow \text{EVENT}$$

Every security conclusion displayed on the SOC dashboard must remain fully traceable to underlying raw evidence:

```text
Incident (CW-INC-0042: Potential Host Compromise)
   │
   └──► Contributing Alert (Brute Force Authentication Failure)
           │
           └──► Supporting Raw Event (Failed password for root from 192.168.1.100)
```

---

## 3. System Architecture

Cyberwolf SIEM is engineered as a **Secure Modular Monolith**:

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                         REACT SOC FRONTEND                             │
 │   (React 18 + TypeScript + Vite + Tailwind CSS + Lucide Icons)          │
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    │ HTTP / REST / WebSocket
                                    ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                          FASTAPI BACKEND                               │
 │                                                                        │
 │   ┌──────────────────────┐  ┌──────────────────────────────────────┐   │
 │   │  API & Auth Routers  │  │        Security Analytics Engine      │   │
 │   │  - /auth, /events    │  │  - Parsers & Normalizer              │   │
 │   │  - /alerts, /incidents│  │  - Declarative Detection Rules       │   │
 │   │  - /dashboard, /audit│  │  - Entity Correlation Engine         │   │
 │   └──────────┬───────────┘  │  - Deterministic Risk Calculator     │   │
 │              │              └──────────────────────────────────────┘   │
 │              ▼                                                         │
 │   ┌────────────────────────────────────────────────────────────────┐   │
 │   │               Repositories & SQLAlchemy 2.0 ORM                │   │
 │   └──────────────────────────────┬─────────────────────────────────┘   │
 └──────────────────────────────────┼─────────────────────────────────────┘
                                    │ SQL (Parameterized Queries)
                                    ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                        POSTGRESQL 15 DATABASE                          │
 │  (users, assets, events, detection_rules, alerts, alert_events,        │
 │   incidents, incident_alerts, incident_timeline, incident_notes, audit)│
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Implementation Status Roadmap (M00 - M18)

| Module ID | Module Name | Status | Priority | Deliverable / Verification |
|---|---|---|---|---|
| **M00** | Foundation & Runtime | `VERIFIED` | P0 | Directory layout, Pydantic settings, health APIs (`3/3 tests passed`). |
| **M01** | Database & Persistence | `VERIFIED` | P0 | 11 PostgreSQL tables, Alembic migrations, FK delete policy (`10/10 tests passed`). |
| **M02** | Authentication & RBAC | `NOT_STARTED` | P0 | JWT auth, bcrypt hashing, `ADMIN`, `ANALYST`, `VIEWER` roles. |
| **M03** | Telemetry Ingestion | `NOT_STARTED` | P0 | Single & batch event REST ingestion with payload limits. |
| **M04** | Parsing & Normalization | `NOT_STARTED` | P0 | Parser registry & canonical normalization engine. |
| **M05** | Event Storage & Explorer | `NOT_STARTED` | P0 | Event query filters & paginated search repository. |
| **M06** | Detection Engine | `NOT_STARTED` | P0 | Declarative rule evaluator & threshold window state. |
| **M07** | Alert Management | `NOT_STARTED` | P0 | Alert lifecycle management & `alert_events` linking. |
| **M08** | Correlation Engine | `NOT_STARTED` | P0 | Entity/time correlation grouping multi-alert attacks. |
| **M09** | Risk Engine | `NOT_STARTED` | P0 | Deterministic 0-100 scoring & factor breakdown. |
| **M10** | Incident Management | `NOT_STARTED` | P0 | Incident queue, evidence timeline, and notes. |
| **M11** | Audit Logging | `NOT_STARTED` | P0 | Immutable append-only audit trail service. |
| **M12** | SOC UI Foundation | `NOT_STARTED` | P0 | React SOC dark console design system & AppShell. |
| **M13** | SOC Dashboard | `NOT_STARTED` | P0 | Real-time SOC dashboard metrics & incident queue UI. |
| **M14** | Demo Generator | `NOT_STARTED` | P0 | Deterministic synthetic golden telemetry replayer. |
| **M15** | Golden Path Integration | `NOT_STARTED` | P0 | End-to-end integration test verifying full pipeline. |
| **M16** | Security Hardening | `NOT_STARTED` | P0 | Rate limits, CORS restrictions, input bounds, XSS escaping. |
| **M17** | Full Verification | `NOT_STARTED` | P0 | Consolidated automated test suite (`pytest`). |
| **M18** | Hackathon Release | `NOT_STARTED` | P0 | Single-command Docker Compose production setup. |

For detailed module audit breakdown, see [IMPLEMENTATION_STATUS.md](file:///e:/neonprojects/docs/IMPLEMENTATION_STATUS.md).

---

## 5. Database Schema & Evidence Policy

Complete database documentation is available at [DATABASE_ARCHITECTURE.md](file:///e:/neonprojects/docs/DATABASE_ARCHITECTURE.md).

### Implemented Tables
- `users`: Authenticated identities and RBAC roles (`ADMIN`, `ANALYST`, `VIEWER`).
- `assets`: Monitored target hosts and infrastructure nodes.
- `events`: Immutable normalized security telemetry evidence layer.
- `detection_rules`: Declarative detection rule specifications (e.g. `CW-AUTH-001`).
- `alerts`: Rule-triggered alerts linked to primary events.
- `alert_events`: Junction table connecting alerts to all supporting events.
- `incidents`: Correlated security incidents (`CW-INC-0042`).
- `incident_alerts`: Junction table connecting incidents to contributing alerts.
- `incident_timeline`: Chronological evidence entries (`EVENT`, `ALERT`, `STATUS`, `NOTE`).
- `incident_notes`: Analyst investigation notes.
- `audit_logs`: Operational action audit log (strictly filters secrets/passwords).

### Foreign-Key Deletion & Evidence Protection Policy

| Target Table | Referencing Table | FK Behavior | Rationale |
|---|---|---|---|
| `events` | `alert_events` | `ON DELETE RESTRICT` | **Raw security events cannot be deleted** while referenced by active alerts. |
| `alerts` | `incident_alerts` | `ON DELETE RESTRICT` | Alerts referenced by active incidents cannot be deleted. |
| `incidents` | `incident_alerts` | `ON DELETE CASCADE` | Deleting an incident removes junction rows only, preserving alerts and events. |
| `assets` | `events` | `ON DELETE SET NULL` | Removing an asset node retains historical telemetry evidence. |

---

## 6. Quickstart & Local Development Setup

### Prerequisites
- Python 3.12+
- Node.js 18+ & npm
- Docker & Docker Compose (optional for local non-containerized dev)

### Environment Configuration
Copy the environment template:
```bash
cp .env.example .env
```

### Running Backend Locally
```bash
# Install Python dependencies
py -3.12 -m pip install -r backend/requirements.txt

# Start FastAPI development server
py -3.12 -m uvicorn backend.app.main:app --reload --port 8000
```
- API Documentation (Swagger): `http://localhost:8000/api/v1/docs`
- Health Endpoint: `http://localhost:8000/health`

### Running Frontend Locally
```bash
cd frontend
npm install
npm run dev
```
- SOC Console UI: `http://localhost:5173`

### Running via Docker Compose
```bash
docker compose up --build
```

---

## 7. Automated Testing & Verification

Run the consolidated `pytest` test suite:

```bash
py -3.12 -m pytest tests/test_database.py tests/test_health.py -v
```

Expected Output:
```text
============================= 10 passed in 0.97s ==============================
```

For complete test case documentation, catalog, and security invariants, see [TEST_SUITE_SPECIFICATION.md](file:///e:/neonprojects/docs/TEST_SUITE_SPECIFICATION.md).

---

## 8. Authoritative Specifications

The repository contains six authoritative engineering specification documents in [docs/specs/](file:///e:/neonprojects/docs/specs/):

1. **`CWS-PRD-001.md`** — Product Requirements Document
2. **`CWS-TRD-001.md`** — Technical Requirements Document
3. **`CWS-AF-001.md`** — Application Flow Specification
4. **`CWS-UX-001.md`** — UI/UX Design Brief
5. **`CWS-BE-001.md`** — Backend & Data Schema Specification
6. **`CWS-IP-001.md`** — Implementation Plan

---

## 9. Security & Governance

- **SEC-01 (Secret Hygiene)**: `.env` is explicitly gitignored; zero committed secrets.
- **SEC-02 (Server Authorization)**: All authorization checks are enforced server-side.
- **SEC-04 (Rule Execution Safety)**: Detection rules use safe declarative JSON schemas; arbitrary code execution (`eval`/`exec`) is strictly prohibited.
- **SEC-07 (Password Hash Exclusion)**: `password_hash` is write-only for database storage and strictly excluded from API response schemas (`UserRead`).

---

**Cyberwolf SIEM — Cyberwolf Engineering Team**
