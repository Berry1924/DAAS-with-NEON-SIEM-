# NEON SIEM

> **Security Information & Event Management Platform**
> *Hackathon MVP — Release Candidate*

[![Architecture](https://img.shields.io/badge/Architecture-Secure_Modular_Monolith-blue.svg)](#architecture)
[![Backend](https://img.shields.io/badge/Backend-FastAPI_%7C_Python_3.12-009688.svg)](file:///e:/neonprojects/backend)
[![Database](https://img.shields.io/badge/Database-PostgreSQL_15_%7C_SQLAlchemy_2.0-336791.svg)](#database)
[![Frontend](https://img.shields.io/badge/Frontend-React_18_%7C_TypeScript_%7C_Vite-61DAFB.svg)](file:///e:/neonprojects/frontend)
[![Tests](https://img.shields.io/badge/Tests-211_Passing-success.svg)](#testing)

---

## 1. Overview

NEON SIEM is a modern cybersecurity monitoring and incident-analysis platform. It collects security telemetry from heterogeneous log sources, normalizes raw logs into a canonical schema, evaluates declarative detection rules, correlates multi-alert attack sequences, calculates explainable risk scores (0–100), and presents actionable incidents to SOC analysts through a dark-themed operations console.

### Key Capabilities

- **Telemetry Ingestion** — Authenticated REST API with rate limiting, payload validation, and batch support
- **Detection Engine** — Four declarative JSON rules evaluated against windowed thresholds
- **Correlation Engine** — Entity-based multi-alert attack sequence identification
- **Risk Engine** — Deterministic 0–100 scoring with full factor breakdown
- **Incident Management** — Lifecycle workflow (NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED)
- **Audit Trail** — Append-only security action logging with credential redaction
- **SOC Dashboard** — Real-time PostgreSQL-backed metrics and event trend visualization
- **Golden Path Demo** — Deterministic 17-event attack replay through the complete pipeline

---

## 2. Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                    NEON SOC Frontend                          │
│         React 18 + TypeScript + Vite + Lucide Icons          │
└──────────────────────────┬───────────────────────────────────┘
                           │ HTTPS / REST
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                     FastAPI Backend                           │
│                                                              │
│  ┌───────────────────┐  ┌──────────────────────────────────┐ │
│  │  API Routers       │  │  Security Analytics Engine       │ │
│  │  /auth /events     │  │  • Parser & Normalizer           │ │
│  │  /alerts /incidents│  │  • Declarative Detection Rules   │ │
│  │  /dashboard /audit │  │  • Entity Correlation Engine     │ │
│  │  /demo             │  │  • Deterministic Risk Calculator │ │
│  └─────────┬─────────┘  └──────────────────────────────────┘ │
│            ▼                                                  │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │          Repositories & SQLAlchemy 2.0 ORM               │ │
│  └──────────────────────────┬───────────────────────────────┘ │
└─────────────────────────────┼────────────────────────────────┘
                              │ SQL (Parameterized Queries)
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                    PostgreSQL 15 Database                     │
│  users, events, detection_rules, alerts, alert_events,       │
│  correlation_groups, incidents, incident_alerts,              │
│  incident_timeline, incident_notes, audit_logs               │
└──────────────────────────────────────────────────────────────┘

Demo Generator ──► Existing Ingestion Pipeline
```

---

## 3. Technology Stack

| Layer | Technology |
|-------|-----------|
| **Language** | Python 3.12 |
| **Backend Framework** | FastAPI |
| **ORM** | SQLAlchemy 2.0 |
| **Database** | PostgreSQL 15 |
| **Migrations** | Alembic |
| **Authentication** | JWT (python-jose) + bcrypt |
| **Frontend** | React 18 + TypeScript |
| **Build Tool** | Vite |
| **Testing** | pytest |
| **Containerization** | Docker Compose |

---

## 4. Security Data Pipeline

```text
[ Telemetry Sources ]
        │
        ▼
[ 1. Ingestion API ] → Rate limits, payload validation
        │
        ▼
[ 2. Parsing ] → Source-specific format extraction
        │
        ▼
[ 3. Normalization ] → Canonical schema, UTC timestamps
        │
        ▼
[ 4. Event Storage ] → Immutable PostgreSQL evidence store
        │
        ▼
[ 5. Detection Engine ] → 4 declarative rules (CW-NET/AUTH/LOGIN/PRIV)
        │
        ▼
[ 6. Alert Engine ] → Evidence-backed alerts with event linking
        │
        ▼
[ 7. Correlation Engine ] → Entity/time-bounded sequence matching
        │
        ▼
[ 8. Risk Engine ] → Deterministic 0-100 scoring
        │
        ▼
[ 9. Incident Manager ] → Lifecycle, timeline, evidence chain
        │
        ▼
[ 10. Audit Trail ] → Append-only action logging
        │
        ▼
[ 11. SOC Dashboard ] → Real-time metrics from PostgreSQL
```

---

## 5. Module Status

| Module | Name | Status |
|--------|------|--------|
| M00 | Foundation & Runtime | ✅ COMPLETE |
| M01 | Database & Persistence | ✅ COMPLETE |
| M02 | Authentication & RBAC | ✅ COMPLETE |
| M03 | Telemetry Ingestion | ✅ COMPLETE |
| M04 | Parsing & Normalization | ✅ COMPLETE |
| M05 | Event Storage & Explorer | ✅ COMPLETE |
| M06 | Live Telemetry Collector | ✅ COMPLETE |
| M07 | Detection Engine | ✅ COMPLETE |
| M08 | Correlation Engine | ✅ COMPLETE |
| M09 | Risk Engine | ✅ COMPLETE |
| M10 | Incident Management | ✅ COMPLETE |
| M11 | Audit Service | ✅ COMPLETE |
| M12 | SOC Frontend | ✅ COMPLETE |
| M13 | Dashboard API | ✅ COMPLETE |
| M14 | Demo Generator | ✅ COMPLETE |
| M15 | Integration & Release | ✅ COMPLETE |

---

## 6. Installation & Quickstart

### Prerequisites

- Python 3.12+
- Node.js 18+ & npm
- PostgreSQL 15+ (or Docker)

### Environment Configuration

```bash
cp .env.example .env
# Edit .env and replace placeholder values for production
```

### Backend Setup

```bash
# Install Python dependencies
py -3.12 -m pip install -r backend/requirements.txt

# Run database migrations
py -3.12 -m alembic upgrade head

# Start FastAPI development server
py -3.12 -m uvicorn backend.app.main:app --reload --port 8000
```

- API Documentation (Swagger): `http://localhost:8000/api/v1/docs`
- Health Endpoint: `http://localhost:8000/health`

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

- SOC Console: `http://localhost:5173`

### Docker Compose

```bash
docker compose up --build
```

---

## 7. Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROJECT_NAME` | `NEON SIEM` | Application name |
| `ENVIRONMENT` | `development` | `development` or `production` |
| `SECRET_KEY` | *placeholder* | JWT signing key (**must change for production**) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` | JWT token lifetime |
| `DEMO_MODE` | `true` | Enable/disable demo replay endpoint |
| `POSTGRES_USER` | `cyberwolf` | Database username |
| `POSTGRES_PASSWORD` | *placeholder* | Database password (**must change for production**) |
| `POSTGRES_DB` | `cyberwolf_db` | Database name |
| `POSTGRES_SERVER` | `localhost` | Database hostname |
| `POSTGRES_PORT` | `5432` | Database port |
| `DATABASE_URL` | *auto-generated* | Full PostgreSQL connection string (overrides individual fields) |
| `ALLOWED_ORIGINS` | `["http://localhost:5173"]` | CORS allowed origins (JSON array) |
| `RATE_LIMIT_LOGIN` | `10/minute` | Login rate limit |
| `RATE_LIMIT_INGEST` | `500/minute` | Telemetry ingestion rate limit |
| `MAX_BATCH_SIZE` | `100` | Maximum batch ingestion size |
| `MAX_REQUEST_BODY_BYTES` | `1048576` | Maximum request payload (1 MiB) |

> **Production Safety**: The application refuses to start with placeholder credentials when `ENVIRONMENT=production`.

---

## 8. Golden Path Demo

The Golden Path is a deterministic 17-event attack scenario that exercises the complete NEON pipeline:

```text
Stage 1: Port Scan (10 events)     → Triggers CW-NET-001
Stage 2: Brute Force (5 events)    → Triggers CW-AUTH-001
Stage 3: Suspicious Login (1 event) → Triggers CW-LOGIN-001
Stage 4: Privilege Escalation (1 event) → Triggers CW-PRIV-001
         ↓
    Correlation: Potential Host Compromise (is_golden_sequence = true)
         ↓
    Risk Score: 100/100 CRITICAL
         ↓
    Incident: NEON-INC-000001
```

### Run via CLI

```bash
python -m security_engine.demo golden-path
# or
python scripts/demo.py golden-path
```

### Run via API (ADMIN only)

```bash
curl -X POST http://localhost:8000/api/v1/demo/replay \
  -H "Authorization: Bearer <admin_token>"
```

---

## 9. Detection Rules

| Rule ID | Name | Trigger | Severity |
|---------|------|---------|----------|
| `CW-NET-001` | Port Scan Activity | ≥10 connections to distinct IPs in 120s | MEDIUM |
| `CW-AUTH-001` | Brute Force Authentication | ≥5 failed logins from same IP in 300s | HIGH |
| `CW-LOGIN-001` | Suspicious Login After Failures | Successful login after ≥3 failures in 600s | HIGH |
| `CW-PRIV-001` | Privilege Escalation | sudo/su activity after successful auth in 300s | CRITICAL |

Rules are declarative JSON files in `rules/`. No arbitrary code execution (`eval`/`exec`) is permitted.

---

## 10. API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | — | Health check with database probe |
| `POST` | `/api/v1/auth/login` | — | Authenticate, returns JWT |
| `GET` | `/api/v1/auth/me` | Any | Current user profile |
| `POST` | `/api/v1/auth/logout` | Any | Logout (audit only) |
| `POST` | `/api/v1/events` | Analyst+ | Single telemetry ingestion |
| `POST` | `/api/v1/events/batch` | Analyst+ | Batch telemetry ingestion |
| `GET` | `/api/v1/events` | Any | List/filter events |
| `GET` | `/api/v1/events/{id}` | Any | Event detail |
| `GET` | `/api/v1/events/stats` | Any | Event statistics |
| `GET` | `/api/v1/alerts` | Any | List/filter alerts |
| `GET` | `/api/v1/alerts/{id}` | Any | Alert detail with evidence |
| `PATCH` | `/api/v1/alerts/{id}` | Analyst+ | Update alert status |
| `GET` | `/api/v1/correlations` | Any | List correlation groups |
| `GET` | `/api/v1/correlations/{id}` | Any | Correlation detail |
| `GET` | `/api/v1/incidents` | Any | Incident queue |
| `GET` | `/api/v1/incidents/{id}` | Any | Incident detail |
| `PATCH` | `/api/v1/incidents/{id}/status` | Analyst+ | Status transition |
| `PATCH` | `/api/v1/incidents/{id}/assign` | Analyst+ | Assign analyst |
| `POST` | `/api/v1/incidents/{id}/notes` | Analyst+ | Add investigation note |
| `GET` | `/api/v1/dashboard/summary` | Any | Dashboard metrics |
| `GET` | `/api/v1/audit` | Admin | Audit trail |
| `POST` | `/api/v1/demo/replay` | Admin | Demo replay (DEMO_MODE) |
| `GET` | `/api/v1/users` | Admin | User administration |
| `POST` | `/api/v1/users` | Admin | Create user |

---

## 11. RBAC Matrix

| Capability | VIEWER | ANALYST | ADMIN |
|-----------|--------|---------|-------|
| Dashboard read | ✅ | ✅ | ✅ |
| Incident read | ✅ | ✅ | ✅ |
| Alert read | ✅ | ✅ | ✅ |
| Correlation read | ✅ | ✅ | ✅ |
| Event read | ✅ | ✅ | ✅ |
| Incident status change | ❌ | ✅ | ✅ |
| Incident assignment | ❌ | ✅ | ✅ |
| Investigation notes | ❌ | ✅ | ✅ |
| Telemetry ingestion | ❌ | ✅ | ✅ |
| Audit trail access | ❌ | ❌ | ✅ |
| User administration | ❌ | ❌ | ✅ |
| Demo replay | ❌ | ❌ | ✅ |

All authorization is enforced server-side.

---

## 12. Security Model

- **Authentication**: JWT tokens signed with configurable SECRET_KEY (HS256)
- **Password Hashing**: bcrypt with salt, minimum 12 characters
- **RBAC**: Server-side role enforcement on every endpoint
- **CORS**: Explicit allowed origins (not wildcard with credentials)
- **Rate Limiting**: Configurable per-endpoint limits (SlowAPI)
- **Input Validation**: Pydantic v2 schema validation, payload size limits
- **SQL Safety**: SQLAlchemy ORM with parameterized queries
- **Audit Redaction**: `password`, `token`, `secret`, `authorization`, `cookie`, `private_key` and similar keys automatically redacted
- **Secret Hygiene**: `.env` gitignored, production startup refuses placeholder credentials
- **Demo Safety**: `/api/v1/demo/replay` requires ADMIN role and DEMO_MODE=true
- **Detection Safety**: Rules are declarative JSON, no eval/exec

---

## 13. Testing

```bash
py -3.12 -m pytest tests/ -v
```

---

## 14. Deployment

### Production Checklist

- [ ] Set `ENVIRONMENT=production`
- [ ] Set `DEMO_MODE=false`
- [ ] Generate strong `SECRET_KEY` (e.g., `openssl rand -hex 32`)
- [ ] Set strong `POSTGRES_PASSWORD`
- [ ] Configure `ALLOWED_ORIGINS` with production frontend URL
- [ ] Run `alembic upgrade head` on production database
- [ ] Deploy frontend with `npm run build` and serve `dist/`
- [ ] Configure HTTPS via reverse proxy (nginx, Caddy, etc.)
- [ ] Verify health endpoint: `GET /health` returns `"database": "connected"`

### Database Management

```bash
# Run migrations
py -3.12 -m alembic upgrade head

# Backup
pg_dump -U cyberwolf cyberwolf_db > backup.sql

# Restore
psql -U cyberwolf cyberwolf_db < backup.sql
```

---

## 15. Hackathon Demo Walkthrough

1. Start backend: `py -3.12 -m uvicorn backend.app.main:app --port 8000`
2. Start frontend: `cd frontend && npm run dev`
3. Open SOC Console: `http://localhost:5173`
4. Login as ADMIN
5. Run Golden Path: `python -m security_engine.demo golden-path`
6. Observe Dashboard: 17 events, 4 alerts, 1 CRITICAL incident
7. Open incident: **Potential Host Compromise**
8. Review risk factors (100/100 CRITICAL)
9. Inspect correlation sequence
10. Review evidence events
11. Add investigation note
12. Change status: ACKNOWLEDGED → INVESTIGATING → RESOLVED
13. View audit trail (ADMIN only)

---

## 16. Known Limitations

1. **Process-Local Idempotency**: Event deduplication uses source_event_id but is not distributed.
2. **Stateless JWT**: Tokens remain valid until expiration after logout.
3. **SQLite Tests**: Integration tests use in-memory SQLite.
4. **Single-Node**: Current architecture is a single-process monolith.
5. **No Real-Time Push**: Dashboard requires manual refresh.
6. **Collector Offsets**: Process-local file offsets, not distributed state.

---

**NEON SIEM — Built for the Hackathon**
