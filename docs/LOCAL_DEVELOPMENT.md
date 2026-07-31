# Local development and verification

This prototype supports M00–M05 only. M06 and later modules are not part of
the runnable scope.

## Windows PowerShell

From the repository root (`E:\neonprojects`):

```powershell
# Backend dependencies and complete test suite
py -3.12 -m pip install -r backend/requirements.txt
py -3.12 -m pytest -q

# Frontend production build
Push-Location frontend
npm ci
npm run build
Pop-Location

# Local backend and health checks
$env:PYTHONPATH = "backend"
py -3.12 -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
# In another PowerShell window:
Invoke-RestMethod http://127.0.0.1:8000/
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health

# Docker and PostgreSQL, only when Docker Desktop's Linux engine is running
docker version
docker compose config
docker compose up -d db
docker compose ps
$env:PYTHONPATH = "backend"
py -3.12 -m alembic -c backend/alembic.ini upgrade head
py -3.12 -m alembic -c backend/alembic.ini current
```

For a full container runtime, use `docker compose up -d --build` only after
`docker version` reports both client and server information. A stopped or
unavailable Docker Desktop engine is an environment blocker, not a reason to
change the application architecture.

## Configuration safety

Copy `.env.example` to `.env` for local development. Development placeholders
are rejected when `ENVIRONMENT=production`; production requires non-empty,
non-placeholder `SECRET_KEY` and `POSTGRES_PASSWORD` values.

## Current verification limits

The ingestion idempotency set is process-local. It prevents duplicates only
within one backend process and resets on restart; it is not durable or
distributed idempotency. PostgreSQL migration and Docker golden-path checks
require a reachable Docker engine.
