# Local development and verification

This prototype supports M00–M05 only. M06 and later modules are not part of
the runnable scope.

## Windows PowerShell

From the repository root (`E:\neonprojects`):

```powershell
# Start Docker Desktop, then wait until both client and server are reported.
Start-Process "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
docker version

# Build and start the complete local stack (does not delete PostgreSQL data).
docker compose config
docker compose build
docker compose up -d
docker compose ps

# Apply and inspect the authoritative Alembic migration inside the backend
# container, which uses the same PostgreSQL database as Compose.
docker compose exec -T backend python -m alembic -c backend/alembic.ini upgrade head
docker compose exec -T backend python -m alembic -c backend/alembic.ini current

# Bootstrap a local administrator. Supply a 12+ character password interactively;
# it is not committed or printed by the bootstrap command.
$env:ADMIN_USERNAME = "admin"
$securePassword = Read-Host "Administrator password" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
try { $env:ADMIN_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
docker compose exec -T -e ADMIN_USERNAME=$env:ADMIN_USERNAME -e ADMIN_PASSWORD=$env:ADMIN_PASSWORD backend python backend/app/bootstrap_admin.py
Remove-Item Env:ADMIN_PASSWORD

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

# Stop containers while preserving PostgreSQL data.
docker compose down
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

The M00–M05 frontend is a real API client: it displays backend health, logs in
with a locally bootstrapped account, submits synthetic telemetry, and displays
persisted event list/detail data through the M05 API. Its browser calls use
relative `/api/...` paths; Vite proxies those paths to `backend:8000` only
inside Compose, so no Docker-internal hostname is exposed to the browser.

The ingestion idempotency set is process-local. It prevents duplicates only
within one backend process and resets on restart; it is not durable or
distributed idempotency. PostgreSQL migration and Docker golden-path checks
require a reachable Docker engine.

The frontend currently uses the newest Vite 5 release compatible with Node 18.
`npm audit` still reports Vite/esbuild development-server advisories; npm
identifies Vite 8.2.0 as the remediation, which requires Node 20.19+ or
22.12+. Upgrade Node before moving to that release; do not use `npm audit fix
--force` on Node 18.
