# CYBERWOLF SIEM — IDENTITY & SECURITY HARDENING SPECIFICATION

**Document Version**: 1.0  
**Date**: 31 July 2026  
**Module**: `M02.1 — Security Certification Patch`  
**Security Reference**: `CWS-PRD-001`, `CWS-TRD-001`, `CWS-AF-001`, `CWS-BE-001`  

---

## 1. Password Handling & Explicit Input Bounds

Cyberwolf SIEM uses direct `bcrypt` password hashing (`get_password_hash`, `verify_password`). Passwords are never silently truncated to 72 bytes. Input bounds are explicitly validated prior to hashing:

- **Minimum Length**: 12 characters (`len(password) >= 12`).
- **Maximum Size**: 72 bytes in UTF-8 representation (`len(password.encode('utf-8')) <= 72`).
- **Whitespace Bounds**: Passwords cannot be empty or whitespace-only (`not password or not password.strip()`).
- **Multibyte / Unicode Support**: Multibyte UTF-8 characters (e.g. emojis or non-Latin glyphs) are measured by byte length.
- **Secret Hygiene**: Rejected password inputs generate explicit validation errors (`HTTP 400 Bad Request`) without printing or logging plain text passwords.

---

## 2. JWT Security & Database-Authoritative State

- **Algorithm**: `HS256` signed using `settings.SECRET_KEY`.
- **Token Claims**: `sub` (username), `role` (`UserRole`), `exp` (UTC expiration timestamp), `type` ("access").
- **Database User State Authority**: Token validation does not rely solely on JWT payload claims. Every protected request checks the persisted `User` entity in PostgreSQL/SQLite. If a user account is set to `is_active = False` in the database, API requests are immediately rejected with `HTTP 400 Bad Request` ("Inactive user account"), even if the client presents an unexpired, cryptographically valid JWT.

---

## 3. Stateless Logout Semantics

- **Behavior**: `POST /api/v1/auth/logout` records a `USER_LOGOUT` audit log event (`AuditResult.SUCCESS`) and returns a standard success message instructing the client to clear local token storage.
- **Revocation Notice**: Cyberwolf SIEM hackathon MVP uses stateless JWT access tokens. Standard unexpired tokens are not server-revoked until expiration unless the user account is explicitly deactivated by an Administrator (`is_active = False`).

---

## 4. Role-Based Access Control (RBAC) Matrix

Server-side authorization is enforced by the reusable dependency `RequireRole(allowed_roles)`. Frontend control hiding is treated strictly as UX enhancement.

| User Role | `READ` (Events, Alerts, Incidents) | `INVESTIGATE` (Status Updates, Notes) | `ADMINISTER` (Users, Rules, System Settings) |
|---|---|---|---|
| **`VIEWER`** | 🟢 **PASS** (`200 OK`) | 🔴 **DENY** (`403 Forbidden`) | 🔴 **DENY** (`403 Forbidden`) |
| **`ANALYST`** | 🟢 **PASS** (`200 OK`) | 🟢 **PASS** (`200 OK`) | 🔴 **DENY** (`403 Forbidden`) |
| **`ADMIN`** | 🟢 **PASS** (`200 OK`) | 🟢 **PASS** (`200 OK`) | 🟢 **PASS** (`200 OK`) |

---

## 5. Rate Limiting Architecture

- **Implementation**: In-process rate limiting via `slowapi` (`Limiter(key_func=get_remote_address)`).
- **Enforcement**: `POST /api/v1/auth/login` is limited to `10 requests/minute`.
- **Exceeded Behavior**: Exceeding the rate limit returns `HTTP 429 Too Many Requests`.
- **Architectural Scope**: In-process rate limiting is tailored for single-instance hackathon deployments. Distributed multi-instance deployments would substitute Redis-backed rate limiters (`limits` with Redis backend).

---

## 6. Request ID Middleware & Audit Links

- **Middleware**: `RequestIDMiddleware` attached to FastAPI middleware stack.
- **Validation**: Incoming `X-Request-ID` headers are validated against regex `^[a-zA-Z0-9_\-]{1,128}$` to prevent header injection or memory exhaustion. Oversized or invalid headers are replaced with a newly generated UUID `str(uuid.uuid4())`.
- **Response Header**: All API responses output `X-Request-ID`.
- **Audit Association**: Authentication and user management audit logs record `request_id` for request-level traceability.

---

## 7. Admin Bootstrap CLI

Cyberwolf provides a CLI tool for bootstrapping the initial administrator account without hardcoded default passwords:

```bash
# Using environment variables
export ADMIN_USERNAME="admin"
export ADMIN_EMAIL="admin@cyberwolf.local"
export ADMIN_PASSWORD="SecureAdminPassword123!"
py -3.12 backend/app/bootstrap_admin.py

# Or via command line arguments
py -3.12 backend/app/bootstrap_admin.py --username admin --email admin@cyberwolf.local --password "SecureAdminPassword123!"
```

- Passwords passed to the bootstrap CLI are validated against strength rules (min 12 chars).
- Plaintext passwords are never logged or echoed to terminal output.

---

## 8. Audit Trail Secret Exclusion

Audit logging middleware and service layer explicitly exclude sensitive keys (`password`, `password_hash`, `access_token`, `Authorization`, `Cookie`, `secret`, `api_key`) from `AuditLog.audit_metadata`. Failed login attempts record `USER_LOGIN_FAILED` with generic failure reason (`"Invalid credentials"`).
