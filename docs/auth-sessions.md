# AG-64 — Signed, revocable user sessions

## Scope and design

AG-64 extends AG-63's persistent demo users and Argon2id authentication.
The session service is backend-only: AG-65 builds the Security Context and
AG-66 integrates the API/frontend. The existing scaffold is not authenticated
until that integration is complete.

A signed JWT with a server-side SQLite record is used instead of a stateless
JWT so logout can revoke a session immediately for subsequent validations.
Opaque tokens would also be viable; this design retains the JWT proposed
in Jira without custom cryptography or refresh tokens.

## Configuration

From the repository root:

```sh
python -m pip install -r requirements.txt
python -m backend.security.auth.bootstrap
```

Provision only fictional Alice/Bob accounts through the masked local bootstrap.
Use the same database as AG-63 (default `data/agentguard.db`, configurable
through `AGENTGUARD_DB_PATH`); coordinate the shared path with AG-37.
Keep databases and secrets outside version control.

Set `AGENTGUARD_JWT_SECRET` in the backend process environment. It must be
at least 32 UTF-8 bytes; choose a cryptographically random key, not a password
or predictable string. For a temporary local shell:

```sh
export AGENTGUARD_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

PowerShell equivalent:

```powershell
$env:AGENTGUARD_JWT_SECRET = python -c "import secrets; print(secrets.token_hex(32))"
```

These commands generate a fresh key without printing it to the terminal.
To preserve sessions across process restarts, securely provision the same key
again. The blank entry in `.env.example` is a template, not an automatic
environment loader. Never commit or log the actual key or bearer tokens.

## Service interface

```python
from backend.security.auth.sessions import SessionStore
from backend.security.auth.users import UserStore

sessions = SessionStore(UserStore())
sessions.initialize()
# Use sessions.login(username, password) with securely supplied credentials.
# Use sessions.validate(token) on each authenticated request.
# Use sessions.logout(token) to revoke the presented session.
```

- `initialize()`: idempotently creates users and sessions tables.
  Demo accounts are provisioned separately.
- `login(username, password)`: returns a signed token only for valid active
  users; invalid credentials return None. Persists the session ID, user ID,
  issuance and expiration.
- `validate(token)`: returns an immutable ValidatedSession (session_id,
  safe User projection, expires_at) or None for invalid, expired, unknown,
  revoked tokens or inactive users.
- `logout(token)`: True only when an unrevoked, unexpired matching session
  was revoked; invalid or repeated logout returns False. Other sessions are
  unaffected.

Storage/configuration failures propagate: callers must fail closed with a
sanitized service error, never fall back to a client-provided identity.

## Trust boundary and lifecycle

PyJWT 2.13.0 accepts only HS256 in this service. Required claims: iss
(agentguard), aud (agentguard-api), sub (canonical user ID), jti (256-bit
random session ID), iat and exp (integer UTC Unix timestamps). PyJWT validates
signature, algorithm, issuer, audience and time validity; the service checks
claim types and matches ID, user, issuance and expiry against SQLite.
The default lifetime is 1800 seconds (30 minutes); an explicit service TTL
must be an integer from 1 to 86400 seconds. No refresh tokens are issued.

The sessions table has a foreign key to users and stores no raw JWT. Logout
sets revoked_at. Validation joins the current user record and requires an
active user; role is resolved exclusively from SQLite. Extra role claims
do not grant rights. The safe user projection excludes passwords and hashes.
JWTs are signed, not encrypted: never include confidential data. The LLM
must never receive tokens or signing keys.

## Verification and limitations

```sh
python -m pytest tests/security/test_sessions.py -q
python -m pytest -q
```

Tests use temporary databases, synthetic passwords, generated keys and clock
substitution, without Ollama or real waits. Coverage includes valid users,
wrong credentials, missing/malformed tokens, altered signatures, wrong keys,
disallowed algorithms (none, HS384, HS512), missing/invalid claims, unknown
sessions, JWT and server expiration, inactive users, logout, unaffected
sibling sessions, persistence, ignored role claims and no stored raw JWT.

Revocation applies to subsequent validation; it cannot undo an action
already authorized. Re-enabling a user can restore an unexpired, unrevoked
session; permanent revocation on account lifecycle changes is future work.
Protect the host, database and signing key. TLS, browser storage and CSRF
protections are integration concerns for AG-66, as are safe error mapping and
protection of /api/chat and /api/simulate. Rate limiting, session cleanup
and key rotation remain outside AG-64. AG-65 must derive its immutable
context only from validated sessions, never client actor or role fields.

References: Jira AG-25, AG-63, AG-64, AG-65, AG-66; AGENTS.md project rules.
