# AG-65 — Immutable Security Context

AG-65 connects AG-63 persistent identities and AG-64 validated sessions
to AG-66 and AG-26. It changes no HTTP API, runner, tools, policy or dependencies.

## Contract

Import SecurityContext and resolve_security_context from
backend.security.auth.context. The backend owns and initializes SessionStore;
untrusted callers supply only a bearer token at the authentication boundary.

    context = resolve_security_context(sessions, token)
    if context is None:
        # Abort the request; do not execute tools.
        ...

The resolver calls SessionStore.validate(token), which verifies the JWT
and matching live SQLite session and active user. Its scalar fields are:

| Field | Source |
| --- | --- |
| user_id | User.id, persistent numeric SQLite identifier |
| username | User.username, canonical application identity |
| role | User.role, current server-owned role |
| session_id | ValidatedSession.session_id |

actor_id is a read-only alias for username. expires_at is intentionally
omitted: freshness comes from validation, not snapshot fields.
No raw JWT, password, hash, signing key or prompt-derived permission is
included. session_id is excluded from repr but not explicit serialization.
Never send the entire context to the LLM, logs or public HTTP responses.

## Trust boundary and lifecycle

    Untrusted token -> server-owned SessionStore.validate -> SecurityContext
                          | invalid -> None -> abort
                          | storage error -> exception -> abort
    SecurityContext -> trusted backend orchestration / authorization

Client JSON, prompts, documents and model tool arguments cannot supply or
override identity, role, session or the store. Frozen dataclasses with slots
prevent ordinary mutation, not arbitrary Python code execution. A manually
constructed ValidatedSession or SecurityContext is not authentication proof.
The trusted store, protected signing key, database and controlled call path
establish provenance. Never deserialize a client object into a trusted context.

Invalid, missing, expired, unknown, revoked and inactive-user sessions
return None. Storage/configuration errors propagate. The HTTP caller must
abort on either outcome and never fall back to client identity. Map service
errors to sanitized responses.

Contexts are request-scoped snapshots, not bearer credentials. Resolve a
fresh context for each authenticated request; do not cache across requests.
Revocation, role changes or account deactivation do not mutate an already
resolved context. Revalidation before sensitive or delayed actions is a
proposed follow-up, not implemented here, and must consider the race between
validation and execution.

## Handoff

AG-66 must obtain tokens using the agreed HTTP transport, use the configured
server-owned store and resolve before /api/chat or /api/simulate performs
actions. Reject untrusted identity fields and keep credentials out of model
messages. Coordinate API/runner/executor changes with their owners.

AG-26 must use context.role and context.actor_id from the trusted call path;
legacy ACTORS must not remain a competing authorization source.
Compatibility tests cover only the fixed demo roles, not authorization
after a role change. AG-27 must ensure all execution paths use trusted
context. AG-67 must cover HTTP identity spoofing, prompt-driven calls,
revocation and regression without relying on Ollama for deterministic tests.

AG-65 alone does NOT authenticate existing endpoints. No RBAC matrix,
HTTP endpoints, frontend, approval flow or monitoring extensions are added.

## Verification

    python -m pytest tests/security/test_security_context.py -q
    python -m pytest -q

Tests use temporary SQLite, fictional passwords and generated keys.
Coverage includes both identities, immutability, minimal projection,
invalid and forged credentials, extra claims, current server role, expiry,
revocation, inactive users, storage failure and legacy actor compatibility.
Fabricated typed objects are rejected as credentials. No real waits or
Ollama are required.

References: Jira AG-25, AG-63, AG-64, AG-65, AG-66, AG-67, AG-26;
docs/auth-sessions.md; project AGENTS.md.
