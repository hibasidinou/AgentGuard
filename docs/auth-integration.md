# AG-66 — Authenticated FastAPI and React integration

## Scope and traceability
AG-66 integrates the persistent users (AG-63), signed revocable sessions (AG-64) and immutable Security Context (AG-65) into the existing scaffold. It contributes to AG-25 on `AG-25-backend-user-sessions`. It does not implement the complete RBAC matrix (AG-26), final gateway (AG-27), strict tool schemas (AG-30), approval or persistent monitoring. AG-67 owns final parent verification and PR preparation.

Reference base: AG-65 commit `bb33a90a39c34350b6cb2f29b7baec7e887fc11f`. See [sessions](auth-sessions.md), [context](security-context.md), [architecture](architecture.md) and [Jira AG-66](https://mounirmerghich004.atlassian.net/browse/AG-66). Earlier AG-64/65 documents describe their historical scope; the current integration supersedes their statements about the scaffold not yet being authenticated or using `ACTORS`.

## Design decision
Before: `actor_id` came from client JSON and the policy looked up a static role. A caller could choose Bob without proving identity. After: FastAPI's lifespan initializes a server-owned SessionStore; user/password login creates a signed JWT and SQLite session. Every protected request validates the token and matching active session/user, creates an immutable context, and carries it separately to runner, executor and policy. There is no legacy identity fallback.

Bearer JWT + SQLite uses the existing AG-64 design. A stateless JWT could not provide immediate server-side revocation; opaque tokens were a viable alternative but would change that contract. An HttpOnly cookie can reduce direct JavaScript access to tokens but introduces ambient credentials and requires CSRF design. The agreed local prototype uses memory-only bearer tokens instead; no cookies or refresh tokens are issued. Reloading requires login. These are trade-offs, not production security claims.

## Setup and API contract
Follow the root README for provisioning and process environment. The signing key must be random and at least 32 UTF-8 bytes. No real credentials belong in code, examples, test output, URLs or version control. The default TTL is 1800 seconds (no refresh). JWT claims/signature and SQLite validation are documented in AG-64. `get_bearer_token` rejects duplicate/ambiguous headers and malformed/oversize tokens. Startup fails if configuration, provisioning or storage is invalid; an inactive existing user cannot authenticate.

All URLs below use local loopback. JSON examples are illustrative; replace placeholders at runtime, not in tracked files. No token is accepted from query parameters or cookies. Use FastAPI Swagger's Bearer authorization or a local HTTP client configured without credential logging.

| Method/path | Request | Success response |
| --- | --- | --- |
| POST `/api/auth/login` | JSON `{"username":"alice","password":"<provisioned password>"}` | 200 `{"access_token":"<JWT>","token_type":"bearer","expires_in":1800}` |
| GET `/api/auth/me` | Bearer, no body | 200 `{"username":"alice","role":"intern"}` |
| POST `/api/auth/logout` | Bearer, no body required | 204 (empty) |
| POST `/api/chat` | Bearer + JSON `{"prompt":"Summarize the public report"}` | 200 `{"answer":"...","actions":[...]}` |
| POST `/api/simulate` | Bearer + JSON `{"tool":"read_document","arguments":{"document_id":"private-budget"}}` | 200 tool decision/result (see below) |
| GET `/api/health` | Public | Existing status object |
| GET `/api/events` | Public (unchanged; dashboard sends bearer but server does not require it) | Existing global events and alerts |

Example authenticated simulation (not an actual credential):

```http
POST /api/simulate HTTP/1.1
Host: localhost:8000
Authorization: Bearer <JWT from login>
Content-Type: application/json

{"tool":"read_document","arguments":{"document_id":"private-budget"}}
```

With Alice, HTTP 200 with `{"ok":false,"error":"Insufficient clearance for restricted document"}`. With Bob, HTTP 200 with `ok:true`, `document_id` and fictional `content`. HTTP 200 is a successfully processed simulation, not a grant of access. `list_documents` filters using the current context role; `request_update` always denies in this MVP. Chat may return denied tool actions within its response.

| Failure | Mapping |
| --- | --- |
| Invalid credentials | 401 generic `Invalid credentials` |
| Missing, forged, expired, revoked, unknown or inactive-user session | 401 generic `Invalid or expired session` + `WWW-Authenticate: Bearer` |
| Strict schema violation, extra identity field, malformed request | 422 generic `Invalid request` (no raw input); validation may occur before auth for malformed JSON |
| Auth store missing/unavailable | 503 generic `Authentication service unavailable` |
| Ollama connection/timeout | 503 |
| Ollama HTTP status failure | 502 |
| Business-level denial | 200 with `ok:false` in tool result; 403 is reserved for future endpoint-level authorization |

Sensitive successful and expected error responses carry `Cache-Control: no-store`. `/api/events` remains unchanged. Unexpected failures are not a complete error-hardening solution; do not enable debug or request/header/body logging with real credentials.

## Internal contracts and role source
`backend/security/auth/http.py` defines `initialize_auth`, `get_session_store`, `get_bearer_token`, `require_security_context`, `AuthenticatedContext`, and sanitized validation errors. `routes.py` provides the auth router with strict login schema and explicit minimal response models. `backend/main.py` registers these, protects the real routes and keeps CORS restricted.

Trusted calls: `run_agent(context, prompt)`, `execute_tool(context, tool, arguments)`, `authorize(context, tool, arguments)`. `SecurityContext` has user ID, username, role and session ID. `actor_id` is an alias for canonical username for audit. Frozen/slots prevents ordinary mutation but does not prove provenance: never construct contexts from client input. Policy uses current `context.role`; known top-level identity fields inside tool arguments are denied. The agent sends only prompt/model/tool messages to Ollama, not authentication credentials or context. Audit records canonical actor and recognized resource/tool names, not arbitrary argument text. Full per-tool schemas and audit fields remain pending.

## Browser lifecycle and network
`frontend/src/session.js` owns the bearer in closure memory. `App.jsx` subscribes to safe snapshots and renders login or dashboard with the existing layout. Login is adopted only after `/me` returns a valid identity. UI role is a display snapshot, not authorization. Password field clears on submission; browser password-manager behavior is separate. No local/session storage, cookie, token URL, JWT decoding for authorization or persistent token cache. Fetch uses `credentials: 'omit'`, `cache: 'no-store'`, `redirect: 'error'`, and fixed local API paths. Auth requests have a 10 s timeout. Expiration checks use a conservative login-start deadline, timer, focus/visibility and request entry. A 401 resets the session; a 403/503 is a request error rather than a sign-out. Logout clears local data immediately, attempts server revocation, and reports if unconfirmed. Failed `/me` triggers best-effort cleanup of the unadopted token. Page navigation/reload clears memory, not necessarily the server session.

Reset increments a generation, aborts pending requests, clears identity/results/events/alerts, and remounts the dashboard with its new session key (prompt and selection reset). Old responses and errors cannot update new sessions, even if abort is ignored. The server may continue a previously started action. The monitoring feed remains global, so a fresh events request can still contain other actors' metadata.

CORS permits only `http://localhost:5173` and `http://127.0.0.1:5173`, GET/POST and Authorization/Content-Type (plus standard safelisted headers); no credentialed cookies. CORS is not authentication and does not restrict non-browser clients. Classic CSRF through ambient cookies is not applicable because the browser does not automatically attach this bearer; XSS or a compromised client remains dangerous. Loopback HTTP only; do not bind externally. A nonlocal deployment requires HTTPS, origin configuration, security headers/CSP review, hardened secrets/storage and a threat-model review.

## Verification and reproduction
From root: `python -m pytest -q`. From frontend: `npm test`, then install dependencies and run `npm run build` and `npm run dev`. See [frontend instructions](../frontend/README.md). Deterministic tests use temporary SQLite, synthetic passwords and random signing keys; only the LLM responses are mocked where needed.

| Test source | Evidence scope |
| --- | --- |
| Existing AG-65 and earlier tests (101 scenarios) | User/password/session/context regressions and original policy/attack behavior with adapted trusted signatures |
| `tests/security/test_auth_api.py` (37) | Login/me/logout, bad credentials, invalid transport, expiry, revocation, inactive users, storage/startup, OpenAPI, no reflected secrets |
| `tests/security/test_authenticated_actions.py` (42) | Actual routes, 401/503 without model/tool/audit execution, 422 identity spoofing, role/list/read enforcement, mocked injection, demotion, CORS, startup failures |
| `frontend/tests/session.test.js` (31) | Node native tests with simulated HTTP and fake clock: auth headers, expiry, failures, logout, race conditions, old 401 and events isolation |

Local AG-66 audit on the reconstructed AG-65 code (Python 3.13.5, Node 22.16.0): 180 Python tests and 31 Node tests passed. Step 3 also recorded five successful loopback HTTP checks between the real FastAPI backend and JS controller; these are not browser E2E. A Vite build remains unverified: npm registry DNS/cache unavailable and Vite not installed in the audit environment. JSX transpilation was checked separately, not equivalent to a build. Existing CI tests only Python 3.11; AG-66 candidate has not been pushed, so no CI run for it exists. Re-run on the actual branch and record exact SHA before closing; AG-67 must review whole-parent acceptance and PR.

## Threat model and limitations
Assets: fictional restricted documents, identity/role integrity, bearer and key confidentiality, session validity, audit metadata, browser session isolation. Threat actors: unauthenticated caller, low-privilege demo user, attacker-controlled document/prompt/tool proposals, stale browser responses. Trusted: local process/host, key, SQLite and backend-controlled call graph. A compromised host or arbitrary backend code can defeat these assumptions.

| Risk | Current mitigation | Residual / follow-up |
| --- | --- | --- |
| Client actor/role impersonation | Server validation and strict body; no static role mapping | Full role matrix AG-26 |
| Replay/forgery | HS256 allowlist, live DB lookup, expiration/revocation | Stolen active token replay; TLS/key protection; no rotation/refresh |
| Long operation after revocation/demotion | Fresh context for each new request | Already resolved context not mutated; revalidation at sensitive execution AG-27 proposal |
| Prompt injection | Separate trusted context, policy on tool calls | Model can still hallucinate/emit attacker text; no real-model detection claim |
| Malformed tool proposals | Known tool/ID/identity checks | Full schema/robust handling of arbitrary model output AG-30; no arbitrary host capabilities |
| Cross-session UI data | Abort + generation + keyed dashboard | Global events still visible; XSS can use active bearer |
| Credential guessing/resource exhaustion | Argon2id, generic errors, size checks | No rate limiter or body-size limit; timing may differ for unknown users |
| Logout/network failure or reload | Clear memory; confirmed logout revokes server record | Orphan session valid until expiry; no automatic revocation on page exit |
| Roles/account lifecycle | Current DB role on each request, inactive check | Fixed demo role checks at startup; reactivation can restore valid unrevoked sessions |
| Audit confidentiality/integrity | Canonical actor/known targets; no auth secrets deliberately logged | Public global feed, in-memory not durable/tamper-proof; coordinate Malak, AG-37 |
| Dependency/supply chain | No new dependency; existing pins for Argon2/PyJWT | No complete SCA or secret-history scanner; frontend no lockfile or build CI |

No change to `/api/events` or its access rules is made here. Agree its intended audience and filtering with Malak before implementation. Do not use real data or expose the lab. Improvements outside AG-66 require team approval and should preserve the scientific evaluation baseline.
