# AgentGuard — Architecture (MVP)

## Problem
An LLM agent might follow malicious text embedded in retrieved documents and attempt to access resources beyond its user's authorization. The prompt is **not** a trust boundary; tools must enforce policy on each call. Before AG-66 the scaffold trusted the actor selected by the client. The authenticated integration replaces that trust with a server-owned session.

## Implemented data flow (AG-66)
```text
React login --> FastAPI /api/auth/login --> UserStore (Argon2id)
                                             | SQLite users
                                             v
                  JWT <-- SessionStore --> SQLite sessions

React request (Bearer JWT + business JSON)
         |
         v
FastAPI require_security_context --> SessionStore.validate --> SQLite users/sessions
         |                         invalid -> 401; unavailable -> 503
         | immutable request-scoped SecurityContext
         +------------------------+---------------------------+
         | chat                   | simulate                  |
         v                        |                           |
   bounded agent runner <--> local Ollama/Qwen3              |
         | model proposes tools (no context/credentials)      |
         +------------------------+                           |
                                  v                           |
                          execute_tool(context, tool, args) <-+
                                  |
                          authorize(context, tool, args)
                                  |
                      +-----------+-----------+
                      | allowed               | denied
                      v                       v
                fictional documents       structured denial
                      |                       |
                      +-----------+-----------+
                                  v
                          in-memory audit
                                  |
                         public /api/events --> dashboard (pending coordination)
```

Login, me and logout share the server-owned session service initialized in FastAPI's lifespan. Chat and simulate resolve fresh contexts, reject extra top-level identity fields, and pass context separately from prompt and tool arguments. Current role comes from SQLite; no static actor-to-role map remains. The context is a snapshot, not an independently verifiable credential.

## Trust boundaries
- The browser is untrusted. The HTTP boundary verifies JWT signature, allowed algorithm, claims, expiry, server session and active user. The API refuses requests when session validation fails; no fallback actor.
- The agent's tool arguments, retrieved content and model output are untrusted. Only the backend context determines the role. The model receives no JWT, signing key, password hash or full context from authentication.
- The model has no direct filesystem, shell, HTTP browsing or database write capabilities. Unknown tools/documents and invalid contexts are refused by the current policy; full typed argument validation is a later ticket.
- The browser stores the bearer only in private session-controller memory. Abort signals and a generation counter discard stale responses after logout/account changes. The server still controls authorization.
- Monitoring currently exposes global actor/decision metadata without authentication. No real data; UI login is not an access-control boundary for this feed.

## Demo-only assumptions
- Alice = intern, Bob = manager at provisioning. Passwords are hashed; users/sessions persist in SQLite; documents and audit logs are in memory.
- `request_update` is intentionally denied until a human approval workflow exists.
- The bounded agent loop executes at most 3 model turns and 3 tool calls per turn.
- The existing `execute_tool` / `authorize` path is not yet the final `authorize_and_execute()` gateway (AG-27). AG-26 owns the full RBAC matrix; AG-30 owns strict tool arguments; AG-31 owns approval; AG-37 owns persistent audit.
- Tests currently validate model-free enforcement and simulated LLM responses. Real Qwen3 prompt-injection trials, latency measurements and false-positive tracking are separate evaluation milestones.

## First demonstration
1. Provision fictional demo accounts and configure the backend key as in the root README. Sign in as Alice (intern).
2. Simulate a read of private-budget: denied. A public read is allowed.
3. Optionally ask the real agent to summarize public-injected. If Ollama proposes a restricted read, policy denies it and records an event; if it does not propose the call, that is not evidence of gateway blocking.
4. Sign out, sign in as Bob (manager); private-budget can legitimately be read. Prior account result/prompt must not carry over.
5. Three denials by one actor in the last 20 events trigger a repeated-denial alert.

This is a teaching scenario using synthetic documents only. See [auth-integration.md](auth-integration.md) for endpoint contracts, threat model, limitations and verification.

## Milestone roadmap (4 weeks)
- Week 1: scaffold, local model, limited tools, baseline end-to-end call.
- Week 2: security gateway, audit and repeatable unit/attack simulations.
- Week 3: dashboard, realistic injections, monitoring, basic human approval.
- Week 4: evaluation (attack success rate, legitimate-task success, false positives and latency), report and demo.

## Suggested task ownership
- Member 1: Qwen3/Ollama and agent tool calling.
- Member 2: security policy, threat scenarios, tests and evaluation.
- Member 3: FastAPI integration, dashboard, logging and documentation.

## Next technical improvements (not implemented here)
Complete AG-26/AG-27 and related contracts; coordinate role-scoped `/api/events` and persistent SQLite audit tables; strengthen per-tool schemas and approval gate; consider rate limiting, session revalidation before sensitive actions, frontend lockfile/build CI and deployment isolation. Preserve the approved scope and evaluation baseline.
