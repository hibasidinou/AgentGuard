# AgentGuard
Security framework for LLM-based AI agents

> Academic PFS project — 3 students, 4 weeks. Local prototype with authenticated demo users (AG-25/AG-66), not a finished security product.

## Goal
Build a local AI document assistant powered by Qwen3/Ollama, and an independent security gateway that **authorizes or rejects every tool action**. Add audit events and reproducible prompt-injection scenarios.

## Tech stack
- Python 3.11+, FastAPI, Pydantic, httpx, pytest
- SQLite users and revocable sessions, Argon2id passwords, PyJWT (HS256)
- Ollama + Qwen3 (local; no paid external API required)
- React + Vite (dashboard)
- In-memory fictional documents and audit events (persistent audit is future work)

## Quick start — backend
From the repository root, create and activate a Python virtual environment, then:

```sh
python -m pip install -r requirements.txt
python -m backend.security.auth.bootstrap
```

The bootstrap prompts for fictional Alice (`intern`) and Bob (`manager`) passwords (at least 15 characters, at most 1024 UTF-8 bytes). It never overwrites existing accounts. There is no public registration or default password. Keep the database (`data/agentguard.db` by default) and secrets out of Git. Set `AGENTGUARD_DB_PATH` before provisioning if using a different database.

Configure a random signing key in the same shell that will run FastAPI. For PowerShell:

```powershell
$env:AGENTGUARD_JWT_SECRET = python -c "import secrets; print(secrets.token_hex(32))"
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

For Bash:

```sh
export AGENTGUARD_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

The commands do not display the key. Preserve it securely if existing sessions must survive a restart. `.env.example` is a template, not an automatic environment loader. Missing configuration/provisioning prevents startup. API documentation: `http://localhost:8000/docs`.

The **simulation endpoint works without Ollama**. Sign in via `POST /api/auth/login` with username/password, then present `Authorization: Bearer <JWT>` to `GET /api/auth/me`, `POST /api/simulate`, `POST /api/chat` and `POST /api/auth/logout`. Simulation accepts `tool` and `arguments`; chat accepts `prompt`. No client actor or role field is accepted. Logout revokes the presented session. See [AG-66 API contracts and security limits](docs/auth-integration.md).

## Optional real AI agent
1. Install Ollama: https://ollama.com
2. Run: `ollama pull qwen3:1.7b`
3. Make sure the Ollama service is running.
4. Use authenticated `POST /api/chat` (the frontend calls it too).

The local chat endpoint returns a sanitized error if Ollama is offline. Model tool-calling quality varies by model and hardware.

## Frontend
Use Node.js 22 for the tested controller workflow. From a second terminal:

```sh
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Sign in with a provisioned account. JWTs stay in JavaScript memory; reloading the page requires sign-in again. The dashboard retains simulation, chat and monitoring. Monitoring is still a public global demo feed at the backend; the login UI does not make it private.

## Tests
```sh
python -m pytest -q
cd frontend
npm test
npm run build
```

Python and Node controller tests require no Ollama. `npm test` uses native Node tests; `npm run build` requires installed React/Vite dependencies. Verify the browser smoke procedure in [frontend/README.md](frontend/README.md). The existing GitHub Actions job tests only the Python backend on Python 3.11; it does not validate the frontend build. There is no frontend lockfile yet.

## Repository layout
- `backend/agent/` — Ollama integration and controlled agent loop
- `backend/security/auth/` — users, passwords, sessions, immutable context and HTTP authentication
- `backend/security/policy.py` — current deterministic authorization rules
- `backend/monitoring/` — auditable decisions and basic alerts
- `backend/tools/` — intentionally limited document tools
- `frontend/` — React dashboard, session controller and Node tests
- `tests/security/` — authentication and access-control regression tests
- `tests/attacks/` — simulated malicious tool-call tests
- `docs/` — architecture, project proposal and authentication documentation
- `.github/workflows/` — backend test CI

## Important security limitations
**Local teaching/demo only; do not use real confidential data or expose to the network.** Authentication protects chat/simulation, not the public `/api/events` feed. Remaining work includes role-scoped monitoring, rate limits, durable audit, stronger tool schemas, the final gateway and approval workflow. Browser memory is not protection against active XSS. Use TLS and review origins before any nonlocal deployment. Revocation applies to subsequent requests; it does not cancel already authorized work. Deterministic attack tests demonstrate enforcement for simulated tool calls, not real-model injection detection.

See [architecture](docs/architecture.md), [project proposal](docs/project-proposal.md), [sessions](docs/auth-sessions.md), [Security Context](docs/security-context.md) and [AG-66 integration](docs/auth-integration.md).

## Contributing
- Create one branch per Jira parent ticket; AG-63 through AG-67 share `AG-25-backend-user-sessions` and a single AG-25 PR.
- Include Jira keys in branch names, commits and PR titles. Coordinate shared changes with their owners.
- Submit changes through Pull Requests; require another team member to review before merging.
- Run automated tests before merging. Never commit secrets or local databases.
