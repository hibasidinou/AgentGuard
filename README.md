# AgentGuard
Security framework for LLM-based AI agents

> Academic PFS project — 3 students, 4 weeks. This repository contains the **initial scaffold**, not a finished security product.

## Goal
Build a local AI document assistant powered by Qwen3/Ollama, and an independent security gateway that **authorizes or rejects every tool action**. Add audit events and reproducible prompt-injection scenarios.

## Tech stack
- Python 3.11+, FastAPI, Pydantic, httpx, pytest
- Ollama + Qwen3 (local; no paid external API required)
- React + Vite (dashboard)
- In-memory sample data and audit logs in the starter version

## Quick start — backend
1. Clone the repository and open its root folder.
2. Create and activate a Python virtual environment.
3. Run: \`pip install -r requirements.txt\`
4. Run: \`uvicorn backend.main:app --reload\`
5. Open \`http://localhost:8000/docs\`.

The **simulation endpoint** works without Ollama:
- \`POST /api/simulate\` accepts an actor, tool name, and arguments.

## Optional real AI agent
1. Install Ollama: https://ollama.com
2. Run: \`ollama pull qwen3:1.7b\`
3. Make sure the Ollama service is running.
4. Use \`POST /api/chat\` (the frontend calls it too).

The local chat endpoint will respond with a helpful error if Ollama is offline. Model tool-calling quality varies by model and hardware.

## Frontend
\`\`\`bash
cd frontend
npm install
npm run dev
\`\`\`
Open \`http://localhost:5173\`. Requires a compatible recent Node.js version.

## Tests
\`\`\`bash
pip install -r requirements.txt
pytest -q
\`\`\`

## Repository layout
- \`backend/agent/\` — Ollama integration and controlled agent loop
- \`backend/security/\` — server-side authorization policy
- \`backend/monitoring/\` — auditable decisions and basic alerts
- \`backend/tools/\` — intentionally limited document tools
- \`frontend/\` — React starter dashboard
- \`tests/security/\` — access-control regression tests
- \`tests/attacks/\` — simulated malicious tool-call tests
- \`docs/\` — architecture and project proposal
- \`.github/workflows/\` — backend test CI

## Important security limitations
**This is a local teaching/demo environment, NOT production-ready.** Actor selection in the dashboard is not authentication; a production version needs authenticated identities, durable and tamper-resistant audit storage, rate limits, and stricter deployment isolation. The initial attack tests verify policy enforcement; they do not yet prove that real-model prompt injections are always detected.

For full design decisions and the four-week roadmap, see [docs/architecture.md](docs/architecture.md) and [docs/project-proposal.md](docs/project-proposal.md).
