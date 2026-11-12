# AgentGuard — Architecture (MVP)

## Problem
An LLM agent might follow malicious text embedded in retrieved documents and attempt to access resources beyond its user's authorization. The prompt is **not** a trust boundary; tools must enforce policy on each call.

## Data flow
\`\`\`text
React UI --> FastAPI --> bounded agent runner --> local Ollama / Qwen3
                            |
                            | proposed tool calls
                            v
                   policy.authorize(...)
                            |
                +-----------+-----------+
                | allowed               | blocked
                v                       v
          simulated tools        structured denial
                |                       |
                +----------+------------+
                           v
                     audit events
                           |
                      UI monitoring
\`\`\`

## Trust boundaries
- The agent's tool arguments are untrusted; the backend checks every request.
- Actor role is resolved by backend-owned policy, **not** by an LLM response.
- Retrieved document content must never be treated as an access-control policy.
- The model receives no direct file-system, shell, HTTP browsing or database write capabilities.
- Unknown actors, unknown tools and unknown documents are rejected by default.

## Demo-only assumptions
- Identity is selected in the UI; **this is not authentication**.
- Documents and audit logs are stored in memory.
- "request_update" is intentionally denied until a human approval workflow exists.
- The bounded agent loop executes at most 3 model turns and 3 tool calls per turn.
- The tests currently validate access control against attack-like tool calls. Real-model prompt-injection trials, latency measurements, and false-positive tracking are next milestones.

## First demonstration
1. Alice (intern) asks the agent to summarize document public-injected.
2. The public document contains attacker-origin text asking for private-budget.
3. If Ollama proposes that tool call, the policy denies it and records an event.
4. Bob (manager) may legitimately read private-budget.
5. Three denials for the same actor generate an alert.

This is a teaching scenario using synthetic documents only.

## Milestone roadmap (4 weeks)
- Week 1: scaffold, local model, limited tools, baseline end-to-end call.
- Week 2: security gateway, audit and repeatable unit/attack simulations.
- Week 3: dashboard, realistic injections, monitoring, basic human approval.
- Week 4: evaluation (attack success rate, legitimate-task success, false positives and latency), report and demo.

## Suggested task ownership
- Member 1: Qwen3/Ollama and agent tool calling.
- Member 2: security policy, threat scenarios, tests and evaluation.
- Member 3: FastAPI integration, dashboard, logging and documentation.

## Next technical improvements
Implement actual authentication, persistent SQLite audit tables, automatic alert test coverage, stronger per-tool argument schemas, a non-bypassable approval gate, and CI integration with model-free regressions.
