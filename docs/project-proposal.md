# AgentGuard — Project proposal summary

**Academic project:** Security gateway for AI agents (3-person team; 4 weeks).

## Research question
How can a tool-using LLM assistant be constrained by deterministic security controls to prevent unauthorized operations, even when prompt injection in an external document influences the model?

## Objective
Build and evaluate a small AI document assistant with:
1. A local Qwen3 model invoked through Ollama.
2. A narrow, auditable set of tools.
3. Server-enforced permissions, input validation and safe defaults.
4. Structured action logging, detection rules and an analyst dashboard.
5. Reproducible authorized and malicious-use tests.

## Scope
The first increment supports two demo roles, synthetic public and restricted documents, reading/listing tools, and a denied-by-default modification request. It intentionally excludes cloud infrastructure, model training, shell execution, uncontrolled browsing, and real sensitive data.

## Test plan
- Legitimate intern reads a public report: **allowed**.
- Intern tries to read a private budget: **denied and logged**.
- Manager reads the private budget: **allowed**.
- Public report contains a prompt injection to read private budget: **any proposed forbidden call is denied**.
- Unknown tool or malformed parameters: **denied**.
- Three blocked calls: **monitoring alert**.
- Model connected vs simulation: compare action traces and latency; record model-dependent behavior separately.

## Evaluation
Report attack success rate on explicitly defined scenarios, forbidden-action block rate, legitimate-task completion rate, false-positive rate, and additional response latency. Explain the denominator and clearly distinguish simulated tool requests from end-to-end LLM attacks.

## Deliverables
A GitHub repository with documented architecture, running FastAPI backend, optional Ollama agent, React dashboard, automated tests, observed metrics, and a final technical report.

The detailed proposal PDF prepared for the supervisor should be added as \`docs/project-proposal.pdf\` by a collaborator after the scaffold is merged. This Markdown document is a readable repository-side summary, not a PDF substitute.
