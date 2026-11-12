"""Deterministic authorization. LLM-provided roles are NEVER trusted."""
from dataclasses import dataclass

# Demo-only identities. Replace with real authentication in later iterations.
ACTORS = {"alice": "intern", "bob": "manager"}

DOCUMENT_CLASSIFICATION = {
    "public-roadmap": "public",
    "public-injected": "public",
    "private-budget": "restricted",
}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def authorize(actor_id: str, tool: str, arguments: object) -> Decision:
    role = ACTORS.get(actor_id)
    if role is None:
        return Decision(False, "Unknown actor")
    if not isinstance(arguments, dict):
        return Decision(False, "Invalid tool arguments")
    if tool == "list_documents":
        return Decision(True, "List access allowed")
    if tool == "request_update":
        return Decision(False, "Manual approval required; updates disabled in MVP")
    if tool != "read_document":
        return Decision(False, "Unknown tool — denied by default")

    document_id = arguments.get("document_id")
    if not isinstance(document_id, str) or document_id not in DOCUMENT_CLASSIFICATION:
        return Decision(False, "Unknown document")
    classification = DOCUMENT_CLASSIFICATION[document_id]
    if classification == "public" or role == "manager":
        return Decision(True, "Read permitted by policy")
    return Decision(False, "Insufficient clearance for restricted document")
