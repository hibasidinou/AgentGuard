"""Deterministic authorization. LLM-provided roles are NEVER trusted."""
from dataclasses import dataclass

from backend.security.auth.context import SecurityContext

# Reserved identity fields are never accepted as tool arguments.
_IDENTITY_FIELDS = frozenset({"actor_id", "role", "username", "user_id", "session_id", "context"})

DOCUMENT_CLASSIFICATION = {
    "public-roadmap": "public",
    "public-injected": "public",
    "private-budget": "restricted",
}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def authorize(context: SecurityContext, tool: str, arguments: object) -> Decision:
    """Use only the context from the trusted backend call path, not client JSON.

    Type/role checks are defensive, not authentication; FastAPI resolves the context.
    """
    if not isinstance(context, SecurityContext) or context.role not in ("intern", "manager"):
        return Decision(False, "Invalid security context")
    role = context.role
    if not isinstance(arguments, dict):
        return Decision(False, "Invalid tool arguments")
    if _IDENTITY_FIELDS.intersection(arguments):
        return Decision(False, "Identity fields are not permitted in tool arguments")
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
