"""These are *simulated tool-call* tests, not evidence of LLM detection."""
from backend.tools.documents import execute_tool, DOCUMENTS


def test_untrusted_public_content_cannot_grant_private_access():
    assert "read_document" in DOCUMENTS["public-injected"]["content"]
    # A compromised LLM may try this tool call. Policy must still deny it.
    result = execute_tool("alice", "read_document", {"document_id": "private-budget"})
    assert result["ok"] is False


def test_malicious_tool_name_cannot_execute():
    result = execute_tool("alice", "execute_shell", {"command": "whoami"})
    assert result["ok"] is False
