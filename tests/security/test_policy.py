from backend.security.policy import authorize
from backend.tools.documents import execute_tool


def test_intern_can_read_public_document():
    assert authorize("alice", "read_document", {"document_id": "public-roadmap"}).allowed


def test_intern_cannot_read_restricted_document():
    result = execute_tool("alice", "read_document", {"document_id": "private-budget"})
    assert result["ok"] is False
    assert "Insufficient clearance" in result["error"]


def test_manager_can_read_restricted_document():
    result = execute_tool("bob", "read_document", {"document_id": "private-budget"})
    assert result["ok"] is True


def test_unknown_tools_and_actors_fail_closed():
    assert not authorize("alice", "run_shell", {"command": "echo test"}).allowed
    assert not authorize("unknown", "list_documents", {}).allowed


def test_updates_require_approval_even_for_manager():
    assert not authorize("bob", "request_update", {"document_id": "public-roadmap"}).allowed


def test_invalid_tool_arguments_denied():
    assert not authorize("alice", "read_document", {"document_id": "../private-budget"}).allowed
    assert not authorize("alice", "read_document", "private-budget").allowed
