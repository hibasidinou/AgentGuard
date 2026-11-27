from backend.security.policy import authorize
from backend.tools.documents import execute_tool


def test_intern_can_read_public_document(demo_contexts):
    assert authorize(demo_contexts["alice"], "read_document", {"document_id": "public-roadmap"}).allowed


def test_intern_cannot_read_restricted_document(demo_contexts):
    result = execute_tool(demo_contexts["alice"], "read_document", {"document_id": "private-budget"})
    assert result["ok"] is False
    assert "Insufficient clearance" in result["error"]


def test_manager_can_read_restricted_document(demo_contexts):
    result = execute_tool(demo_contexts["bob"], "read_document", {"document_id": "private-budget"})
    assert result["ok"] is True


def test_unknown_tools_and_actors_fail_closed(demo_contexts):
    assert not authorize(demo_contexts["alice"], "run_shell", {"command": "echo test"}).allowed
    assert not authorize("unknown", "list_documents", {}).allowed


def test_updates_require_approval_even_for_manager(demo_contexts):
    assert not authorize(demo_contexts["bob"], "request_update", {"document_id": "public-roadmap"}).allowed


def test_invalid_tool_arguments_denied(demo_contexts):
    assert not authorize(demo_contexts["alice"], "read_document", {"document_id": "../private-budget"}).allowed
    assert not authorize(demo_contexts["alice"], "read_document", "private-budget").allowed
