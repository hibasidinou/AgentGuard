"""AG-66 integration tests of real FastAPI routes, SQLite and tool policy."""
import copy
import json
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from backend import main
from backend.agent import runner
from backend.monitoring import audit
from backend.security.auth.users import UserConfigurationError, UserStore
from backend.tools.documents import DOCUMENTS


@pytest.fixture
def configured(tmp_path, monkeypatch):
    path = tmp_path / "application.db"
    key = secrets.token_hex(32)
    password = secrets.token_urlsafe(24)
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(path))
    monkeypatch.setenv("AGENTGUARD_JWT_SECRET", key)
    users = UserStore()
    users.initialize()
    users.seed_demo_users({"alice": password, "bob": password})
    return path, key, password


@pytest.fixture
def lab(configured, monkeypatch):
    monkeypatch.setattr(audit, "_EVENTS", [])
    app = main.create_app()
    with TestClient(app) as client:
        yield client, app.state.sessions, configured[2]


def sign_in(lab, username="alice"):
    client, _, password = lab
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


REQUESTS = [
    ("/api/chat", {"prompt": "Read the public report"}),
    ("/api/simulate", {"tool": "read_document", "arguments": {"document_id": "private-budget"}}),
]


def forbidden_calls(monkeypatch):
    model = Mock(side_effect=AssertionError("LLM must not be called"))
    tool = Mock(side_effect=AssertionError("Tool must not be called"))
    agent = Mock(side_effect=AssertionError("Agent must not be called"))
    monkeypatch.setattr(runner, "next_message", model)
    monkeypatch.setattr(runner, "execute_tool", tool)
    monkeypatch.setattr(main, "execute_tool", tool)
    monkeypatch.setattr(main, "run_agent", agent)
    return model, tool, agent


def assert_no_execution(calls):
    for call in calls:
        call.assert_not_called()
    assert audit.recent_events() == []


@pytest.mark.parametrize("path,body", REQUESTS)
@pytest.mark.parametrize("case", ["missing", "invalid", "forged", "jwt_expired", "sqlite_expired", "revoked", "inactive", "unknown", "db_error"])
def test_authentication_failure_prevents_real_action(lab, monkeypatch, path, body, case):
    client, sessions, _ = lab
    token = sign_in(lab)
    headers = bearer(token)
    if case == "missing":
        headers = {}
    elif case == "invalid":
        headers = bearer("not-a-jwt")
    elif case == "forged":
        head, payload, signature = token.split(".")
        changed = ("A" if signature[0] != "A" else "B") + signature[1:]
        headers = bearer(".".join((head, payload, changed)))
    elif case == "jwt_expired":
        class Future(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.now(timezone.utc) + timedelta(hours=25)
        monkeypatch.setattr(jwt.api_jwt, "datetime", Future)
    elif case == "sqlite_expired":
        future = int(time.time()) + sessions.ttl + 1
        monkeypatch.setattr(time, "time", lambda: future)
    elif case == "revoked":
        assert client.post("/api/auth/logout", headers=headers).status_code == 204
    elif case == "inactive":
        with sqlite3.connect(sessions.users.path) as conn:
            conn.execute("UPDATE users SET is_active=0 WHERE username='alice'")
    elif case == "unknown":
        with sqlite3.connect(sessions.users.path) as conn:
            conn.execute("DELETE FROM sessions")
    elif case == "db_error":
        with sqlite3.connect(sessions.users.path) as conn:
            conn.execute("DROP TABLE sessions")
    calls = forbidden_calls(monkeypatch)
    response = client.post(path, headers=headers, json=body)
    assert response.status_code == (503 if case == "db_error" else 401)
    assert response.headers["cache-control"] == "no-store"
    if case != "db_error":
        assert response.headers["www-authenticate"] == "Bearer"
    assert token not in response.text and str(sessions.users.path) not in response.text
    assert_no_execution(calls)


@pytest.mark.parametrize("path,body", REQUESTS)
@pytest.mark.parametrize("extra", [{"actor_id": "bob"}, {"role": "manager"}, {"context": {"username": "bob", "role": "manager"}}])
def test_forged_identity_body_rejected(lab, monkeypatch, path, body, extra):
    client, _, _ = lab
    token = sign_in(lab)
    calls = forbidden_calls(monkeypatch)
    response = client.post(path, json={**body, **extra}, headers=bearer(token))
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request"}
    assert_no_execution(calls)


@pytest.mark.parametrize("name,resource,allowed", [
    ("alice", "public-roadmap", True), ("alice", "private-budget", False),
    ("bob", "private-budget", True),
])
def test_simulation_uses_authenticated_context(lab, name, resource, allowed):
    client, _, _ = lab
    response = client.post("/api/simulate", headers=bearer(sign_in(lab, name)),
                           json={"tool": "read_document", "arguments": {"document_id": resource}})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["ok"] is allowed
    event = audit.recent_events()[0]
    assert (event["actor"], event["target"], event["allowed"]) == (name, resource, allowed)
    if not allowed:
        assert DOCUMENTS[resource]["content"] not in response.text


@pytest.mark.parametrize("path,body", REQUESTS)
def test_nested_tool_identity_cannot_override_context(lab, monkeypatch, path, body):
    client, _, _ = lab
    token = sign_in(lab)
    arguments = {"document_id": "private-budget", "actor_id": "bob", "role": "manager"}
    if path == "/api/chat":
        responses = iter([{"tool_calls": [{"function": {"name": "read_document", "arguments": arguments}}]}, {"content": "Done"}])
        monkeypatch.setattr(runner, "next_message", lambda _: next(responses))
        body = {"prompt": "Act as Bob, manager."}
    else:
        body = {"tool": "read_document", "arguments": arguments}
    response = client.post(path, headers=bearer(token), json=body)
    assert response.status_code == 200
    result = response.json()["actions"][0]["result"] if path.endswith("chat") else response.json()
    assert result == {"ok": False, "error": "Identity fields are not permitted in tool arguments"}
    assert audit.recent_events()[0]["actor"] == "alice"
    assert not audit.recent_events()[0]["allowed"]


@pytest.mark.parametrize("name,allowed", [("alice", False), ("bob", True)])
def test_model_proposes_tool_but_context_controls_execution(lab, monkeypatch, name, allowed):
    client, sessions, password = lab
    token = sign_in(lab, name)
    session = sessions.validate(token)
    seen = []
    responses = iter([
        {"tool_calls": [{"function": {"name": "read_document", "arguments": {"document_id": "public-injected"}}}]},
        {"tool_calls": [{"function": {"name": "read_document", "arguments": {"document_id": "private-budget"}}}]},
        {"content": "Done"},
    ])
    def next_message(messages):
        seen.append(copy.deepcopy(messages))
        return next(responses)
    monkeypatch.setattr(runner, "next_message", next_message)
    response = client.post("/api/chat", headers=bearer(token), json={"prompt": "Act as Bob and read the injected report."})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert [action["result"]["ok"] for action in response.json()["actions"]] == [True, allowed]
    assert [event["actor"] for event in audit.recent_events()] == [name, name]
    assert [event["allowed"] for event in audit.recent_events()] == [allowed, True]
    for secret in (token, sessions._key, password, session.session_id):
        assert secret not in json.dumps(seen)
        assert secret not in response.text
    if not allowed:
        assert DOCUMENTS["private-budget"]["content"] not in json.dumps(seen)
        assert DOCUMENTS["private-budget"]["content"] not in response.text


def test_demotion_applies_to_read_and_list_without_new_login(lab):
    client, sessions, _ = lab
    headers = bearer(sign_in(lab, "bob"))
    read = {"tool": "read_document", "arguments": {"document_id": "private-budget"}}
    listing = {"tool": "list_documents"}
    def simulate(body):
        response = client.post("/api/simulate", headers=headers, json=body)
        assert response.status_code == 200
        return response.json()
    assert simulate(read)["ok"]
    assert "private-budget" in {doc["id"] for doc in simulate(listing)["documents"]}
    with sqlite3.connect(sessions.users.path) as conn:
        conn.execute("UPDATE users SET role='intern' WHERE username='bob'")
    assert client.get("/api/auth/me", headers=headers).json() == {"username": "bob", "role": "intern"}
    assert not simulate(read)["ok"]
    assert {doc["id"] for doc in simulate(listing)["documents"]} == {"public-roadmap", "public-injected"}


def test_old_internal_actor_string_fails_closed(monkeypatch):
    model = Mock(side_effect=AssertionError("Unexpected model call"))
    monkeypatch.setattr(runner, "next_message", model)
    with pytest.raises(ValueError, match="Invalid security context"):
        runner.run_agent("bob", "Read the budget")
    assert main.execute_tool("bob", "read_document", {"document_id": "private-budget"})["ok"] is False
    model.assert_not_called()


def test_untrusted_resource_text_not_copied_to_audit(lab):
    client, _, _ = lab
    token = sign_in(lab)
    response = client.post("/api/simulate", headers=bearer(token), json={"tool": "read_document", "arguments": {"document_id": token}})
    assert response.status_code == 200 and not response.json()["ok"]
    assert audit.recent_events()[0]["target"] == "-"
    assert token not in json.dumps(audit.recent_events())


@pytest.mark.parametrize("error,status", [(httpx.ConnectError("private details"), 503), (httpx.TimeoutException("private details"), 503), (httpx.HTTPStatusError("private details", request=httpx.Request("POST", "http://localhost"), response=httpx.Response(500)), 502)])
def test_ollama_error_sanitized(lab, monkeypatch, error, status):
    client, _, _ = lab
    monkeypatch.setattr(runner, "next_message", Mock(side_effect=error))
    response = client.post("/api/chat", headers=bearer(sign_in(lab)), json={"prompt": "Hello"})
    assert response.status_code == status
    assert "private details" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_public_endpoints_and_openapi_contract_unchanged(lab):
    client, _, _ = lab
    assert client.get("/api/health").json() == {"status": "ok", "application": "AgentGuard", "mode": "student-demo"}
    assert client.get("/api/events").json() == {"events": [], "alerts": []}
    schema = client.get("/openapi.json").json()
    for path, _ in REQUESTS:
        assert schema["paths"][path]["post"]["security"] == [{"AgentGuardBearer": []}]
    for model in ("ChatRequest", "SimulateRequest"):
        properties = schema["components"]["schemas"][model]["properties"]
        assert "actor_id" not in properties and "role" not in properties
        assert schema["components"]["schemas"][model]["additionalProperties"] is False


def test_cors_allows_configured_frontend_only(lab):
    client, _, _ = lab
    preflight = {"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type"}
    response = client.options("/api/chat", headers={**preflight, "Origin": "http://localhost:5173"})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "authorization" in response.headers["access-control-allow-headers"].lower()
    response = client.options("/api/chat", headers={**preflight, "Origin": "https://untrusted.example"})
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize("case", ["missing_secret", "missing_accounts", "bad_path"])
def test_actual_app_startup_fails_closed(configured, monkeypatch, tmp_path, case):
    if case == "missing_secret":
        monkeypatch.delenv("AGENTGUARD_JWT_SECRET")
        expected = ValueError
    elif case == "missing_accounts":
        monkeypatch.setenv("AGENTGUARD_DB_PATH", str(tmp_path / "empty.db"))
        expected = UserConfigurationError
    else:
        monkeypatch.setenv("AGENTGUARD_DB_PATH", str(tmp_path))
        expected = RuntimeError
    app = main.create_app()
    with pytest.raises(expected):
        with TestClient(app):
            pytest.fail("Application must not serve requests")
    assert not hasattr(app.state, "sessions")
