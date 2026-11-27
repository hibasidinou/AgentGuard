"""AG-66 HTTP boundary tests with real SQLite, Argon2id and JWT; no Ollama."""
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient

from backend.security.auth.http import (
    AuthenticatedContext, initialize_auth, sanitized_validation_error,
)
from backend.security.auth.routes import router
from backend.security.auth.sessions import SessionStore
from backend.security.auth.users import UserConfigurationError, UserStore


@pytest.fixture
def lab(tmp_path):
    password = secrets.token_urlsafe(24)
    users = UserStore(tmp_path / "test.db")
    store = SessionStore(users, signing_key=secrets.token_hex(32))
    store.initialize()
    users.seed_demo_users({"alice": password, "bob": password})
    app = FastAPI()
    app.state.sessions = store
    app.add_exception_handler(RequestValidationError, sanitized_validation_error)
    app.include_router(router)
    calls = []

    # An isolated probe, NOT a real AgentGuard action route.
    @app.post("/probe")
    def probe(context: AuthenticatedContext):
        calls.append(context.actor_id)
        return {"username": context.username, "role": context.role}

    with TestClient(app) as client:
        yield client, store, password, calls


def login(lab, username="alice"):
    client, _, password, _ = lab
    result = client.post("/api/auth/login", json={"username": username, "password": password})
    assert result.status_code == 200
    assert result.headers["cache-control"] == "no-store"
    assert set(result.json()) == {"access_token", "token_type", "expires_in"}
    assert result.json()["token_type"] == "bearer"
    assert result.json()["expires_in"] == 1800
    return result.json()["access_token"]


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def assert_unauthorized(response):
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("username,role", [("alice", "intern"), ("bob", "manager")])
def test_login_me_and_probe(lab, username, role):
    client, store, password, calls = lab
    token = login(lab, username)
    result = client.get("/api/auth/me", headers=bearer(token))
    assert result.status_code == 200
    assert result.json() == {"username": username, "role": role}
    assert result.headers["cache-control"] == "no-store"
    assert all(secret not in result.text for secret in (password, token, store._key))
    assert client.post("/probe", headers=bearer(token)).json() == result.json()
    assert calls == [username]


def test_generic_bad_credentials(lab):
    client, store, password, _ = lab
    wrong = client.post("/api/auth/login", json={"username": "alice", "password": password + "x"})
    unknown = client.post("/api/auth/login", json={"username": "unknown", "password": password})
    for result in (wrong, unknown):
        assert_unauthorized(result)
        assert result.json() == {"detail": "Invalid credentials"}
    with sqlite3.connect(store.users.path) as conn:
        assert conn.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0


@pytest.mark.parametrize("case", ["extra_role", "extra_actor", "extra_secret_key", "missing", "type", "malformed", "oversized"])
def test_login_validation_does_not_echo_credentials(lab, case):
    client, store, password, _ = lab
    body = {"username": "alice", "password": password}
    if case == "extra_role":
        body["role"] = "manager"
    elif case == "extra_actor":
        body["actor_id"] = "bob"
    elif case == "extra_secret_key":
        body[password] = password
    elif case == "missing":
        del body["username"]
    elif case == "type":
        body["password"] = {"value": password}
    elif case == "oversized":
        body["password"] = password * 100
    result = (client.post("/api/auth/login", content='{"password":"' + password,
                          headers={"Content-Type": "application/json"})
              if case == "malformed" else client.post("/api/auth/login", json=body))
    assert result.status_code == 422
    assert result.json() == {"detail": "Invalid request"}
    assert password not in result.text
    assert result.headers["cache-control"] == "no-store"
    with sqlite3.connect(store.users.path) as conn:
        assert conn.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0


@pytest.mark.parametrize("case", ["missing", "basic", "empty", "invalid", "too_long", "duplicate", "comma", "query", "cookie", "forged"])
def test_invalid_transport_or_signature_never_reaches_probe(lab, case):
    client, _, _, calls = lab
    token = login(lab)
    path = "/probe"
    headers = {}
    if case == "basic":
        headers = {"Authorization": f"Basic {token}"}
    elif case == "empty":
        headers = {"Authorization": "Bearer"}
    elif case == "invalid":
        headers = bearer("not-a-jwt")
    elif case == "too_long":
        headers = bearer("a" * 4097 + ".b.c")
    elif case == "duplicate":
        headers = [("Authorization", f"Bearer {token}"), ("Authorization", f"Bearer {token}")]
    elif case == "comma":
        headers = bearer(token + ", " + token)
    elif case == "query":
        path += "?access_token=" + token
    elif case == "cookie":
        headers = {"Cookie": "access_token=" + token}
    elif case == "forged":
        head, payload, sig = token.split(".")
        forged = ("A" if sig[0] != "A" else "B") + sig[1:]
        headers = bearer(".".join((head, payload, forged)))
    assert_unauthorized(client.post(path, headers=headers))
    assert calls == []


def test_logout_revokes_only_presented_session(lab):
    client, _, _, calls = lab
    first = login(lab)
    second = login(lab)
    result = client.post("/api/auth/logout", headers=bearer(first))
    assert result.status_code == 204
    assert not result.content
    assert result.headers["cache-control"] == "no-store"
    assert_unauthorized(client.get("/api/auth/me", headers=bearer(first)))
    assert_unauthorized(client.post("/probe", headers=bearer(first)))
    assert_unauthorized(client.post("/api/auth/logout", headers=bearer(first)))
    assert client.get("/api/auth/me", headers=bearer(second)).status_code == 200
    assert calls == []


@pytest.mark.parametrize("case", ["jwt_expiry", "sqlite_expiry", "inactive", "unknown_session"])
def test_invalid_session_never_reaches_probe(lab, monkeypatch, case):
    client, store, _, calls = lab
    token = login(lab)
    if case == "jwt_expiry":
        class Future(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.now(timezone.utc) + timedelta(hours=25)
        monkeypatch.setattr(jwt.api_jwt, "datetime", Future)
    elif case == "sqlite_expiry":
        future = int(time.time()) + store.ttl + 1
        monkeypatch.setattr(time, "time", lambda: future)
    elif case == "inactive":
        with sqlite3.connect(store.users.path) as conn:
            conn.execute("UPDATE users SET is_active=0 WHERE username='alice'")
    else:
        with sqlite3.connect(store.users.path) as conn:
            conn.execute("DELETE FROM sessions")
    assert_unauthorized(client.post("/probe", headers=bearer(token)))
    assert calls == []


def test_me_resolves_role_again_each_request(lab):
    client, store, _, _ = lab
    token = login(lab, "bob")
    assert client.get("/api/auth/me", headers=bearer(token)).json()["role"] == "manager"
    with sqlite3.connect(store.users.path) as conn:
        conn.execute("UPDATE users SET role='intern' WHERE username='bob'")
    assert client.get("/api/auth/me", headers=bearer(token)).json()["role"] == "intern"


@pytest.mark.parametrize("method,path", [("GET", "/api/auth/me"), ("POST", "/api/auth/logout"), ("POST", "/probe"), ("POST", "/api/auth/login")])
def test_sqlite_failure_sanitized(lab, method, path):
    client, store, password, calls = lab
    token = login(lab)
    with sqlite3.connect(store.users.path) as conn:
        conn.execute("DROP TABLE sessions")
    kwargs = {"headers": bearer(token)}
    if path.endswith("/login"):
        kwargs["json"] = {"username": "alice", "password": password}
    result = client.request(method, path, **kwargs)
    assert result.status_code == 503
    assert result.json() == {"detail": "Authentication service unavailable"}
    assert result.headers["cache-control"] == "no-store"
    assert all(secret not in result.text for secret in (str(store.users.path), token, password, store._key))
    assert calls == []


def test_missing_app_store_fails_closed(lab):
    client, _, _, calls = lab
    token = login(lab)
    del client.app.state.sessions
    assert client.post("/probe", headers=bearer(token)).status_code == 503
    assert calls == []


def test_openapi_describes_bearer_security(lab):
    client, _, _, _ = lab
    schema = client.get("/openapi.json").json()
    assert schema["components"]["securitySchemes"]["AgentGuardBearer"]["scheme"] == "bearer"
    assert schema["paths"]["/api/auth/me"]["get"]["security"] == [{"AgentGuardBearer": []}]


@pytest.fixture
def config(tmp_path, monkeypatch):
    path = tmp_path / "configured.db"
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(path))
    monkeypatch.setenv("AGENTGUARD_JWT_SECRET", secrets.token_hex(32))
    return path


def test_initialize_reuses_provisioned_accounts(config):
    users = UserStore(config)
    users.initialize()
    password = secrets.token_urlsafe(24)
    users.seed_demo_users({"alice": password, "bob": password})
    store = initialize_auth()
    assert store.users.path == config
    assert store.login("alice", password) is not None
    assert initialize_auth().login("bob", password) is not None


@pytest.mark.parametrize("key", [None, "short"])
def test_initialize_refuses_missing_or_short_secret(config, monkeypatch, key):
    if key is None:
        monkeypatch.delenv("AGENTGUARD_JWT_SECRET")
    else:
        monkeypatch.setenv("AGENTGUARD_JWT_SECRET", key)
    with pytest.raises(ValueError, match="signing secret"):
        initialize_auth()
    assert not config.exists()


def test_initialize_refuses_missing_demo_users(config):
    with pytest.raises(UserConfigurationError, match="bootstrap"):
        initialize_auth()
    with sqlite3.connect(config) as conn:
        assert conn.execute("SELECT count(*) FROM users").fetchone()[0] == 0


def test_initialize_sanitizes_storage_failure(config):
    config.mkdir()
    with pytest.raises(RuntimeError, match="Authentication storage initialization failed"):
        initialize_auth()
