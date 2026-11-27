"""AG-65 regressions with real SQLite and signed test sessions."""
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import datetime, timedelta, timezone
import secrets
import sqlite3
import time

import jwt
import pytest

from backend.security.auth.context import SecurityContext, resolve_security_context
from backend.security.auth.sessions import SessionStore, ValidatedSession
from backend.security.auth.users import UserStore
from backend.security.policy import authorize

PASSWORD = "fictional test password only"


@pytest.fixture
def store(tmp_path):
    users = UserStore(tmp_path / "test.db")
    sessions = SessionStore(users, signing_key=secrets.token_hex(32))
    sessions.initialize()
    users.seed_demo_users({"alice": PASSWORD, "bob": PASSWORD})
    return sessions


def login(store, username="alice"):
    token = store.login(username, PASSWORD)
    assert token is not None
    return token


def context_for(store, token):
    context = resolve_security_context(store, token)
    assert isinstance(context, SecurityContext)
    return context


@pytest.mark.parametrize("username,role", [("alice", "intern"), ("bob", "manager")])
def test_context_matches_session(store, username, role):
    token = login(store, username)
    context = context_for(store, token)
    session = store.validate(token)
    user = store.users.get_by_username(username)
    assert session is not None and user is not None
    assert context.user_id == session.user.id == user.id
    assert context.username == context.actor_id == username
    assert context.role == session.user.role == user.role == role
    assert context.session_id == session.session_id


@pytest.mark.parametrize("name,value", [
    ("user_id", 999), ("username", "bob"),
    ("role", "manager"), ("session_id", "other"),
])
def test_fields_frozen(store, name, value):
    context = context_for(store, login(store))
    before = asdict(context)
    with pytest.raises(FrozenInstanceError):
        setattr(context, name, value)
    assert asdict(context) == before


@pytest.mark.parametrize("name", ["actor_id", "extra"])
def test_no_mutable_alias_or_extra_attribute(store, name):
    context = context_for(store, login(store))
    with pytest.raises((AttributeError, TypeError)):
        setattr(context, name, "bob")
    assert context.actor_id == "alice"
    assert not hasattr(context, "__dict__")
    assert not hasattr(context, "extra")


def test_minimal_projection(store):
    token = login(store)
    context = context_for(store, token)
    assert set(asdict(context)) == {"user_id", "username", "role", "session_id"}
    assert all(value not in repr(context) for value in (
        token, PASSWORD, store._key, context.session_id
    ))


@pytest.mark.parametrize("token", [None, "", "bad", 1, "x" * 4097,
                                    {"actor_id": "bob", "role": "manager"}])
def test_invalid_input(store, token):
    assert resolve_security_context(store, token) is None


def test_wrong_key(store):
    token = login(store)
    other = SessionStore(store.users, signing_key=secrets.token_hex(32))
    assert resolve_security_context(other, token) is None


def test_altered_signature(store):
    head, payload, signature = login(store).split(".")
    changed = ("A" if signature[0] != "A" else "B") + signature[1:]
    assert resolve_security_context(store, ".".join((head, payload, changed))) is None


def test_unknown_session(store):
    claims = jwt.decode(login(store), options={"verify_signature": False})
    claims["jti"] = secrets.token_hex(32)
    assert resolve_security_context(store, jwt.encode(claims, store._key, algorithm="HS256")) is None


def test_wrong_session_owner(store):
    claims = jwt.decode(login(store), options={"verify_signature": False})
    claims["sub"] = str(store.users.get_by_username("bob").id)
    assert resolve_security_context(store, jwt.encode(claims, store._key, algorithm="HS256")) is None


def test_extra_claims_ignored(store):
    claims = jwt.decode(login(store), options={"verify_signature": False})
    claims.update(actor_id="bob", username="bob", role="manager")
    context = context_for(store, jwt.encode(claims, store._key, algorithm="HS256"))
    assert context.actor_id == "alice"
    assert context.role == "intern"
    assert context.user_id == store.users.get_by_username("alice").id


def test_role_is_current_server_state(store):
    token = login(store)
    previous = context_for(store, token)
    with sqlite3.connect(store.users.path) as conn:
        conn.execute("UPDATE users SET role='manager' WHERE username='alice'")
    fresh = context_for(store, token)
    assert previous.role == "intern"
    assert fresh.role == "manager"
    assert fresh.user_id == previous.user_id
    assert fresh.session_id == previous.session_id


def test_fabricated_objects_are_not_credentials(store):
    token = login(store)
    session = store.validate(token)
    assert session is not None
    forged = ValidatedSession(
        session.session_id, replace(session.user, username="bob", role="manager"),
        session.expires_at,
    )
    fake_context = replace(context_for(store, token), username="bob", role="manager")
    for value in (session, forged, fake_context):
        assert resolve_security_context(store, value) is None


def test_no_client_identity_arguments(store):
    token = login(store)
    with pytest.raises(TypeError):
        resolve_security_context(store, token, actor_id="bob", role="manager")
    assert context_for(store, token).role == "intern"


def test_jwt_expiry(store, monkeypatch):
    token = login(store)

    class Future(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(timezone.utc) + timedelta(hours=25)

    monkeypatch.setattr(jwt.api_jwt, "datetime", Future)
    assert resolve_security_context(store, token) is None


def test_server_expiry(store, monkeypatch):
    token = login(store)
    future = int(time.time()) + store.ttl + 1
    monkeypatch.setattr(time, "time", lambda: future)
    assert resolve_security_context(store, token) is None


def test_revocation_prevents_fresh_context(store):
    token = login(store)
    previous = context_for(store, token)
    other = login(store)
    assert store.logout(token)
    assert resolve_security_context(store, token) is None
    assert context_for(store, other).session_id != previous.session_id
    assert previous.actor_id == "alice"
    assert resolve_security_context(store, previous) is None


def test_inactive_user(store):
    token = login(store)
    with sqlite3.connect(store.users.path) as conn:
        conn.execute("UPDATE users SET is_active=0 WHERE username='alice'")
    assert resolve_security_context(store, token) is None


def test_storage_failure_propagates(store):
    token = login(store)
    with sqlite3.connect(store.users.path) as conn:
        conn.execute("DROP TABLE sessions")
    with pytest.raises(sqlite3.OperationalError):
        resolve_security_context(store, token)


@pytest.mark.parametrize("username,allowed", [("alice", False), ("bob", True)])
def test_authenticated_policy_compatibility(store, username, allowed):
    context = context_for(store, login(store, username))
    decision = authorize(context, "read_document", {"document_id": "private-budget"})
    assert decision.allowed is allowed
