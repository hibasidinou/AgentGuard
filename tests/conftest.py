"""Real server-resolved demo identities for model-free authorization tests."""
import secrets

import pytest

from backend.security.auth.context import resolve_security_context
from backend.security.auth.sessions import SessionStore
from backend.security.auth.users import UserStore


@pytest.fixture
def demo_contexts(tmp_path):
    password = secrets.token_urlsafe(24)
    users = UserStore(tmp_path / "policy.db")
    sessions = SessionStore(users, signing_key=secrets.token_hex(32))
    sessions.initialize()
    users.seed_demo_users({"alice": password, "bob": password})
    contexts = {}
    for name in ("alice", "bob"):
        token = sessions.login(name, password)
        context = resolve_security_context(sessions, token)
        assert context is not None
        contexts[name] = context
    return contexts
