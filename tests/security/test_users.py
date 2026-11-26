from dataclasses import asdict
import sqlite3
import pytest
from backend.security.auth.users import UserStore, UserConfigurationError

# Synthetic test fixtures only, never demonstration account credentials.
PASSWORDS = {"alice": "synthetic-alice-test-password", "bob": "synthetic-bob-test-password"}


@pytest.fixture
def store(tmp_path):
    s = UserStore(tmp_path / "auth.db")
    s.initialize()
    return s


def test_persistence_and_server_roles(store):
    assert store.seed_demo_users(PASSWORDS) == ("alice", "bob")
    reopened = UserStore(store.path)
    alice = reopened.authenticate("ALICE", PASSWORDS["alice"])
    bob = reopened.authenticate("bob", PASSWORDS["bob"])
    assert alice.role == "intern" and bob.role == "manager"
    assert alice.id != bob.id
    assert reopened.get_by_id(alice.id) == alice
    assert set(asdict(alice)) == {"id", "username", "role", "is_active", "created_at"}
    with sqlite3.connect(store.path) as conn:
        rows = conn.execute("SELECT username, password_hash FROM users").fetchall()
    assert len(rows) == 2
    assert all(h.startswith("$argon2id$") and h != PASSWORDS[n] for n, h in rows)


def test_wrong_credentials_and_injection(store):
    store.seed_demo_users(PASSWORDS)
    for username, password in [("alice", PASSWORDS["bob"]), ("unknown", PASSWORDS["alice"]), ("alice' OR 1=1 --", PASSWORDS["alice"]), ("bob", "")]:
        assert store.authenticate(username, password) is None


def test_idempotent_never_overwrites(store):
    store.seed_demo_users(PASSWORDS)
    with sqlite3.connect(store.path) as conn:
        before = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    store.initialize()
    assert store.seed_demo_users({"alice": "different-test-password", "bob": "different-test-password"}) == ()
    assert store.seed_demo_users({}) == ()
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT * FROM users ORDER BY id").fetchall() == before


def test_duplicate_and_invalid_role_rejected_at_database(store):
    store.seed_demo_users(PASSWORDS)
    with sqlite3.connect(store.path) as conn:
        h = conn.execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()[0]
        for name, role in [("alice", "intern"), ("ALICE", "intern"), ("newuser", "admin")]:
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)", (name, h, role, "2026-01-01T00:00:00+00:00"))
        assert conn.execute("SELECT count(*) FROM users").fetchone()[0] == 2


def test_missing_or_invalid_password_is_atomic(store):
    with pytest.raises(UserConfigurationError):
        store.seed_demo_users({"alice": PASSWORDS["alice"]})
    with pytest.raises(ValueError):
        store.seed_demo_users({"alice": PASSWORDS["alice"], "bob": "short"})
    assert store.missing_demo_users() == ("alice", "bob")


def test_role_mismatch_fails_without_overwriting(store):
    store.seed_demo_users(PASSWORDS)
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE users SET role='manager' WHERE username='alice'")
    with pytest.raises(UserConfigurationError):
        store.seed_demo_users(PASSWORDS)
    assert store.get_by_username("alice").role == "manager"


def test_disabled_user_cannot_authenticate_or_be_reenabled(store):
    store.seed_demo_users(PASSWORDS)
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE users SET is_active=0 WHERE username='alice'")
    assert store.authenticate("alice", PASSWORDS["alice"]) is None
    assert store.seed_demo_users(PASSWORDS) == ()
    assert not store.get_by_username("alice").is_active


def test_missing_account_only_recreated(store):
    store.seed_demo_users(PASSWORDS)
    with sqlite3.connect(store.path) as conn:
        before = conn.execute("SELECT * FROM users WHERE username='alice'").fetchone()
        conn.execute("DELETE FROM users WHERE username='bob'")
    assert store.seed_demo_users({"bob": PASSWORDS["bob"]}) == ("bob",)
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT * FROM users WHERE username='alice'").fetchone() == before


def test_unknown_account_not_provisioned(store):
    with pytest.raises(UserConfigurationError):
        store.seed_demo_users({**PASSWORDS, "eve": PASSWORDS["alice"]})
    assert store.missing_demo_users() == ("alice", "bob")


def test_existing_audit_table_untouched(tmp_path):
    path = tmp_path / "shared.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE audit_events (id INTEGER PRIMARY KEY, event TEXT)")
        conn.execute("INSERT INTO audit_events VALUES (1, 'synthetic event')")
    s = UserStore(path)
    s.initialize()
    s.seed_demo_users(PASSWORDS)
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT * FROM audit_events").fetchall() == [(1, "synthetic event")]


def test_new_account_id_not_reused(store):
    store.seed_demo_users(PASSWORDS)
    old_bob = store.get_by_username("bob")
    with sqlite3.connect(store.path) as conn:
        conn.execute("DELETE FROM users WHERE username='bob'")
    store.seed_demo_users({"bob": PASSWORDS["bob"]})
    assert store.get_by_username("bob").id != old_bob.id
    assert store.get_by_id(old_bob.id) is None
    assert store.get_by_id(2**63) is None


def test_missing_database_not_created_by_lookup(tmp_path):
    path = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        UserStore(path).get_by_username("alice")
    assert not path.exists()


def test_concurrent_bootstrap_preserves_one_pair(store):
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: UserStore(store.path).seed_demo_users(PASSWORDS), range(2)))
    assert sorted(len(result) for result in results) == [0, 2]
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT count(*) FROM users").fetchone()[0] == 2


def test_owner_only_permissions_on_new_database(tmp_path):
    import os
    import stat
    if os.name != "posix":
        pytest.skip("POSIX file mode does not describe Windows ACLs")
    path = tmp_path / "new" / "auth.db"
    UserStore(path).initialize()
    assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0


def test_env_path(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(tmp_path / "configured.db"))
    assert UserStore().path == tmp_path / "configured.db"
