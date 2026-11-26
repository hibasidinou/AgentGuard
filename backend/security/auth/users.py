"""SQLite repository for server-controlled demo users (AG-63)."""
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import sqlite3
from typing import Literal

from .passwords import hash_password, valid_password_input, verify_password

Role = Literal["intern", "manager"]
_DEMO_ROLES: tuple[tuple[str, Role], ...] = (("alice", "intern"), ("bob", "manager"))
_DEFAULT_DB = Path(__file__).resolve().parents[3] / "data" / "agentguard.db"
_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE
        CHECK (username = lower(username) COLLATE BINARY),
    password_hash TEXT NOT NULL CHECK (password_hash GLOB '$argon2id$*'),
    role TEXT NOT NULL CHECK (role IN ('intern', 'manager')),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at TEXT NOT NULL
)
"""


@dataclass(frozen=True, slots=True)
class User:
    """Safe identity projection: no password or hash can be serialized from it."""
    id: int
    username: str
    role: Role
    is_active: bool
    created_at: str


class UserConfigurationError(RuntimeError):
    """An inconsistent or incomplete demo account configuration."""


def database_path() -> Path:
    """Resolve relative configured paths against the repository root."""
    configured = os.environ.get("AGENTGUARD_DB_PATH")
    if not configured:
        return _DEFAULT_DB
    path = Path(configured).expanduser()
    return path if path.is_absolute() else _DEFAULT_DB.parent.parent / path


def _normalize(username: object) -> str | None:
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", username):
        return None
    return username.lower()


def _public(row: sqlite3.Row) -> User:
    return User(row["id"], row["username"], row["role"], bool(row["is_active"]), row["created_at"])


class UserStore:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path is not None else database_path()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path.resolve().as_uri() + "?mode=rw", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def initialize(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Create new database files with owner-only permissions on POSIX.
        # Do not change existing file permissions: they may belong to the audit module.
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        with closing(self._connect()) as conn, conn:
            conn.execute(_SCHEMA)

    def get_by_username(self, username: str) -> User | None:
        normalized = _normalize(username)
        if normalized is None:
            return None
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT id, username, role, is_active, created_at FROM users WHERE username = ?", (normalized,)).fetchone()
        return _public(row) if row else None

    def get_by_id(self, user_id: int) -> User | None:
        if type(user_id) is not int or not 0 < user_id <= 2**63 - 1:
            return None
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT id, username, role, is_active, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
        return _public(row) if row else None

    def authenticate(self, username: str, password: str) -> User | None:
        """Verify credentials, return only a safe active identity; never a hash."""
        normalized = _normalize(username)
        if normalized is None or not valid_password_input(password):
            return None
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT id, username, role, is_active, created_at, password_hash FROM users WHERE username = ?", (normalized,)).fetchone()
        if row is None or not row["is_active"]:
            return None
        if not verify_password(password, row["password_hash"]):
            return None
        return _public(row)

    @staticmethod
    def _missing(conn: sqlite3.Connection) -> tuple[str, ...]:
        missing = []
        for name, expected_role in _DEMO_ROLES:
            row = conn.execute("SELECT role FROM users WHERE username = ?", (name,)).fetchone()
            if row is None:
                missing.append(name)
            elif row["role"] != expected_role:
                raise UserConfigurationError(f"Unexpected role for demo account {name}; manual review required")
        return tuple(missing)

    def missing_demo_users(self) -> tuple[str, ...]:
        with closing(self._connect()) as conn:
            return self._missing(conn)

    def seed_demo_users(self, passwords: Mapping[str, str]) -> tuple[str, ...]:
        """Insert missing Alice/Bob atomically, using fixed server-owned roles.

        Existing records are never updated, even if supplied new passwords.
        Missing passwords or role inconsistencies fail before inserting anything.
        """
        if set(passwords) - {name for name, _ in _DEMO_ROLES}:
            raise UserConfigurationError("Unknown demo account in initialization")
        missing = self.missing_demo_users()
        if any(name not in passwords for name in missing):
            raise UserConfigurationError("Password required for each missing demo account")
        # Expensive hashing outside the SQLite write lock.
        hashes = {name: hash_password(passwords[name]) for name in missing}
        roles = dict(_DEMO_ROLES)
        with closing(self._connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            remaining = self._missing(conn)
            if any(name not in hashes for name in remaining):
                raise UserConfigurationError("Demo accounts changed during initialization; retry")
            for name in remaining:
                conn.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                             (name, hashes[name], roles[name], datetime.now(timezone.utc).isoformat()))
        return remaining
