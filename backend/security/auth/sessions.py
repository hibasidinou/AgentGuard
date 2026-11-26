"""Signed, revocable server-side sessions (AG-64). No HTTP endpoints."""
from contextlib import closing
from dataclasses import dataclass
import os
import secrets
import sqlite3
import time

import jwt

from .users import User, UserStore

ISSUER = "agentguard"
AUDIENCE = "agentguard-api"
ALGORITHM = "HS256"
MAX_TOKEN_LENGTH = 4096
DEFAULT_TTL = 1800
_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > issued_at),
    revoked_at INTEGER
)
"""


@dataclass(frozen=True, slots=True)
class ValidatedSession:
    session_id: str
    user: User
    expires_at: int


class SessionStore:
    def __init__(self, users: UserStore, *, signing_key: str | None = None,
                 ttl: int = DEFAULT_TTL):
        key = signing_key if signing_key is not None else os.environ.get("AGENTGUARD_JWT_SECRET", "")
        if not isinstance(key, str) or len(key.encode("utf-8")) < 32:
            raise ValueError("Configure a random signing secret of at least 32 bytes")
        if type(ttl) is not int or not 1 <= ttl <= 86400:
            raise ValueError("Session TTL must be between 1 and 86400 seconds")
        self.users = users
        self._key = key
        self.ttl = ttl

    def _connect(self):
        conn = sqlite3.connect(self.users.path.resolve().as_uri() + "?mode=rw", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def initialize(self) -> None:
        self.users.initialize()
        with closing(self._connect()) as conn, conn:
            conn.execute(_SCHEMA)

    def login(self, username: str, password: str) -> str | None:
        user = self.users.authenticate(username, password)
        if user is None:
            return None
        now = int(time.time())
        sid = secrets.token_hex(32)
        exp = now + self.ttl
        token = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": str(user.id),
                            "jti": sid, "iat": now, "exp": exp}, self._key, algorithm=ALGORITHM)
        with closing(self._connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT is_active FROM users WHERE id = ?", (user.id,)).fetchone()
            if row is None or not row["is_active"]:
                return None
            conn.execute("INSERT INTO sessions (id,user_id,issued_at,expires_at) VALUES (?,?,?,?)",
                         (sid, user.id, now, exp))
        return token

    def _claims(self, token: object) -> dict | None:
        if not isinstance(token, str) or not 0 < len(token) <= MAX_TOKEN_LENGTH:
            return None
        try:
            claims = jwt.decode(token, self._key, algorithms=[ALGORITHM], issuer=ISSUER,
                                audience=AUDIENCE, options={"require": ["iss", "aud", "sub", "jti", "iat", "exp"], "strict_aud": True})
        except (jwt.InvalidTokenError, ValueError, TypeError, OverflowError):
            return None
        sub, sid = claims["sub"], claims["jti"]
        if (not isinstance(sub, str) or not sub.isascii() or not sub.isdecimal()
                or len(sub) > 19 or not 0 < int(sub) <= 2**63-1 or str(int(sub)) != sub
                or not isinstance(sid, str) or len(sid) != 64
                or any(c not in "0123456789abcdef" for c in sid)
                or type(claims["iat"]) is not int or type(claims["exp"]) is not int
                or not 0 <= claims["iat"] < claims["exp"] <= 2**63-1):
            return None
        return claims

    def validate(self, token: object) -> ValidatedSession | None:
        claims = self._claims(token)
        if claims is None:
            return None
        with closing(self._connect()) as conn:
            row = conn.execute("""SELECT s.id AS sid, s.expires_at, u.id, u.username, u.role,
                    u.is_active, u.created_at FROM sessions s JOIN users u ON u.id=s.user_id
                    WHERE s.id=? AND s.user_id=? AND s.issued_at=? AND s.expires_at=?
                    AND s.revoked_at IS NULL AND s.expires_at>? AND u.is_active=1""",
                    (claims["jti"], int(claims["sub"]), claims["iat"], claims["exp"], int(time.time()))).fetchone()
        if row is None:
            return None
        user = User(row["id"], row["username"], row["role"], bool(row["is_active"]), row["created_at"])
        return ValidatedSession(row["sid"], user, row["expires_at"])

    def logout(self, token: object) -> bool:
        claims = self._claims(token)
        if claims is None:
            return False
        now = int(time.time())
        with closing(self._connect()) as conn, conn:
            result = conn.execute("""UPDATE sessions SET revoked_at=? WHERE id=? AND user_id=?
                AND issued_at=? AND expires_at=? AND revoked_at IS NULL AND expires_at>?""",
                (now, claims["jti"], int(claims["sub"]), claims["iat"], claims["exp"], now))
            return result.rowcount == 1
