"""HTTP authentication boundary for AG-66; no client-owned identity."""
from typing import Annotated
import re
import sqlite3

from fastapi import Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .context import SecurityContext, resolve_security_context
from .sessions import MAX_TOKEN_LENGTH, SessionStore
from .users import UserConfigurationError, UserStore

_bearer = HTTPBearer(auto_error=False, scheme_name="AgentGuardBearer", bearerFormat="JWT")
_token_pattern = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", re.ASCII)


def initialize_auth() -> SessionStore:
    """Construct the trusted store at startup; never seed default passwords."""
    try:
        users = UserStore()
        sessions = SessionStore(users)
        sessions.initialize()
        if users.missing_demo_users():
            raise UserConfigurationError("Provision demo accounts with the auth bootstrap first")
    except (sqlite3.Error, OSError):
        raise RuntimeError("Authentication storage initialization failed") from None
    return sessions


def unauthorized(detail: str = "Invalid or expired session") -> HTTPException:
    return HTTPException(status_code=401, detail=detail, headers={
        "WWW-Authenticate": "Bearer", "Cache-Control": "no-store",
    })


def auth_unavailable() -> HTTPException:
    return HTTPException(status_code=503, detail="Authentication service unavailable",
                         headers={"Cache-Control": "no-store"})


def get_session_store(request: Request) -> SessionStore:
    sessions = getattr(request.app.state, "sessions", None)
    if not isinstance(sessions, SessionStore):
        raise auth_unavailable()
    return sessions


def get_bearer_token(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> str:
    # Reject duplicate/ambiguous headers rather than selecting the first one.
    values = request.headers.getlist("authorization")
    if len(values) != 1 or credentials is None:
        raise unauthorized()
    token = credentials.credentials
    if (credentials.scheme.lower() != "bearer" or len(token) > MAX_TOKEN_LENGTH
            or not _token_pattern.fullmatch(token)):
        raise unauthorized()
    return token


BearerToken = Annotated[str, Depends(get_bearer_token)]
AuthStore = Annotated[SessionStore, Depends(get_session_store)]


def require_security_context(token: BearerToken, sessions: AuthStore) -> SecurityContext:
    try:
        context = resolve_security_context(sessions, token)
    except (sqlite3.Error, OSError):
        raise auth_unavailable() from None
    if context is None:
        raise unauthorized()
    return context


AuthenticatedContext = Annotated[SecurityContext, Depends(require_security_context)]


async def sanitized_validation_error(
    request: Request, exc: RequestValidationError,
) -> JSONResponse:
    """Do not echo input, body, or attacker-controlled field names in 422 errors."""
    return JSONResponse(status_code=422, content={"detail": "Invalid request"},
                        headers={"Cache-Control": "no-store"})
