"""Login, logout and minimal identity projection using existing auth services."""
import sqlite3
from typing import Literal

from fastapi import APIRouter, Response
from pydantic import BaseModel, ConfigDict, Field

from .http import AuthenticatedContext, AuthStore, BearerToken, auth_unavailable, unauthorized
from .passwords import MAX_PASSWORD_BYTES
from .users import Role

router = APIRouter(prefix="/api/auth", tags=["authentication"])


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_BYTES, repr=False)


class LoginResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


class IdentityResponse(BaseModel):
    username: str
    role: Role


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, response: Response, sessions: AuthStore) -> LoginResponse:
    try:
        token = sessions.login(body.username, body.password)
    except (sqlite3.Error, OSError):
        raise auth_unavailable() from None
    if token is None:
        raise unauthorized("Invalid credentials")
    response.headers["Cache-Control"] = "no-store"
    return LoginResponse(access_token=token, expires_in=sessions.ttl)


@router.get("/me", response_model=IdentityResponse)
def me(response: Response, context: AuthenticatedContext) -> IdentityResponse:
    response.headers["Cache-Control"] = "no-store"
    return IdentityResponse(username=context.username, role=context.role)


@router.post("/logout", status_code=204, response_class=Response)
def logout(token: BearerToken, sessions: AuthStore, context: AuthenticatedContext) -> Response:
    # The context dependency validates the active session before revocation.
    # The service atomically revokes only the session corresponding to this token.
    try:
        revoked = sessions.logout(token)
    except (sqlite3.Error, OSError):
        raise auth_unavailable() from None
    if not revoked:
        raise unauthorized()
    return Response(status_code=204, headers={"Cache-Control": "no-store"})
