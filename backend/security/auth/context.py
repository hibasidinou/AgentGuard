"""Trusted request-scoped security context (AG-65)."""
from dataclasses import dataclass, field

from .sessions import SessionStore
from .users import Role


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Immutable identity snapshot for trusted backend components."""

    user_id: int
    username: str
    role: Role
    session_id: str = field(repr=False)

    @property
    def actor_id(self) -> str:
        """Application identity compatible with existing contracts."""
        return self.username


def resolve_security_context(
    sessions: SessionStore, token: object
) -> SecurityContext | None:
    """Validate through the server-owned store; storage errors propagate."""
    session = sessions.validate(token)
    if session is None:
        return None
    return SecurityContext(
        user_id=session.user.id,
        username=session.user.username,
        role=session.user.role,
        session_id=session.session_id,
    )
