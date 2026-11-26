"""Password hashing and verification using the Argon2id implementation."""
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

# OWASP minimum Argon2id profile; tune on the deployment hardware.
_HASHER = PasswordHasher(time_cost=2, memory_cost=19 * 1024, parallelism=1,
                         hash_len=32, salt_len=16, type=Type.ID)
MAX_PASSWORD_BYTES = 1024
MIN_PASSWORD_LENGTH = 15


def valid_password_input(password: object) -> bool:
    if not isinstance(password, str) or not password:
        return False
    try:
        return len(password.encode("utf-8")) <= MAX_PASSWORD_BYTES
    except UnicodeEncodeError:
        return False


def hash_password(password: str) -> str:
    """Hash a new password; the library generates a fresh random salt."""
    if not valid_password_input(password) or len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError("Password must have at least 15 characters and at most 1024 UTF-8 bytes")
    return _HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Reject malformed or non-Argon2id hashes and incorrect passwords."""
    if not valid_password_input(password) or not isinstance(password_hash, str):
        return False
    if not password_hash.startswith("$argon2id$"):
        return False
    try:
        return _HASHER.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False
