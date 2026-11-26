import pytest
from backend.security.auth.passwords import hash_password, verify_password

PASSWORD = "synthetic-password-for-test"


def test_argon2id_random_salts_and_verification():
    first, second = hash_password(PASSWORD), hash_password(PASSWORD)
    assert first.startswith("$argon2id$")
    assert first != second
    assert PASSWORD not in first
    assert verify_password(PASSWORD, first)
    assert verify_password(PASSWORD, second)
    assert not verify_password("incorrect", first)


@pytest.mark.parametrize("value", ["", "short", "x" * 1025, None, "\ud800"])
def test_invalid_password_rejected(value):
    with pytest.raises(ValueError):
        hash_password(value)
    assert not verify_password(value, "invalid")


@pytest.mark.parametrize("bad_hash", ["plaintext", "$argon2id$bad", "$argon2i$bad", None])
def test_invalid_hash_rejected(bad_hash):
    assert not verify_password(PASSWORD, bad_hash)
