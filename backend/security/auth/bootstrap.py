"""Explicit local provisioning: python -m backend.security.auth.bootstrap."""
from getpass import GetPassWarning, getpass
import sys
import warnings
import sqlite3

from argon2.exceptions import HashingError

from .users import UserConfigurationError, UserStore


def main() -> int:
    store = UserStore()
    try:
        store.initialize()
        missing = store.missing_demo_users()
        if not missing:
            print("Demo accounts already initialized; no changes.")
            return 0
        passwords = {}
        with warnings.catch_warnings():
            # Refuse input if the terminal cannot hide the password.
            warnings.simplefilter("error", GetPassWarning)
            for username in missing:
                password = getpass(f"New password for {username}: ")
                if password != getpass(f"Confirm password for {username}: "):
                    print("Password confirmation mismatch; no accounts changed.", file=sys.stderr)
                    return 1
                passwords[username] = password
        created = store.seed_demo_users(passwords)
        print("Created: " + (", ".join(created) or "none"))
        return 0
    except (UserConfigurationError, ValueError, GetPassWarning, EOFError, KeyboardInterrupt, OSError, sqlite3.Error, HashingError):
        print("Initialization failed; check configuration, password requirements and terminal access.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
