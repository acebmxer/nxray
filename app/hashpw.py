"""Generate an Argon2id hash for NXRAY_ADMIN_PASSWORD_HASH.

Run it as:

    docker compose run --rm nxray python -m app.hashpw

The password is read from a prompt rather than an argument so it does not end
up in shell history or in the process list.
"""

from __future__ import annotations

import getpass
import sys

from app.security import hash_password

MIN_LENGTH = 8


def main() -> int:
    """Prompt for a password and print the env line holding its hash."""
    if sys.stdin.isatty():
        password = getpass.getpass("Password for the NXray admin user: ")
        confirm = getpass.getpass("Repeat the password: ")
        if password != confirm:
            print("Passwords do not match.", file=sys.stderr)
            return 1
    else:
        # Allows: echo 'secret' | python -m app.hashpw
        password = sys.stdin.readline().rstrip("\n")

    if not password:
        print("Password must not be empty.", file=sys.stderr)
        return 1
    if len(password) < MIN_LENGTH:
        print(f"Password must be at least {MIN_LENGTH} characters.", file=sys.stderr)
        return 1

    print()
    print("Add this line to your nxray.env file:")
    print()
    print(f"NXRAY_ADMIN_PASSWORD_HASH={hash_password(password)}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
