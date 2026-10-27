"""Set a new password for an NXray account from the command line.

For when nobody who can reset it can sign in any more (the only admin forgot
their password). Run it in the running container:

    docker compose exec nxray python -m app.resetpw <username>

It asks for the new password twice, stores it, enables the account if it was
disabled, and signs it out everywhere. The password is read from a prompt, not
an argument, so it stays out of shell history and the process list.

Changing NXRAY_ADMIN_PASSWORD_HASH in nxray.env does NOT do this: that line
only creates the first account, on the very first start.
"""

from __future__ import annotations

import getpass
import sys

from app.config import ConfigError, load_settings
from app.db import init_db, open_db
from app.users import UserError, check_new_password, get_user, set_disabled, set_password


def main(argv: list[str] | None = None) -> int:
    """Prompt for a new password for the named account and store it."""
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: python -m app.resetpw <username>", file=sys.stderr)
        return 2
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"NXray's settings are not usable: {exc}", file=sys.stderr)
        return 1
    init_db(settings.db_path)

    with open_db(settings.db_path) as conn:
        user = get_user(conn, args[0])
        if user is None:
            print(f"There is no NXray account called {args[0]}.", file=sys.stderr)
            return 1

        if sys.stdin.isatty():
            password = getpass.getpass(f"New password for {user.username}: ")
            confirm = getpass.getpass("Repeat the password: ")
        else:
            # Allows: printf '%s\n' 'secret' | python -m app.resetpw name
            password = sys.stdin.readline().rstrip("\n")
            confirm = password
        try:
            check_new_password(password, confirm)
        except UserError as exc:
            print(str(exc), file=sys.stderr)
            return 1

        set_password(conn, user.id, password)
        if user.disabled:
            set_disabled(conn, user.id, False)

    enabled = " It was disabled and is enabled again." if user.disabled else ""
    print(f"New password set for {user.username} ({user.role}).{enabled}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
