"""Switch accounts for NXray users (admin only): the Users page's switch side.

Each change here signs in with the switch admin login typed on the form, used
for that one request and never stored or logged, and saves the switch
configuration afterwards. See app/switch_accounts.py.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import (
    admin_required,
    current_account,
    note_activity,
    require_csrf,
    templates,
)
from app.nxapi import PERSON_ROLES
from app.security import csrf_token, session_id_from_request
from app.switch_accounts import (
    ROLE_MAP_WORDS,
    AccountChange,
    AccountLink,
    SwitchAccount,
    SwitchAccountError,
    bring_roles_in_step,
    check_switch_name,
    check_switch_side_password,
    create_on_switch,
    get_link,
    guard_account,
    list_links,
    load_switch_accounts,
    lock_password,
    out_of_step,
    remove_link,
    reserved,
    run_as_admin,
    save_link,
    save_words,
    switch_roles,
    update_link,
)
from app.switch_connection import (
    DecryptionError,
    SwitchConnection,
    get_connection,
    list_connections,
    load_target,
)
from app.switch_setup import read_switch
from app.users import (
    MIN_PASSWORD_LENGTH,
    ROLE_HELP,
    User,
    UserError,
    check_new_password,
    get_user_by_id,
    set_password,
)

router = APIRouter()
log = logging.getLogger("nxray.users")


def read_accounts(
    request: Request, connection: SwitchConnection
) -> tuple[list[SwitchAccount] | None, str | None]:
    """The switch's local accounts, read with NXray's own account, or why not."""
    if connection.paused_seconds():
        return None, "NXray is waiting for the switch to apply a new role; try again shortly."
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        try:
            target = load_target(conn, connection.id, settings.secret_key)
        except (LookupError, DecryptionError):
            return None, "NXray cannot read its stored login for this switch."
    status, accounts = read_switch(
        target, load_switch_accounts, transport=request.app.state.nxapi_transport
    )
    return accounts, None if accounts is not None else status.message


def _user_id(raw: str) -> int:
    try:
        return int(raw)
    except ValueError:
        return 0


def render_user_switch(
    request: Request,
    username: str,
    user_id: int,
    *,
    error: str | None = None,
    notice: str | None = None,
    status_code: int = 200,
) -> Response:
    """One NXray user's accounts on every switch, with the forms that change them."""
    with open_db(request.app.state.settings.db_path) as conn:
        user = get_user_by_id(conn, user_id)
        connections = list_connections(conn)
        links = {link.switch_id: link for link in list_links(conn, user_id=user_id)}
        taken = {
            (link.switch_id, link.account_name.lower())
            for link in list_links(conn)
            if link.user_id != user_id
        }
    if user is None:
        status_code = 404
    switches = []
    for connection in connections if user else []:
        link = links.get(connection.id)
        accounts, read_error = read_accounts(request, connection)
        linkable = [
            account
            for account in accounts or []
            if account.name.lower() != connection.username.lower()
            and not reserved(account.name)
            and (connection.id, account.name.lower()) not in taken
        ]
        switches.append(
            {
                "connection": connection,
                "link": link,
                "problems": out_of_step(user, link, connection) if link and user else [],
                "roles": switch_roles(user.role, connection.changes_enabled) if user else (),
                "role_out": link is not None
                and user is not None
                and set(switch_roles(user.role, connection.changes_enabled))
                != {role for role in link.roles if role in PERSON_ROLES},
                "accounts": accounts,
                "linkable": linkable,
                "read_error": read_error,
                "on_switch": link is not None
                and accounts is not None
                and any(a.name == link.account_name for a in accounts),
            }
        )
    return templates.TemplateResponse(
        request,
        "users_switch.html",
        {
            "username": username,
            "user": user,
            "switches": switches,
            "role_help": ROLE_HELP,
            "role_map": ROLE_MAP_WORDS,
            "min_password": MIN_PASSWORD_LENGTH,
            "error": error,
            "notice": notice,
            "csrf_token": csrf_token(request),
        },
        status_code=status_code,
    )


@router.get("/users/switch", response_class=HTMLResponse)
def user_switch_page(
    request: Request, user_id: str = "", username: str = Depends(admin_required)
) -> Response:
    return render_user_switch(request, username, _user_id(user_id))


def _load(
    request: Request, user_id: str, switch_id: str
) -> tuple[User | None, SwitchConnection | None, AccountLink | None]:
    with open_db(request.app.state.settings.db_path) as conn:
        user = get_user_by_id(conn, _user_id(user_id))
        connection = get_connection(conn, _user_id(switch_id))
        link = get_link(conn, user.id, connection.id) if user and connection else None
    return user, connection, link


def _done(request: Request, username: str, user: User, words: str, change, connection) -> Response:
    return render_user_switch(
        request, username, user.id, notice=f"Done: {words} {save_words(change, connection)}"
    )


@router.post("/users/switch/create", response_class=HTMLResponse)
def user_switch_create(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    user_id: str = Form(""),
    switch_id: str = Form(""),
    password: str = Form(""),
    confirm_password: str = Form(""),
    admin_user: str = Form(""),
    admin_password: str = Form(""),
    confirm_roles: str = Form(""),
) -> Response:
    """Make an account on one switch for an existing NXray user.

    NXray keeps no plain password, so the password typed here becomes the
    user's NXray password too: both sides are then in step.
    """
    require_csrf(request, csrf)
    user, connection, link = _load(request, user_id, switch_id)
    if user is None or connection is None:
        return render_user_switch(
            request, username, _user_id(user_id), error="No such user or switch.", status_code=400
        )

    def refuse(message: str) -> Response:
        return render_user_switch(request, username, user.id, error=message, status_code=400)

    if link is not None:
        return refuse(f"{user.username} already has an account on {connection.label}.")
    roles = switch_roles(user.role, connection.changes_enabled)
    try:
        name = check_switch_name(user.username)
        guard_account(name, connection)
        check_new_password(password, confirm_password)
        check_switch_side_password(password)
    except (ValueError, UserError) as exc:
        return refuse(f"Not made: {exc}.".replace("..", "."))
    if confirm_roles != "yes":
        return refuse(
            f"Not made: tick the box to confirm the account {name} on {connection.label} "
            f"with the role {' + '.join(roles)}."
        )
    try:
        change = run_as_admin(
            connection,
            admin_user,
            admin_password,
            lambda client: create_on_switch(client, name, password, roles),
            secrets=(password,),
            transport=request.app.state.nxapi_transport,
        )
    except SwitchAccountError as exc:
        return refuse(f"Not made on {connection.label}: {exc}")
    with open_db(request.app.state.settings.db_path) as conn:
        set_password(conn, user.id, password, keep_session=own_session(request, user))
        save_link(conn, user.id, connection.id, name, roles, password_set=True)
    log.info("%s made the switch account %s on %s", username, name, connection.host)
    note_activity(
        request,
        username,
        "Users",
        f"Made the switch account {name} ({' + '.join(roles)}) for {user.username}",
        connection.host,
    )
    return _done(
        request,
        username,
        user,
        f"{user.username} now has the account {name} on {connection.label} with the role "
        f"{' + '.join(roles)}, and the password typed here for NXray and the switch.",
        change,
        connection,
    )


@router.post("/users/switch/link", response_class=HTMLResponse)
def user_switch_link(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    user_id: str = Form(""),
    switch_id: str = Form(""),
    account_name: str = Form(""),
) -> Response:
    """Link an account that is already on the switch to an NXray user. Changes
    nothing on the switch; its password and role show as out of step until set."""
    require_csrf(request, csrf)
    user, connection, link = _load(request, user_id, switch_id)
    if user is None or connection is None:
        return render_user_switch(
            request, username, _user_id(user_id), error="No such user or switch.", status_code=400
        )

    def refuse(message: str) -> Response:
        return render_user_switch(request, username, user.id, error=message, status_code=400)

    if link is not None:
        return refuse(f"{user.username} already has an account on {connection.label}.")
    accounts, read_error = read_accounts(request, connection)
    if accounts is None:
        return refuse(f"Not linked: {read_error}")
    account = next((a for a in accounts if a.name == account_name), None)
    if account is None:
        return refuse(f"Not linked: {connection.label} has no account called {account_name!r}.")
    try:
        guard_account(account.name, connection)
        with open_db(request.app.state.settings.db_path) as conn:
            save_link(conn, user.id, connection.id, account.name, account.roles, password_set=False)
    except ValueError as exc:
        return refuse(f"Not linked: {exc}.")
    log.info("%s linked %s on %s to %s", username, account.name, connection.host, user.username)
    note_activity(
        request,
        username,
        "Users",
        f"Linked the switch account {account.name} to {user.username}",
        connection.host,
    )
    return render_user_switch(
        request,
        username,
        user.id,
        notice=(
            f"Linked {account.name} on {connection.label} to {user.username}. Nothing changed on "
            "the switch. Set a new password below to bring the passwords in step."
        ),
    )


@router.post("/users/switch/password", response_class=HTMLResponse)
def user_switch_password(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    user_id: str = Form(""),
    password: str = Form(""),
    confirm_password: str = Form(""),
    admin_user: str = Form(""),
    admin_password: str = Form(""),
) -> Response:
    """One new password for NXray and every switch account of the user.

    Both sides' rules are checked before anything is sent. Each switch is
    changed in turn, then NXray; a switch that refuses stays out of step and
    the page says which. A locked switch account is opened again by this.
    """
    require_csrf(request, csrf)
    with open_db(request.app.state.settings.db_path) as conn:
        user = get_user_by_id(conn, _user_id(user_id))
        links = list_links(conn, user_id=user.id) if user else []
        connections = {c.id: c for c in list_connections(conn)}
    if user is None:
        return render_user_switch(
            request, username, 0, error="That account no longer exists.", status_code=400
        )
    try:
        check_new_password(password, confirm_password)
    except UserError as exc:
        return render_user_switch(request, username, user.id, error=str(exc), status_code=400)
    try:
        check_switch_side_password(password)
    except ValueError as exc:
        return render_user_switch(
            request,
            username,
            user.id,
            error=f"Not changed: NXray takes this password, but {exc}.",
            status_code=400,
        )
    done: list[tuple[AccountLink, SwitchConnection, AccountChange]] = []
    failed: list[str] = []
    for link in links:
        connection = connections.get(link.switch_id)
        if connection is None:
            continue
        try:
            guard_account(link.account_name, connection)
            change = run_as_admin(
                connection,
                admin_user,
                admin_password,
                lambda client, name=link.account_name: client.set_person_password(name, password),
                secrets=(password,),
                transport=request.app.state.nxapi_transport,
            )
        except (SwitchAccountError, ValueError) as exc:
            failed.append(f"{connection.label}: not changed, {exc}")
            continue
        done.append((link, connection, change))
    with open_db(request.app.state.settings.db_path) as conn:
        set_password(conn, user.id, password, keep_session=own_session(request, user))
        for link, _, _ in done:
            update_link(conn, user.id, link.switch_id, password_set=True, locked=False)
    log.info(
        "%s set a new password for %s and %d switch account(s)", username, user.username, len(done)
    )
    note_activity(
        request,
        username,
        "Users",
        f"Set a new password for {user.username} in NXray and on "
        + (", ".join(c.label for _, c, _ in done) or "no switch"),
    )
    parts = [f"New password set for {user.username} in NXray; it was signed out everywhere."]
    for link, connection, change in done:
        parts.append(
            f"{link.account_name} on {connection.label} has it too. "
            + save_words(change, connection)
        )
    if failed:
        parts.append("Out of step: " + " ".join(failed))
        return render_user_switch(
            request, username, user.id, error=" ".join(parts), status_code=400
        )
    return render_user_switch(request, username, user.id, notice=" ".join(parts))


def _one_switch_change(
    request: Request,
    username: str,
    user_id: str,
    switch_id: str,
    admin_user: str,
    admin_password: str,
    act,
) -> Response:
    """Run ``act(user, connection, link)`` -> (change function, done words, after)
    for a linked account; ``after(conn)`` records it once the switch made it."""
    user, connection, link = _load(request, user_id, switch_id)
    if user is None or connection is None or link is None:
        return render_user_switch(
            request,
            username,
            _user_id(user_id),
            error="That user has no account on that switch.",
            status_code=400,
        )
    try:
        guard_account(link.account_name, connection)
        change_fn, words, after = act(user, connection, link)
        change = run_as_admin(
            connection,
            admin_user,
            admin_password,
            change_fn,
            transport=request.app.state.nxapi_transport,
        )
    except (SwitchAccountError, ValueError) as exc:
        return render_user_switch(
            request,
            username,
            user.id,
            error=f"Not changed on {connection.label}: {exc}",
            status_code=400,
        )
    with open_db(request.app.state.settings.db_path) as conn:
        after(conn)
    log.info("%s: %s", username, words)
    note_activity(request, username, "Users", words, connection.host)
    return _done(request, username, user, words, change, connection)


@router.post("/users/switch/roles", response_class=HTMLResponse)
def user_switch_roles(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    user_id: str = Form(""),
    switch_id: str = Form(""),
    admin_user: str = Form(""),
    admin_password: str = Form(""),
) -> Response:
    """Give a switch account the role its NXray user's role maps to."""
    require_csrf(request, csrf)
    result: dict[str, tuple[str, ...]] = {}

    def act(user: User, connection: SwitchConnection, link: AccountLink):
        wanted = switch_roles(user.role, connection.changes_enabled)

        def change(client) -> None:
            result["roles"] = bring_roles_in_step(client, link.account_name, wanted)

        words = (
            f"{link.account_name} on {connection.label} has the role {' + '.join(wanted)}, "
            f"as an NXray {user.role}."
        )

        def after(conn) -> None:
            update_link(conn, user.id, connection.id, roles=result.get("roles", wanted))

        return change, words, after

    return _one_switch_change(
        request, username, user_id, switch_id, admin_user, admin_password, act
    )


@router.post("/users/switch/lock", response_class=HTMLResponse)
def user_switch_lock(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    user_id: str = Form(""),
    switch_id: str = Form(""),
    admin_user: str = Form(""),
    admin_password: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Lock a switch account: a random password nobody sees. A new password opens it."""
    require_csrf(request, csrf)
    if confirm != "yes":
        return render_user_switch(
            request,
            username,
            _user_id(user_id),
            error="Not locked: tick the box to confirm.",
            status_code=400,
        )

    def act(user: User, connection: SwitchConnection, link: AccountLink):
        secret = lock_password()
        words = (
            f"Locked {link.account_name} on {connection.label}: it has a random password "
            "nobody knows. SSH sessions already open stay open until they end."
        )
        return (
            lambda client: client.set_person_password(link.account_name, secret),
            words,
            lambda conn: update_link(conn, user.id, connection.id, locked=True),
        )

    return _one_switch_change(
        request, username, user_id, switch_id, admin_user, admin_password, act
    )


@router.post("/users/switch/remove", response_class=HTMLResponse)
def user_switch_remove(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    user_id: str = Form(""),
    switch_id: str = Form(""),
    admin_user: str = Form(""),
    admin_password: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Remove the account from the switch, and the link. The NXray user stays."""
    require_csrf(request, csrf)
    if confirm != "yes":
        return render_user_switch(
            request,
            username,
            _user_id(user_id),
            error="Not removed: tick the box to confirm.",
            status_code=400,
        )

    def act(user: User, connection: SwitchConnection, link: AccountLink):
        words = f"Removed the account {link.account_name} from {connection.label}."
        return (
            lambda client: client.remove_person_account(link.account_name),
            words,
            lambda conn: remove_link(conn, user.id, connection.id),
        )

    return _one_switch_change(
        request, username, user_id, switch_id, admin_user, admin_password, act
    )


@router.post("/users/switch/unlink", response_class=HTMLResponse)
def user_switch_unlink(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    user_id: str = Form(""),
    switch_id: str = Form(""),
) -> Response:
    """Forget which switch account belongs to the user; the switch is not touched."""
    require_csrf(request, csrf)
    user, connection, link = _load(request, user_id, switch_id)
    if user is None or connection is None or link is None:
        return render_user_switch(
            request,
            username,
            _user_id(user_id),
            error="That user has no account on that switch.",
            status_code=400,
        )
    with open_db(request.app.state.settings.db_path) as conn:
        remove_link(conn, user.id, connection.id)
    note_activity(
        request,
        username,
        "Users",
        f"Unlinked the switch account {link.account_name} from {user.username}",
        connection.host,
    )
    return render_user_switch(
        request,
        username,
        user.id,
        notice=(
            f"NXray no longer links {link.account_name} on {connection.label} to "
            f"{user.username}. The account is still on the switch, unchanged."
        ),
    )


def create_with_switches(
    request: Request,
    username: str,
    user: User,
    password: str,
    switch_ids: list[int],
    admin_user: str,
    admin_password: str,
) -> tuple[list[str], list[str]]:
    """After an NXray user was added with "NXray and the switch": make its account
    on each chosen switch. Returns (what was made, what was not and why)."""
    with open_db(request.app.state.settings.db_path) as conn:
        connections = [c for c in list_connections(conn) if c.id in switch_ids]
    made: list[str] = []
    failed: list[str] = []
    name = check_switch_name(user.username)
    for connection in connections:
        roles = switch_roles(user.role, connection.changes_enabled)
        try:
            guard_account(name, connection)
            change = run_as_admin(
                connection,
                admin_user,
                admin_password,
                lambda client, r=roles: create_on_switch(client, name, password, r),
                secrets=(password,),
                transport=request.app.state.nxapi_transport,
            )
        except (SwitchAccountError, ValueError) as exc:
            failed.append(f"{connection.label}: not made, {exc}")
            continue
        with open_db(request.app.state.settings.db_path) as conn:
            save_link(conn, user.id, connection.id, name, roles, password_set=True)
        made.append(
            f"{name} on {connection.label} ({' + '.join(roles)}). {save_words(change, connection)}"
        )
        note_activity(
            request,
            username,
            "Users",
            f"Made the switch account {name} ({' + '.join(roles)}) for {user.username}",
            connection.host,
        )
    return made, failed


def own_session(request: Request, target: User) -> str | None:
    """This session's id when the target is the signed-in account, so a new
    password leaves it signed in."""
    account = current_account(request)
    if account is not None and target.id == account.id:
        return session_id_from_request(request)
    return None


def switch_ids(values: list[str] | None) -> list[int]:
    """The ticked switches of the Add an account form, as ids."""
    return sorted({_user_id(value) for value in values or [] if _user_id(value)})
