# Function index

[← back to the README](../README.md)

Every public function in `app/`, in one place, so the same thing does not get
written three different ways.

**Read this before writing a new function.** If something here already does
the job, call it. If you genuinely need a second implementation, say so in its
`Does` column and in a comment on the function itself, *deliberately not
`<the other one>`, because `<reason>`*, so the next reader can tell a decision
from an accident.

`tests/test_function_index.py` checks that every public function has a row and
that no row names a function that has been removed. It does not check the
prose columns; those are a reviewer's job.

---

## Where to look first

| I need to… | Look at |
| --- | --- |
| Read a setting | `app/config.py`, the only module that reads `os.environ` |
| Talk to the database | `app/db.py`, `open_db` |
| Hash or check a password | `app/security.py` |
| Create, read or end a session | `app/security.py` |
| Throttle or count login failures | `app/security.py` |
| Require a login on a route | `app/dependencies.py`, `login_required` |
| Redirect after a POST, or to a `?next=` | `app/dependencies.py`, `redirect` and `safe_next` |
| Render a page | `app/dependencies.py`, `templates` |
| Add a route | `app/routes/`, one module per area |
| Run a command on the switch | `app/nxapi.py`, `NxapiClient.show` |
| Turn switch output into page data | `app/switch.py` |

---

## `app/config.py` — settings

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `load_settings` | `() -> Settings` | Reads and validates the environment; raises `ConfigError` with the fix | `main.create_app` | v0.1.0 |

`Settings` is a frozen dataclass; `ConfigError` means the app must not start.

## `app/db.py` — SQLite

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `connect` | `(db_path: Path) -> Connection` | Opens a connection with WAL and foreign keys on | `db.open_db` | v0.1.0 |
| `current_version` | `(conn) -> int` | The applied schema version, 0 for a new file | `db.migrate` | v0.1.0 |
| `init_db` | `(db_path: Path) -> int` | Creates or upgrades the database, returns its version | `main.lifespan` | v0.1.0 |
| `migrate` | `(conn) -> int` | Applies pending migrations in order | `db.init_db` | v0.1.0 |
| `open_db` | `(db_path: Path) -> Iterator[Connection]` | Context manager: one connection per unit of work, always closed | routes, `security.current_user`, `main.lifespan` | v0.1.0 |

Migrations are append-only. Editing an applied one leaves existing databases
behind.

## `app/security.py` — authentication

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `check_credentials` | `(username, password, admin_user, admin_hash) -> bool` | Checks a login in constant time whether the username or the password is wrong | `routes/auth.login_submit` | v0.1.0 |
| `clear_login_failures` | `(conn, ip: str) -> None` | Forgets an address's failures after success | `routes/auth.login_submit` | v0.1.0 |
| `client_ip` | `(request) -> str` | The peer address login throttling counts against | `routes/auth.login_submit` | v0.1.0 |
| `create_session` | `(conn, username: str, session_hours: int) -> str` | Records a session, returns its id | `routes/auth.login_submit` | v0.1.0 |
| `current_user` | `(request) -> str \| None` | Resolves the cookie to a username and slides the expiry | `dependencies.login_required`, `routes/auth.login_form` | v0.1.0 |
| `destroy_session` | `(conn, session_id: str) -> None` | Deletes a session immediately | `routes/auth.logout`, `security.get_session_user`, `security.current_user` | v0.1.0 |
| `get_session_user` | `(conn, session_id: str) -> str \| None` | Username for a live session; ends an expired one | `security.current_user` | v0.1.0 |
| `hash_password` | `(plain: str) -> str` | Argon2id hash for storage | `hashpw.main`, tests | v0.1.0 |
| `is_rate_limited` | `(conn, ip, max_attempts, window_minutes) -> bool` | True when an address has failed too often | `routes/auth.login_submit` | v0.1.0 |
| `purge_expired_sessions` | `(conn) -> int` | Deletes expired sessions | `main.lifespan` | v0.1.0 |
| `purge_old_login_attempts` | `(conn, window_minutes: int) -> int` | Drops attempts older than the window | `main.lifespan` | v0.1.0 |
| `record_login_failure` | `(conn, ip: str) -> None` | Records a failed login | `routes/auth.login_submit` | v0.1.0 |
| `sign_session_id` | `(session_id: str, secret_key: str) -> str` | Wraps a session id in a signed cookie value | `routes/auth` | v0.1.0 |
| `touch_session` | `(conn, session_id: str, session_hours: int) -> None` | Slides the expiry forward on use | `security.current_user` | v0.1.0 |
| `unsign_session_id` | `(cookie_value: str, secret_key: str) -> str \| None` | Recovers an id, None if forged | `security.current_user`, `routes/auth.logout` | v0.1.0 |
| `verify_password` | `(plain: str, stored_hash: str) -> bool` | Checks a password against its hash | `security.check_credentials`, tests | v0.1.0 |

`SESSION_COOKIE` is the cookie name. Sessions are stored server-side so logout
really invalidates rather than merely asking the browser to forget.

## `app/dependencies.py` — shared route plumbing

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `add_security_headers` | `(request, call_next) -> Response` | HTTP middleware adding `SECURITY_HEADERS` to every response | `main.create_app` | v0.1.0 |
| `login_required` | `(request) -> str` | FastAPI dependency; sends anonymous callers to `/login` | every protected route | v0.1.0 |
| `redirect` | `(url: str, status_code: int = 303) -> RedirectResponse` | Redirect, defaulting to see-other | `routes/auth` | v0.1.0 |
| `safe_next` | `(target: str) -> str` | A `?next=` destination on this site only, else `/` | `routes/auth` | v0.1.0 |

`templates` is the shared Jinja environment; `RedirectToLogin` is the
exception `login_required` raises, handled in `main.create_app`.

## `app/nxapi.py` — the NX-API client

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `build_payload` | `(commands: list[str]) -> list[dict]` | The JSON-RPC request body for running commands in order | `NxapiClient.show` | v0.1.0 |
| `error_message` | `(error) -> str` | The most specific message in a JSON-RPC error | `nxapi.parse_response` | v0.1.0 |
| `is_valid_host` | `(value: str) -> bool` | True for a bare hostname or IP, nothing attached | (switch setup, a later stage) | v0.1.0 |
| `parse_response` | `(payload, commands: list[str]) -> list[dict]` | One body per command, in request order; raises on errors | `NxapiClient.show` | v0.1.0 |
| `validate_show_command` | `(command: str) -> str` | Refuses anything but a single `show` command | `NxapiClient.show` | v0.1.0 |

`NxapiClient(target).show(*commands)` runs show commands in one request.
`SwitchTarget` holds the address and login; its `repr` never shows the
password. Errors are `NxapiUnreachable`, `NxapiAuthError`, `NxapiCommandError`
and `NxapiProtocolError`, all subclasses of `NxapiError`. The switch's
self-signed certificate is accepted on purpose.

## `app/switch.py` — switch output to page data

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `fan_speed_percent` | `(zone_speed) -> int \| None` | Fan zone speed (`"0x80"`) as a percentage | `switch.parse_environment` | v0.1.0 |
| `load_dashboard` | `(client: NxapiClient) -> Dashboard` | Everything the dashboard shows, from one request | (dashboard, a later stage) | v0.1.0 |
| `parse_environment` | `(body) -> Environment` | Temperatures, fans, power supplies from `show environment` | `switch.load_dashboard` | v0.1.0 |
| `parse_port_summary` | `(body) -> PortSummary` | Ethernet port counts from `show interface brief` | `switch.load_dashboard` | v0.1.0 |
| `parse_resources` | `(body) -> Resources` | CPU and memory use from `show system resources` | `switch.load_dashboard` | v0.1.0 |
| `parse_version` | `(body) -> SystemInfo` | Hostname, model, NX-OS version, uptime from `show version` | `switch.load_dashboard` | v0.1.0 |
| `rows` | `(body, table: str, row: str) -> list[dict]` | An NX-OS table's rows as a list, one row or many | every parser | v0.1.0 |
| `section` | `(body, key: str) -> dict` | A nested object of an NX-OS body, or `{}` | `switch.parse_environment` | v0.1.0 |
| `to_int` | `(value) -> int \| None` | A number from NX-OS text such as `"650 W"` | every parser | v0.1.0 |

NX-OS JSON holds a one-row table as an object and only a several-row table as
a list; `rows` hides that.

## `app/logging_conf.py` — application logging

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `configure_logging` | `(level: str = "INFO") -> Logger` | Sends app logs to stdout | `main.lifespan` | v0.1.0 |

## `app/main.py` — application assembly

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `create_app` | `(settings: Settings \| None = None) -> FastAPI` | Builds and wires the app | module `__getattr__`, tests | v0.1.0 |
| `lifespan` | `(app: FastAPI)` | Migrates the database and purges stale rows on start | `main.create_app` | v0.1.0 |

## `app/routes/` — HTTP endpoints

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `dashboard` | `(request, username) -> Response` | `GET /`, the landing page | router | v0.1.0 |
| `healthz` | `() -> dict[str, str]` | `GET /healthz`, unauthenticated liveness | router, container healthcheck | v0.1.0 |
| `login_form` | `(request, next: str = "/") -> Response` | `GET /login` | router | v0.1.0 |
| `login_submit` | `(request, username, password, next) -> Response` | `POST /login` | router | v0.1.0 |
| `logout` | `(request) -> Response` | `POST /logout` | router | v0.1.0 |

## `app/hashpw.py` — password hash helper

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `main` | `() -> int` | Prompts for a password, prints the env line with its hash | `python -m app.hashpw` | v0.1.0 |
