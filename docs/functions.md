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
| Add, change or check an NXray account | `app/users.py` |
| Limit a route to a role | `app/dependencies.py`, `operator_required` / `admin_required` |
| Create, read or end a session | `app/security.py` |
| Throttle or count login failures | `app/security.py` |
| Two-factor sign-in codes, backup codes, the setup QR code | `app/totp.py`; per account in `app/users.py` |
| Built-in HTTPS: the certificate and nginx's config | `app/tls.py`; started by `docker/entrypoint.sh` |
| Require a login on a route | `app/dependencies.py`, `login_required` |
| Redirect after a POST, or to a `?next=` | `app/dependencies.py`, `redirect` and `safe_next` |
| Render a page | `app/dependencies.py`, `templates` |
| Add a route | `app/routes/`, one module per area |
| Run a command on the switch | `app/nxapi.py`, `NxapiClient.show` (and the guarded config methods) |
| Get NXray's stored switch login | `app/switch_connection.py`, `load_target` |
| Check NXray can reach the switch | `app/switch_setup.py`, `check_connection` |
| Give NXray's account a new password, or make it again | `app/switch_repair.py`, `run_repair` |
| Encrypt a secret for the database | `app/crypto.py` |
| Protect a form against forgery | `app/dependencies.py`, `require_csrf`; token from `security.csrf_token` |
| Turn switch output into page data | `app/switch.py` (health), `app/ports.py` (ports) |
| Read the switch with NXray's account from a route | `dependencies.stored_switch`, then `switch_setup.read_switch` |
| Show a byte count or a bit rate | the `bytes` and `rate` template filters (`ports.human_bytes`, `ports.human_rate`) |
| Change a port on the switch | `app/nxapi.py`, `NxapiClient.configure_port` (checked by `validate_port_name`, `validate_description`) |
| Type configuration lines NX-API refuses (they contain `;`) | `app/switch_ssh.py`, `run_config` |
| Give NXray's account the port-changes role | `app/port_changes.py`, `enable_port_changes` |
| Draw the front panel, or colour a port by state, traffic, errors or VLAN | `app/face.py`, `draw_face` |
| Read or set a port's label (NXray only, never the switch) | `app/port_labels.py` |
| Record or draw history | `app/history.py` (`Sampler`, `system_charts`, `port_charts`); the SVG itself is `app/charts.py`, `line_chart` |
| Check for a newer image, or replace this container with it | `app/update.py`, `check_for_updates` / `apply_update` |

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
| `clear_login_failures` | `(conn, ip: str) -> None` | Forgets an address's failures after success | `routes/auth.login_submit` | v0.1.0 |
| `client_ip` | `(request) -> str` | The peer address login throttling counts against | `routes/auth.login_submit` | v0.1.0 |
| `create_session` | `(conn, username: str, session_hours: int) -> str` | Records a session, returns its id | `routes/auth.login_submit` | v0.1.0 |
| `csrf_token` | `(request) -> str` | This session's anti-forgery token, derived from the session id | routes rendering forms | v0.1.0 |
| `csrf_valid` | `(request, token: str) -> bool` | True when a form carries this session's token | `dependencies.require_csrf` | v0.1.0 |
| `current_user` | `(request) -> str \| None` | Resolves the cookie to a username and slides the expiry | `dependencies.login_required`, `routes/auth.login_form` | v0.1.0 |
| `destroy_session` | `(conn, session_id: str) -> None` | Deletes a session immediately | `routes/auth.logout`, `security.get_session_user` | v0.1.0 |
| `destroy_user_sessions` | `(conn, username, *, keep=None) -> int` | Signs an account out everywhere except one session | `users.set_password`, `users.set_disabled` | v0.1.0 |
| `get_session_user` | `(conn, session_id: str) -> str \| None` | Username for a live session; ends one that expired or whose account is gone or disabled | `security.current_user` | v0.1.0 |
| `hash_password` | `(plain: str) -> str` | Argon2id hash for storage | `hashpw.main`, `users.create_user`, `users.set_password` | v0.1.0 |
| `is_rate_limited` | `(conn, ip, max_attempts, window_minutes) -> bool` | True when an address has failed too often | `routes/auth.login_submit` | v0.1.0 |
| `pending_matches` | `(mark: str, password_hash: str) -> bool` | True when a pending-2FA cookie belongs to this password hash | `routes/auth` | v0.1.0 |
| `purge_expired_sessions` | `(conn) -> int` | Deletes expired sessions | `main.lifespan` | v0.1.0 |
| `purge_old_login_attempts` | `(conn, window_minutes: int) -> int` | Drops attempts older than the window | `main.lifespan` | v0.1.0 |
| `read_pending_2fa` | `(cookie_value: str, secret_key: str) -> tuple[str, str] \| None` | Name and password mark from a pending-2FA cookie; None if forged or older than 5 minutes | `routes/auth` | v0.1.0 |
| `record_login_failure` | `(conn, ip: str) -> None` | Records a failed login | `routes/auth.login_submit` | v0.1.0 |
| `session_id_from_request` | `(request) -> str \| None` | The session id in the signed cookie | `security.csrf_token`, `security.csrf_valid` | v0.1.0 |
| `sign_pending_2fa` | `(username, password_hash, secret_key) -> str` | The short-lived cookie between the password and code steps of a two-factor sign-in | `routes/auth.login_submit` | v0.1.0 |
| `sign_session_id` | `(session_id: str, secret_key: str) -> str` | Wraps a session id in a signed cookie value | `routes/auth` | v0.1.0 |
| `touch_session` | `(conn, session_id: str, session_hours: int) -> None` | Slides the expiry forward on use | `security.current_user` | v0.1.0 |
| `unsign_session_id` | `(cookie_value: str, secret_key: str) -> str \| None` | Recovers an id, None if forged | `security.current_user`, `routes/auth.logout` | v0.1.0 |
| `verify_password` | `(plain: str, stored_hash: str) -> bool` | Checks a password against its hash | `users.authenticate`, `routes/users.account_password` | v0.1.0 |

`SESSION_COOKIE` is the cookie name (`PENDING_2FA_COOKIE`, valid `PENDING_2FA_MINUTES`, the one between the two sign-in steps); `DUMMY_HASH` is what `users.authenticate`
checks a password against when there is no such account. Sessions are stored server-side so logout
really invalidates rather than merely asking the browser to forget.

## `app/dependencies.py` — shared route plumbing

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `add_security_headers` | `(request, call_next) -> Response` | HTTP middleware adding `SECURITY_HEADERS` to every response | `main.create_app` | v0.1.0 |
| `admin_required` | `(request) -> str` | FastAPI dependency for the Switch and Users pages; raises `Forbidden` for other roles | `routes/switch_page`, `routes/users` | v0.1.0 |
| `current_account` | `(request) -> User \| None` | The signed-in account, looked up once per request | the role guards, `current_role`, `routes/users` | v0.1.0 |
| `current_role` | `(request) -> str \| None` | The signed-in account's role; a template global so pages hide buttons the role can't use | templates, `main.create_app` | v0.1.0 |
| `login_required` | `(request) -> str` | FastAPI dependency; sends anonymous callers to `/login` | every protected route | v0.1.0 |
| `operator_required` | `(request) -> str` | FastAPI dependency for forms that change the switch (port, VLAN, Save config); operator or admin | `routes/ports`, `routes/vlans`, `switch_save` | v0.1.0 |
| `paused_message` | `(seconds: int) -> str` | What the pages say while NXray leaves the switch alone after a role change | `stored_switch`, Switch page | v0.1.0 |
| `redirect` | `(url: str, status_code: int = 303) -> RedirectResponse` | Redirect, defaulting to see-other | `routes/auth` | v0.1.0 |
| `stored_switch` | `(request) -> tuple[SwitchConnection \| None, SwitchTarget \| None, str \| None]` | The stored switch, its decrypted login, or why it can't be used (key changed, waiting after a role change) | dashboard, ports routes, Save config | v0.1.0 |
| `require_csrf` | `(request, token: str) -> None` | Raises `CsrfFailed` (a 403 page) unless the form carries the session's token | every state-changing POST | v0.1.0 |
| `safe_next` | `(target: str) -> str` | A `?next=` destination on this site only, else `/` | `routes/auth` | v0.1.0 |

`templates` is the shared Jinja environment; `RedirectToLogin` is the
exception `login_required` raises, `Forbidden` the one the role guards raise
(a 403 page naming the role needed) and `CsrfFailed` the one `require_csrf`
raises, all handled in `main.create_app`.

## `app/nxapi.py` — the NX-API client

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `build_payload` | `(commands: list[str]) -> list[dict]` | The JSON-RPC request body for running commands in order | `NxapiClient.show` | v0.1.0 |
| `error_message` | `(error) -> str` | The most specific message in a JSON-RPC error | `nxapi.parse_response` | v0.1.0 |
| `is_valid_host` | `(value: str) -> bool` | True for a bare hostname or IP, nothing attached | `routes/switch_page` (setup, address, repair) | v0.1.0 |
| `format_vlan_list` | `(vlans: Iterable[int]) -> str` | `[1, 10, 11, 12]` -> `1,10-12`, as the switch writes it; `[]` -> `none` | `NxapiClient.configure_port_vlans`, `vlans` | v0.1.0 |
| `parse_response` | `(payload, commands, labels=None, allow_text=False) -> list[dict]` | One body per command, in request order; raises on errors; `labels` keep passwords out of messages | `NxapiClient._send` | v0.1.0 |
| `parse_vlan_list` | `(text: str) -> list[int]` | A typed VLAN list (`10,20-30`, `all`, `none`) as numbers; refuses anything else | `vlans` | v0.1.0 |
| `validate_account_name` | `(name: str) -> str` | Refuses a switch account name NXray would not use (format, reserved names) | `NxapiClient.create_user`, `give_role`, `delete_user`, `switch_setup.run_setup`, `switch_repair.run_repair`, `port_changes.role_lines` | v0.1.0 |
| `validate_description` | `(text: str) -> str` | A port description as the switch stores it; refuses non-ASCII, `?`, `;`, over 254 characters | `NxapiClient.configure_port`, `routes/ports.port_change` | v0.1.0 |
| `validate_port_name` | `(name: str) -> str` | Refuses anything but a front-panel Ethernet port name | `NxapiClient.configure_port`, `port_changes` | v0.1.0 |
| `validate_show_command` | `(command: str) -> str` | Refuses anything but a single `show` command | `NxapiClient.show` | v0.1.0 |
| `validate_vlan_id` | `(value: int \| str) -> int` | A VLAN number 1-4094, else `ValueError` | VLAN client methods, `vlans`, `routes/vlans` | v0.1.0 |
| `validate_vlan_name` | `(name: str) -> str` | A VLAN name the switch stores: 1-32 letters, digits, `.`, `-`, `_` | `NxapiClient.configure_vlan`, `routes/vlans` | v0.1.0 |

`NxapiClient(target).show(*commands)` runs show commands in one request.
The only configuration methods are `create_user(name, password, role)`
(letters-and-digits password, role `network-operator` only),
`give_role(name, role)` (role `nxray-ports` only), `delete_user(name)`,
`configure_port(name, description=, enabled=)` (one
port's description and on/off, nothing else), `configure_vlan(vlan_id,
name=None)` (create or rename), `delete_vlan(vlan_id)` (never VLAN 1),
`configure_port_vlans(name, mode=, access_vlan=, native_vlan=,
allowed_vlans=)` (one port's mode and VLANs) and `save_config()`; each
builds its commands from checked values.
`SwitchTarget` holds the address and login; its `repr` never shows the
password. Errors are `NxapiUnreachable`, `NxapiAuthError`, `NxapiCommandError`
and `NxapiProtocolError`, all subclasses of `NxapiError`. The switch's
self-signed certificate is accepted on purpose.

## `app/switch.py` — switch output to page data

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `fan_speed_percent` | `(zone_speed) -> int \| None` | Fan zone speed (`"0x80"`) as a percentage | `switch.parse_environment` | v0.1.0 |
| `health_problems` | `(dashboard: Dashboard) -> list[str]` | Plain-words list of hot sensors and failed fans or power supplies | `routes/dashboard.dashboard` | v0.1.0 |
| `load_dashboard` | `(client: NxapiClient) -> Dashboard` | Everything the dashboard shows, from one request | `switch_setup.load_dashboard_status` | v0.1.0 |
| `parse_environment` | `(body) -> Environment` | Temperatures, fans, power supplies from `show environment` | `switch.load_dashboard` | v0.1.0 |
| `parse_port_summary` | `(body) -> PortSummary` | Ethernet port counts from `show interface brief` | `switch.load_dashboard` | v0.1.0 |
| `parse_resources` | `(body) -> Resources` | CPU and memory use from `show system resources` | `switch.load_dashboard` | v0.1.0 |
| `parse_version` | `(body) -> SystemInfo` | Hostname, model, NX-OS version, uptime from `show version` | `switch.load_dashboard` | v0.1.0 |
| `rows` | `(body, table: str, row: str) -> list[dict]` | An NX-OS table's rows as a list, one row or many | every parser | v0.1.0 |
| `section` | `(body, key: str) -> dict` | A nested object of an NX-OS body, or `{}` | `switch.parse_environment` | v0.1.0 |
| `to_int` | `(value) -> int \| None` | A number from NX-OS text such as `"650 W"` | every parser | v0.1.0 |

NX-OS JSON holds a one-row table as an object and only a several-row table as
a list; `rows` hides that.

## `app/ports.py` — the front-panel ports

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `human_bytes` | `(count: int) -> str` | `1536` -> `1.5 KB` (powers of 1024) | `bytes` template filter | v0.1.0 |
| `human_rate` | `(bits_per_second: int) -> str` | `12500000` -> `12.5 Mb/s` (powers of 1000) | `rate` template filter | v0.1.0 |
| `load_ports` | `(client: NxapiClient) -> list[Port]` | Every port, from one request of `PORTS_COMMANDS` | `routes/ports` | v0.1.0 |
| `parse_ports` | `(interface_body, status_body, transceiver_body) -> list[Port]` | Every Ethernet port in front-panel order, mgmt0 left out | `ports.load_ports` | v0.1.0 |
| `parse_transceivers` | `(body) -> dict[str, Transceiver]` | What is plugged into each port | `ports.parse_ports` | v0.1.0 |
| `port_sort_key` | `(name: str) -> tuple[int, ...]` | Sorts Ethernet1/2 before Ethernet1/10 | `ports.parse_ports` | v0.1.0 |

`Port.errors` adds up `ERROR_COUNTERS`; `COUNTER_LABELS` names the counters a
port's own page shows.

## `app/crypto.py` — secrets in the database

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `decrypt` | `(stored: str, secret_key: str) -> str` | Recovers a secret; raises `DecryptionError` for a changed key or tampering | `switch_connection.load_target` | v0.1.0 |
| `encrypt` | `(plaintext: str, secret_key: str) -> str` | AES-GCM with a key derived from the secret key | `switch_connection.save_connection`, `replace_login` | v0.1.0 |

## `app/switch_connection.py` — the stored switch

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `delete_connection` | `(conn) -> bool` | Forgets the stored login; the switch account stays | `routes/switch_page.switch_forget` | v0.1.0 |
| `get_connection` | `(conn) -> SwitchConnection \| None` | The stored connection without its password | Switch page, dashboard | v0.1.0 |
| `load_target` | `(conn, secret_key) -> SwitchTarget` | The stored login, decrypted; `LookupError` / `DecryptionError` | Switch page test, dashboard | v0.1.0 |
| `record_test_result` | `(conn, *, ok, message) -> None` | Remembers the last connection test | Switch page | v0.1.0 |
| `replace_login` | `(conn, *, host, port, password, switch_hostname, secret_key) -> None` | Stores the new password Run setup again gave the account, and the address it worked at | `routes/switch_page.switch_repair` | v0.1.0 |
| `save_connection` | `(conn, *, host, port, username, password, switch_hostname, config_saved, secret_key) -> None` | Stores the connection, password encrypted; refuses a second one | `routes/switch_page.switch_setup` | v0.1.0 |
| `set_address` | `(conn, *, host, port, switch_hostname) -> None` | Stores a new switch address NXray's account already signed in at | `routes/switch_page.switch_address` | v0.1.0 |
| `set_changes_enabled` | `(conn, *, pause_seconds, role_version) -> None` | Records that port changes are on with that role version and pauses switch calls; never shortens a running pause | `routes/switch_page.switch_enable_changes` | v0.1.0 |
| `set_changes_off` | `(conn) -> None` | Records that port changes are off (role version 0) | `routes/switch_page.switch_repair` | v0.1.0 |
| `set_config_saved` | `(conn, saved: bool) -> None` | Records whether the switch config was saved after setup or Run setup again | `routes/switch_page.switch_setup`, `switch_repair` | v0.1.0 |
| `set_unsaved_changes` | `(conn, unsaved: bool) -> None` | Remembers whether NXray changed the switch since the last Save config | `routes/ports`, `routes/vlans`, `routes/switch_page.switch_save` | v0.1.0 |

`SwitchConnection.changes_enabled` and `paused_seconds()` say whether port
changes are on and how long NXray still waits before calling the switch;
`vlan_changes_enabled` says whether the role includes the VLAN rules
(`role_version` 2 or later).

## `app/switch_setup.py` — creating NXray's account

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `account_names` | `(user_account_body) -> set[str]` | Lower-cased local account names from `show user-account` | `switch_setup.run_setup`, `switch_repair.run_repair` | v0.1.0 |
| `check_connection` | `(target, transport=None) -> ConnectionStatus` | Signs in with NXray's account and reads `show version` | Switch page Test connection | v0.1.0 |
| `connection_error` | `(exc, target) -> str` | The message for a failed call with NXray's own account, password scrubbed | `check_connection`, `read_switch` | v0.1.0 |
| `describe_error` | `(exc, host, port, who) -> str` | Plain-words message for an NX-API failure, with the fix | `run_setup`, `connection_error` | v0.1.0 |
| `load_dashboard_status` | `(target, transport=None) -> tuple[ConnectionStatus, Dashboard \| None]` | The whole dashboard from one request, or why it failed | `routes/dashboard.dashboard` | v0.1.0 |
| `read_switch` | `(target, reader, transport=None) -> tuple[ConnectionStatus, T \| None]` | Runs `reader(client)` with NXray's account; result or the failure message | `load_dashboard_status`, `routes/ports` | v0.1.0 |
| `generate_password` | `() -> str` | 32 random letters and digits that pass NX-OS's strength check | `switch_setup.run_setup`, `switch_repair.run_repair` | v0.1.0 |
| `run_setup` | `(*, host, port, admin_user, admin_password, account_name, store, transport=None) -> SetupResult` | Creates the account, checks it signs in, stores it, saves the config; undoes the account if a later step fails | `routes/switch_page.switch_setup` | v0.1.0 |
| `verify_account` | `(host, port, name, password, transport) -> None` | Signs in with a login NXray just set, retrying briefly; raises the `NxapiError` if it never works | `run_setup`, `switch_repair.run_repair` | v0.1.0 |

`SetupError` carries the message the page shows. The admin login lives only
inside `run_setup`.

## `app/switch_repair.py` — Run setup again

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `role_names` | `(role_body) -> set[str]` | Every role name in `show role` | `run_repair` | v0.1.0 |
| `run_repair` | `(*, host, port, admin_user, admin_password, account_name, port_changes, store, transport=None) -> RepairResult` | Gives NXray's account a new password (or makes it again under the same name), gives back the port-changes role if the switch still has it, checks the login, stores it, saves the config | `routes/switch_page.switch_repair` | v0.1.0 |

`RepairResult.port_role` is `ROLE_KEPT`, `ROLE_GIVEN`, `ROLE_MISSING` or
None (port changes were off); `pause_seconds` is non-zero only when an
existing account had to be given the role again. The admin login lives
only inside `run_repair`.

## `app/switch_ssh.py` — SSH, for lines NX-API refuses

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `open_paramiko_shell` | `(host, port, username, password, timeout) -> ParamikoShell` | Signs in over SSH with a password only (no local keys or agent) and opens the NX-OS command line | `run_config` (the default opener) | v0.1.0 |
| `refused` | `(output: str) -> str \| None` | The switch's complaint in a command's output, or None | `run_config` | v0.1.0 |
| `run_config` | `(*, host, port, username, password, lines, timeout, opener=None) -> None` | Types checked lines between `configure terminal` and `end`; stops at the first refusal | `port_changes.enable_port_changes` | v0.1.0 |

Errors are `SshUnreachable`, `SshAuthError` and `SshCommandError`, all
subclasses of `SshError`. The switch's host key is accepted unchecked, as its
NX-API certificate is. Tests pass a pretend opener through
`app.state.ssh_opener`.

## `app/port_changes.py` — turning on port changes

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `account_roles` | `(user_account_body, account_name) -> set[str]` | The roles `show user-account` lists for one account | `enable_port_changes`, `switch_repair.run_repair` | v0.1.0 |
| `enable_port_changes` | `(*, host, nxapi_port, ssh_port, admin_user, admin_password, account_name, transport=None, ssh_opener=None) -> EnableResult` | Creates the `nxray-ports` role over SSH, gives it to NXray's account, checks it took, saves the config | `routes/switch_page.switch_enable_changes` | v0.1.0 |
| `front_ports` | `(interface_brief_body) -> list[str]` | Every front-panel Ethernet port name | `enable_port_changes` | v0.1.0 |
| `pause_seconds` | `(nxapi_body) -> int` | NX-API's idle timeout plus a minute: how long NXray waits for the switch to apply the role | `enable_port_changes`, `switch_repair.run_repair` | v0.1.0 |
| `role_lines` | `(ports, account_name) -> list[str]` | The configuration lines for the role and for giving it to the account, from checked values | `enable_port_changes` | v0.1.0 |

`ROLE_RULES` (ports) and `VLAN_RULES` are the role's only rules; `ROLE_NAME`
is `nxray-ports`, shared by every NXray install on a switch. `ROLE_VERSION`
counts the rule sets (1 ports, 2 ports and VLANs). `EnableResult.had_role`
is true when the account already had the role, so only its rules changed and
there is no wait.

## `app/vlans.py` — VLANs

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `describe_port_vlans` | `(current, change) -> tuple[list[str], list[str]]` | A port's VLAN change in words, plus warnings (mode change, VLANs dropped, port moved) | `routes/ports.port_vlans_change` | v0.1.0 |
| `load_ports_with_vlans` | `(client) -> tuple[list[Port], VlanView]` | Everything a port's own page shows, from one request | `routes/ports` | v0.1.0 |
| `load_vlans` | `(client) -> VlanView` | The VLAN list and every port's VLAN settings, from one request | `routes/vlans` | v0.1.0 |
| `parse_switchports` | `(body) -> dict[str, PortVlans]` | Each Ethernet port's mode, access, native and carried VLANs from `show interface switchport` | `load_vlans`, `load_ports_with_vlans` | v0.1.0 |
| `parse_vlans` | `(body) -> list[Vlan]` | Every VLAN from `show vlan brief`, lowest first | `load_vlans`, `load_ports_with_vlans` | v0.1.0 |
| `plan_port_vlans` | `(current, view, *, mode, access_vlan, native_vlan, allowed) -> PortVlanChange` | Checks a port's VLAN form against the switch (VLANs must exist) and keeps only what changes | `routes/ports.port_vlans_change` | v0.1.0 |

`PortVlans.uses(vlan_id)` says whether deleting a VLAN would cut a port off
(access VLAN, native VLAN, or a trunk naming it; a trunk carrying every VLAN
does not count); `VlanView.ports_using(vlan_id)` lists those ports.

## `app/logging_conf.py` — application logging

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `configure_logging` | `(level: str = "INFO") -> Logger` | Sends app logs to stdout | `main.lifespan` | v0.1.0 |

## `app/main.py` — application assembly

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `create_app` | `(settings: Settings \| None = None) -> FastAPI` | Builds and wires the app | module `__getattr__`, tests | v0.1.0 |
| `lifespan` | `(app: FastAPI)` | Migrates the database, creates the first account from nxray.env once, purges stale rows on start | `main.create_app` | v0.1.0 |

## `app/routes/` — HTTP endpoints

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `account_page` | `(request, username) -> Response` | `GET /account`, your name, role, password form and two-factor sign-in | router | v0.1.0 |
| `account_2fa_codes` | `(request, username, csrf, current_password) -> Response` | `POST /account/2fa/codes`: ten new backup codes, needs your password | router | v0.1.0 |
| `account_2fa_confirm` | `(request, username, csrf, code) -> Response` | `POST /account/2fa/confirm`: turns two-factor on once the app's code is right, shows the backup codes once | router | v0.1.0 |
| `account_2fa_off` | `(request, username, csrf, current_password) -> Response` | `POST /account/2fa/off`: turns your own two-factor off, needs your password | router | v0.1.0 |
| `account_2fa_setup` | `(request, username, csrf) -> Response` | `POST /account/2fa/setup`: a new key and its QR code; nothing changes until confirmed | router | v0.1.0 |
| `account_password` | `(request, username, csrf, current_password, new_password, confirm_password) -> Response` | `POST /account/password`: needs the current password (throttled like sign-in), signs out your other sessions | router | v0.1.0 |
| `dashboard` | `(request, username) -> Response` | `GET /`, the switch's health read live | router | v0.1.0 |
| `change_refused` | `(exc, target) -> str` | The message for a port or VLAN change the switch did not make | `port_change`, `port_vlans_change`, `routes/vlans` | v0.1.0 |
| `change_summary` | `(port, action, description) -> tuple[str, str \| None]` | A port change in words, and a warning when turning off an up port | `port_change` | v0.1.0 |
| `healthz` | `() -> dict[str, str]` | `GET /healthz`, unauthenticated liveness | router, container healthcheck | v0.1.0 |
| `settings_certificate` | `(request, username, csrf, cert_file, key_file) -> Response` | `POST /settings/certificate`: checks and installs an uploaded certificate, admin only | router | v0.1.0 |
| `settings_page` | `(request, username) -> Response` | `GET /settings`, built-in HTTPS, its certificate and self-update, admin only | router | v0.1.0 |
| `settings_update_apply` | `(request, username, csrf) -> Response` | `POST /settings/update/apply`: refuses unless an update is waiting and none is running, then starts it | router | v0.1.0 |
| `settings_update_check` | `(request, username, csrf) -> Response` | `POST /settings/update/check`: compares ghcr.io with this container now | router | v0.1.0 |
| `settings_update_dismiss` | `(request, username, csrf) -> Response` | `POST /settings/update/dismiss`: hides the last update result | router | v0.1.0 |
| `login_2fa_form` | `(request, next: str = "/") -> Response` | `GET /login/2fa`, the code step; back to `/login` without a recent password step | router | v0.1.0 |
| `login_2fa_submit` | `(request, code, next) -> Response` | `POST /login/2fa`: an app code (once) or a backup code, throttled like sign-in | router | v0.1.0 |
| `login_form` | `(request, next: str = "/") -> Response` | `GET /login` | router | v0.1.0 |
| `login_submit` | `(request, username, password, next) -> Response` | `POST /login`; for an account with two-factor, on to `/login/2fa` without a session | router | v0.1.0 |
| `logout` | `(request) -> Response` | `POST /logout` | router | v0.1.0 |
| `port_change` | `(request, username, csrf, name, action, description, confirm) -> Response` | `POST /ports/change`: asks to confirm, then changes one port's description or on/off | router | v0.1.0 |
| `port_detail` | `(request, name, username) -> Response` | `GET /ports/detail?name=`, one port with its VLANs; 404 for an unknown name | router | v0.1.0 |
| `port_vlans_change` | `(request, username, csrf, name, mode, access_vlan, native_vlan, allowed, confirm) -> Response` | `POST /ports/vlans`: asks to confirm, then sets one port's mode and VLANs | router | v0.1.0 |
| `port_label` | `(request, username, csrf, name, label) -> Response` | `POST /ports/label`: stores or removes a port's label in NXray, operator or admin; the switch is not called to change anything | router | v0.1.0 |
| `ports_page` | `(request, username, show, color) -> Response` | `GET /ports?show=all\|up\|down\|errors&color=state\|traffic\|errors\|vlan`: the front panel and the table; only `vlan` also reads the VLAN names | router | v0.1.0 |
| `render_port_page` | `(request, username, name, *, error=None, notice=None) -> Response` | Reads the switch and shows one port's page with a message | `port_detail`, `switch_save` | v0.1.0 |
| `render_vlans_page` | `(request, username, *, error=None, notice=None) -> Response` | Reads the switch and shows the VLANs page with a message | `switch_save` | v0.1.0 |
| `switch_address` | `(request, username, csrf, host, port) -> Response` | `POST /switch/address`: signs in at the new address with NXray's account, then stores it; keeps the old one on failure | router | v0.1.0 |
| `switch_enable_changes` | `(request, username, csrf, admin_user, admin_password, ssh_port, confirm_save) -> Response` | `POST /switch/enable-changes`, the Turn on port and VLAN changes and Turn on VLAN changes buttons | router | v0.1.0 |
| `switch_forget` | `(request, username, csrf) -> Response` | `POST /switch/forget` | router | v0.1.0 |
| `switch_page` | `(request, username) -> Response` | `GET /switch`, setup form or the stored connection | router | v0.1.0 |
| `switch_repair` | `(request, username, csrf, host, port, admin_user, admin_password, confirm_save) -> Response` | `POST /switch/repair`, the Run setup again button; one switch change at a time | router | v0.1.0 |
| `switch_save` | `(request, username, csrf, back, port) -> Response` | `POST /switch/save`, the Save config button; answers on the page it was pressed on (a port's page, VLANs, else Switch) | router | v0.1.0 |
| `switch_setup` | `(request, username, csrf, host, port, admin_user, admin_password, account_name, confirm_save) -> Response` | `POST /switch/setup`, one at a time | router | v0.1.0 |
| `switch_test` | `(request, username, csrf) -> Response` | `POST /switch/test`, the Test connection button | router | v0.1.0 |
| `users_create` | `(request, username, csrf, new_username, password, confirm_password, role) -> Response` | `POST /users/create`, admin only | router | v0.1.0 |
| `users_2fa_off` | `(request, username, csrf, user_id) -> Response` | `POST /users/2fa-off`: an admin turns off someone else's two-factor, no code needed | router | v0.1.0 |
| `users_disable` | `(request, username, csrf, user_id, disabled) -> Response` | `POST /users/disable`: disables (signs out) or enables an account; not your own | router | v0.1.0 |
| `users_page` | `(request, username) -> Response` | `GET /users`, every account, admin only | router | v0.1.0 |
| `users_password` | `(request, username, csrf, user_id, new_password, confirm_password) -> Response` | `POST /users/password`: an admin sets an account's password and signs it out | router | v0.1.0 |
| `users_role` | `(request, username, csrf, user_id, role) -> Response` | `POST /users/role`; not your own, never the last active admin | router | v0.1.0 |
| `vlan_create` | `(request, username, csrf, vlan_id, name) -> Response` | `POST /vlans/create`; refuses a VLAN that exists | router | v0.1.0 |
| `vlan_delete` | `(request, username, csrf, vlan_id, confirm) -> Response` | `POST /vlans/delete`: refuses VLAN 1 and a VLAN a port uses, else asks to confirm, then deletes | router | v0.1.0 |
| `vlan_rename` | `(request, username, csrf, vlan_id, name) -> Response` | `POST /vlans/rename`; not VLAN 1 | router | v0.1.0 |
| `vlans_page` | `(request, username) -> Response` | `GET /vlans`, every VLAN and the ports using it | router | v0.1.0 |

## `app/tls.py` — built-in HTTPS

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `current_certificate` | `(tls_dir) -> CertificateInfo \| None` | The certificate nginx serves, read from disk | `routes/settings_page` | v0.1.0 |
| `ensure_certificate` | `(tls_dir) -> bool` | Makes a self-signed certificate and key (EC P-256, ten years) unless both exist | `tls.main` | v0.1.0 |
| `install_certificate` | `(tls_dir, cert_pem, key_pem) -> CertificateInfo` | Checks, stores and loads an uploaded pair; raises `CertificateError` | `routes/settings_page.settings_certificate` | v0.1.0 |
| `main` | `() -> int` | Entrypoint helper: prints `http`, or prepares the certificate and nginx's config and prints `https` | `docker/entrypoint.sh` (`python -m app.tls`) | v0.1.0 |
| `reload_nginx` | `(pid_file=NGINX_PID_FILE) -> bool` | Sends nginx SIGHUP so it loads the new certificate | `install_certificate` | v0.1.0 |
| `validate_certificate_pair` | `(cert_pem, key_pem) -> CertificateInfo` | Raises `CertificateError` unless the certificate (chain allowed) and unencrypted key match and are in date | `install_certificate` | v0.1.0 |
| `write_nginx_config` | `(https_port, tls_dir, template, target) -> None` | nginx's config from `docker/nginx.conf.template` | `tls.main` | v0.1.0 |

## `app/healthcheck.py` — the container health check

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `https_enabled` | `() -> bool` | `NXRAY_ENABLE_HTTPS` read as the app reads it | `healthcheck.main` | v0.1.0 |
| `main` | `() -> int` | 0 when `/healthz` answers, over HTTPS through nginx when that is on | Dockerfile `HEALTHCHECK` | v0.1.0 |

## `app/totp.py` — two-factor codes

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `code_at` | `(secret_b32, step) -> str` | The six-digit code for one 30-second step (tests) | tests | v0.1.0 |
| `generate_backup_codes` | `() -> list[str]` | Ten one-time codes as XXXXX-XXXXX | `users.confirm_two_factor`, `users.new_backup_codes` | v0.1.0 |
| `generate_secret` | `() -> str` | A new random base32 key | `users.begin_two_factor` | v0.1.0 |
| `hash_backup_code` | `(code) -> str` | SHA-256 of a backup code, case, spaces and dash ignored | `users` | v0.1.0 |
| `matching_step` | `(secret_b32, code, *, at=None) -> int \| None` | The step a typed code belongs to, one step either side of now | `users.confirm_two_factor`, `users.check_second_factor` | v0.1.0 |
| `provisioning_uri` | `(secret_b32, username) -> str` | The `otpauth://` text in the QR code | `routes/users` | v0.1.0 |
| `qr_svg` | `(text) -> str` | A QR code as inline `<svg>` (segno) | `routes/users` | v0.1.0 |
| `spaced_secret` | `(secret_b32) -> str` | The key in groups of four, for typing by hand | `routes/users` | v0.1.0 |
| `time_step` | `(at=None) -> int` | The 30-second step a moment falls in | `matching_step`, tests | v0.1.0 |

## `app/users.py` — NXray's own accounts

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `authenticate` | `(conn, username, password) -> User \| None` | Checks a sign-in in constant time; raises `AccountDisabled` for the right password on a disabled account | `routes/auth.login_submit` | v0.1.0 |
| `bootstrap_admin` | `(conn, admin_user, admin_password_hash) -> bool` | Makes the nxray.env account the first admin, only while there are no accounts | `main.lifespan` | v0.1.0 |
| `begin_two_factor` | `(conn, user_id, secret_key) -> str` | Stores a new two-factor key (encrypted), still off; refused while it is on | `routes/users.account_2fa_setup` | v0.1.0 |
| `check_new_password` | `(password, confirm) -> None` | Raises `UserError` unless a new password is long enough and typed twice the same | `create_user`, `routes/users`, `resetpw.main` | v0.1.0 |
| `check_second_factor` | `(conn, user, code, secret_key) -> str \| None` | `"app"` or `"backup"` for a right code, each usable once; None for wrong | `routes/auth.login_2fa_submit` | v0.1.0 |
| `confirm_two_factor` | `(conn, user_id, code, secret_key, *, keep_session=None) -> list[str] \| None` | Turns two-factor on for a right code, returns ten backup codes, signs out other sessions | `routes/users.account_2fa_confirm` | v0.1.0 |
| `create_user` | `(conn, username, password, confirm, role) -> User` | Adds an account after checking name, role and password | `routes/users.users_create` | v0.1.0 |
| `get_user` | `(conn, username) -> User \| None` | An account by name, case ignored | `dependencies.current_account`, `routes/users`, `resetpw.main` | v0.1.0 |
| `get_user_by_id` | `(conn, user_id) -> User \| None` | An account by id | `routes/users`, the setters below | v0.1.0 |
| `list_users` | `(conn) -> list[User]` | Every account, oldest first | `routes/users.users_page` | v0.1.0 |
| `new_backup_codes` | `(conn, user_id) -> list[str]` | Ten new backup codes; the old ones stop working | `routes/users.account_2fa_codes` | v0.1.0 |
| `set_disabled` | `(conn, user_id, disabled) -> User` | Disables (and signs out) or enables an account; keeps the last active admin | `routes/users.users_disable`, `resetpw.main` | v0.1.0 |
| `set_password` | `(conn, user_id, password, *, keep_session=None) -> None` | Stores a new password and signs the account out everywhere but `keep_session` | `routes/users`, `resetpw.main` | v0.1.0 |
| `set_role` | `(conn, user_id, role) -> User` | Changes an account's role; keeps the last active admin | `routes/users.users_role` | v0.1.0 |
| `turn_off_two_factor` | `(conn, user_id) -> User` | Turns two-factor off and forgets the key and backup codes | `routes/users`, `resetpw.main` | v0.1.0 |
| `two_factor_secret` | `(user, secret_key) -> str \| None` | The key in plain text, None if missing or unreadable | `users.check_second_factor`, `routes/users.account_2fa_confirm` | v0.1.0 |

`ROLES` is the three roles, `ROLE_HELP` says what each may do in words, and
`User.can_change` / `User.is_admin` are what the route guards test.
`User.backup_codes_left` is how many unused backup codes an account has.

## `app/resetpw.py` — password reset from the command line

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `main` | `(argv=None) -> int` | Prompts for a new password for a named account, stores it, enables the account; with `--2fa-off`, turns off its two-factor instead | `python -m app.resetpw [--2fa-off] <username>` | v0.1.0 |

## `app/hashpw.py` — password hash helper

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `main` | `() -> int` | Prompts for a password, prints the env line with its hash | `python -m app.hashpw` | v0.1.0 |

## `app/update.py` — self-update

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `apply_update` | `(db_path) -> str \| None` | Marks an update running, starts the throwaway container that pulls and recreates, and watches it on a thread; an error text or `None` | `routes/settings_page.settings_update_apply` | v0.1.0 |
| `check_for_updates` | `(conn, *, dev_build=False) -> str` | Compares ghcr.io's digest for this container's tag with what runs; `"available"`, `"current"` or why nothing was compared | `routes/settings_page.settings_update_check`, `start_background_checker` | v0.1.0 |
| `clear_result` | `(conn) -> None` | Forgets the last update result | `routes/settings_page.settings_update_dismiss` | v0.1.0 |
| `current_state` | `(conn) -> UpdateState` | The update row, with an old success hidden | `routes/settings_page`, `watch_update` | v0.1.0 |
| `deployed_digests` | `(image_id) -> set[str] \| None` | Registry digests of the image the container runs; `None` for an image built locally | `check_for_updates` | v0.1.0 |
| `deployment` | `() -> Deployment \| None` | Asks Docker what this container was made from and which compose project owns it | `check_for_updates`, `start_update` | v0.1.0 |
| `finish_pending_update` | `(conn) -> None` | At start: an update still running means this is its replacement, so record success | `main.lifespan` | v0.1.0 |
| `ghcr_digest` | `(tag) -> str \| None` | The digest ghcr.io has for a tag; `None` on any failure | `check_for_updates` | v0.1.0 |
| `own_container` | `() -> str` | The name Docker knows this container by (its hostname) | `deployment` | v0.1.0 |
| `reap_stalled_update` | `(conn) -> None` | Fails an update that never replaced the container | `routes/settings_page` | v0.1.0 |
| `start_background_checker` | `(settings) -> None` | Checks once a day on a thread; does nothing with self-update off | `main.lifespan` | v0.1.0 |
| `start_update` | `(conn) -> str \| None` | Refuses an image or container compose did not make, else marks the update running and launches the recreator | `apply_update` | v0.1.0 |
| `watch_update` | `(db_path) -> None` | Waits for the recreator; records a failure (or a no-op success) if this container is still alive | `apply_update` | v0.1.0 |

## `app/history.py` — history

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `bucket_seconds` | `(span: int) -> int` | How wide one chart point is: a minute at least, and at most 500 points | `system_charts`, `port_charts` | v0.1.0 |
| `build_rows` | `(environment, resources, ports, previous_errors) -> (rows, error_totals)` | The rows one sample stores; a port's errors as the increase since the last sample | `Sampler.sample_once` | v0.1.0 |
| `fill_zeros` | `(points, start, end, bucket) -> list` | Every bucket of a range, 0 where there is no point | `port_charts` | v0.1.0 |
| `last_sample_time` | `(conn) -> float \| None` | When the newest row was stored | `routes/history.history_page` | v0.1.0 |
| `port_charts` | `(conn, port, key, now) -> list[ChartView]` | One port's traffic and errors charts for a range | `routes/ports._render_port` | v0.1.0 |
| `purge` | `(conn, now, keep_days=30) -> int` | Deletes rows older than the retention; how many went | `start_sampler` | v0.1.0 |
| `range_key` | `(value) -> str` | A valid `?range=` name; the default for anything else | `routes/history`, `routes/ports` | v0.1.0 |
| `read_series` | `(conn, metric, *, start, end, bucket, item=None, total=False) -> dict` | A metric's rows averaged (or added up) into buckets, by item | `system_charts`, `port_charts` | v0.1.0 |
| `record` | `(conn, moment, rows) -> None` | Stores one sample's rows | `Sampler.sample_once` | v0.1.0 |
| `start_sampler` | `(settings, transport) -> Event \| None` | Samples on a thread every `NXRAY_HISTORY_INTERVAL` seconds, purging hourly; `None` when history is off | `main.lifespan` | v0.1.0 |
| `system_charts` | `(conn, key, now) -> list[ChartView]` | The History page's charts for a range | `routes/history.history_page` | v0.1.0 |

## `app/charts.py` — SVG line charts

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `line_chart` | `(lines, *, start, end, bucket, fmt, zero_based=True, y_max=None, label="") -> Markup` | Draws lines over a time range as inline SVG, breaking a line where samples are missing | `history._chart` | v0.1.0 |
| `nice_ticks` | `(low, high, target=5) -> list[float]` | Round axis values covering a range | `line_chart` | v0.1.0 |
| `time_label` | `(moment, step) -> str` | An axis label: the clock time, or the date for a midnight or labels a day apart (UTC) | `line_chart` | v0.1.0 |
| `time_ticks` | `(start, end) -> (list[float], int)` | Round UTC times to label an axis (at most seven) and the step between them | `line_chart` | v0.1.0 |

## `app/face.py` — the front-panel picture

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `color_mode` | `(value) -> str` | A valid `?color=` name; `state` for anything else | `draw_face`, `routes/ports.ports_page` | v0.1.0 |
| `draw_face` | `(ports, mode, labels=None, vlan_names=None) -> Face` | The front panel as inline SVG (each port a link with a tooltip) and a legend with a count per colour | `routes/ports.ports_page` | v0.1.0 |
| `panel_layout` | `(ports) -> tuple[list[Cage], float, float]` | Where each port sits: pairs with the odd port on top, SFP cages in blocks of six pairs, then QSFP cages (40 Gb/s or more, or broken out); plus width and height | `draw_face` | v0.1.0 |
| `port_colour` | `(port, mode, colours, vlan_names=None) -> tuple[str, str]` | A port's CSS classes and legend words in one colour mode | `draw_face` | v0.1.0 |
| `tooltip` | `(port, label="", vlan_names=None) -> str` | What hovering over a port shows, one fact per line | `draw_face` | v0.1.0 |
| `vlan_colours` | `(ports) -> dict[str, int]` | A colour number (0-7, repeating) per access VLAN in use, lowest first | `draw_face` | v0.1.0 |

The colours are CSS classes (`f-up`, `f-t2`, `f-vlan s3`, ...) in
`static/style.css`; the SVG carries no inline style, so the strict
Content-Security-Policy holds.

## `app/port_labels.py` — port labels

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `get_labels` | `(conn) -> dict[str, str]` | Every port's label, by port name | `routes/ports` | v0.1.0 |
| `set_label` | `(conn, port, label, username) -> str` | Checks and stores a label (empty removes it); returns what was stored | `routes/ports.port_label` | v0.1.0 |
| `validate_label` | `(text: str) -> str` | Trims a label; refuses over 64 characters or control characters (any other text is fine, the switch never sees it) | `set_label` | v0.1.0 |

## `app/routes/history.py` — the History page

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `history_page` | `(request, username, period) -> Response` | `GET /history`: the charts for the chosen range, from the database only | the router | v0.1.0 |
