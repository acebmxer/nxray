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
| Turn switch output into page data | `app/switch.py` (health), `app/ports.py` (ports), `app/neighbors.py` (neighbors and tables) |
| Read the switch with NXray's account from a route | `dependencies.stored_switch`, then `switch_setup.read_switch` |
| Show a byte count or a bit rate | the `bytes` and `rate` template filters (`ports.human_bytes`, `ports.human_rate`) |
| Change a port on the switch | `app/nxapi.py`, `NxapiClient.configure_port` (checked by `validate_port_name`, `validate_description`) |
| Read or change a port's speed, MTU, FEC, flow control, storm control, layer, or split it | `app/port_settings.py` (`plan_port_settings`, `plan_breakout`); commands from `NxapiClient.configure_port_settings`, `breakout_port`, `join_port` |
| Type configuration lines NX-API refuses (they contain `;`) | `app/switch_ssh.py`, `run_config` |
| Give NXray's account the port-changes role | `app/port_changes.py`, `enable_port_changes` |
| Draw the front panel, or colour a port by state, traffic, errors or VLAN | `app/face.py`, `draw_face` |
| Read CDP and LLDP neighbors, the MAC address table, ARP, or what is plugged into a port | `app/neighbors.py`, `load_neighbors` and `NeighborView.for_port` |
| Write a MAC address, or name the maker it belongs to | `app/oui.py`, `format_mac` and `mac_maker` |
| Turn CDP or LLDP on or off on a port, set the MAC aging time, add or remove a static MAC address, clear learned ones | `app/neighbor_changes.py` (`plan_port_discovery`, `plan_mac_aging`, `plan_static_mac`, `plan_static_removal`, `plan_clear`); commands from `NxapiClient.set_port_discovery`, `set_mac_aging`, `add_static_mac`, `remove_static_mac`, `clear_learned_macs` |
| Read port-channels and LACP, or make, change and delete them | `app/port_channels.py` (`load_channels`; `plan_create`, `plan_add`, `plan_remove`, `plan_delete`, `plan_channel_settings`, `plan_port_lacp`, `plan_system_priority`); commands from `NxapiClient.join_port_channel`, `leave_port_channel`, `delete_port_channel`, `configure_port_channel`, `set_port_lacp`, `set_lacp_system_priority` |
| Read VLAN interfaces and routed ports with their IPv4 and IPv6 addresses, or make, change and delete them | `app/routing.py` (`load_routing`; `plan_create_vlan_interface`, `plan_vlan_interface_settings`, `plan_delete_vlan_interface`, `plan_add_address`, `plan_remove_address`); commands from `NxapiClient.configure_vlan_interface`, `delete_vlan_interface`, `set_interface_addresses` |
| List the switch's features, or turn one on or off | `app/features.py`, `load_features` and `Feature.refusal`; the command from `NxapiClient.set_feature` |
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
| `breakout_numbers` | `(name: str) -> tuple[int, int]` | Module and port of a port or split port: Ethernet1/50/2 gives (1, 50) | `NxapiClient.breakout_port`, `join_port` | v0.1.0 |
| `build_payload` | `(commands: list[str]) -> list[dict]` | The JSON-RPC request body for running commands in order | `NxapiClient.show` | v0.1.0 |
| `error_message` | `(error) -> str` | The most specific message in a JSON-RPC error | `nxapi.parse_response` | v0.1.0 |
| `is_valid_host` | `(value: str) -> bool` | True for a bare hostname or IP, nothing attached | `routes/switch_page` (setup, address, repair) | v0.1.0 |
| `format_vlan_list` | `(vlans: Iterable[int]) -> str` | `[1, 10, 11, 12]` -> `1,10-12`, as the switch writes it; `[]` -> `none` | `NxapiClient.configure_port_vlans`, `vlans` | v0.1.0 |
| `parse_response` | `(payload, commands, labels=None, allow_text=False) -> list[dict]` | One body per command, in request order; raises on errors; `labels` keep passwords out of messages | `NxapiClient._send` | v0.1.0 |
| `parse_vlan_list` | `(text: str) -> list[int]` | A typed VLAN list (`10,20-30`, `all`, `none`) as numbers; refuses anything else | `vlans` | v0.1.0 |
| `validate_channel_number` | `(value: int \| str) -> int` | A port-channel number 1-4096, else `ValueError` | port-channel client methods, `port_channels` | v0.1.0 |
| `validate_account_name` | `(name: str) -> str` | Refuses a switch account name NXray would not use (format, reserved names) | `NxapiClient.create_user`, `give_role`, `delete_user`, `switch_setup.run_setup`, `switch_repair.run_repair`, `port_changes.role_lines` | v0.1.0 |
| `validate_device_mac` | `(text: str) -> str` | One device's MAC address in any common form, written as the switch writes it (`0200.0000.0001`); refuses multicast, broadcast and all-zero | `NxapiClient.add_static_mac`, `remove_static_mac`, `clear_learned_macs`, `neighbor_changes` | v0.1.0 |
| `validate_description` | `(text: str) -> str` | A port description as the switch stores it; refuses non-ASCII, `?`, `;`, over 254 characters | `NxapiClient.configure_port`, `routes/ports.port_change` | v0.1.0 |
| `validate_mac_aging` | `(value: int \| str) -> int` | A MAC address aging time: 0 (never forget) or 120 to 918000 seconds in steps of 5, as the switch takes it | `NxapiClient.set_mac_aging`, `neighbor_changes.plan_mac_aging` | v0.1.0 |
| `validate_port_name` | `(name: str) -> str` | Refuses anything but a front-panel Ethernet port name | `NxapiClient.configure_port`, `port_changes` | v0.1.0 |
| `validate_lacp_priority` | `(value: int \| str) -> int` | An LACP priority (the switch's or a port's) 1-65535, else `ValueError` | `NxapiClient.set_port_lacp`, `set_lacp_system_priority`, `port_channels` | v0.1.0 |
| `validate_min_links` | `(value: int \| str) -> int` | A port-channel's LACP minimum links 1-32, else `ValueError` | `NxapiClient.configure_port_channel`, `port_channels.plan_channel_settings` | v0.1.0 |
| `address_line` | `(address: str, secondary: bool = False) -> str` | The interface line that puts an address on (`ip address A [secondary]`, `ipv6 address A`); its `no` form takes it off | `NxapiClient.configure_vlan_interface`, `set_interface_addresses`, `configure_port_settings` | v0.1.0 |
| `validate_interface_address` | `(text: str) -> str` | An IPv4 or IPv6 address with its prefix, checked by `validate_ip_interface` or `validate_ipv6_interface` | `address_line`, `routing` | v0.1.0 |
| `validate_ipv6_interface` | `(text: str) -> str` | An IPv6 address with its prefix (`2001:db8::1/64`), written short; refuses link-local (the switch makes its own), multicast, loopback and unspecified | `validate_interface_address`, `routing` | v0.1.0 |
| `validate_routed_interface` | `(name: str) -> str` | A name an address can go on: `Vlan1`-`Vlan4094`, a front port or a port-channel; never mgmt0 | `NxapiClient.set_interface_addresses`, `routing` | v0.1.0 |
| `validate_ip_interface` | `(text: str) -> str` | An IPv4 address with its prefix length a port can have (`192.0.2.1/24`); refuses the network and broadcast address | `NxapiClient.configure_port_settings`, `port_settings.plan_port_settings` | v0.1.0 |
| `validate_show_command` | `(command: str) -> str` | Refuses anything but a single `show` command | `NxapiClient.show` | v0.1.0 |
| `validate_storm_level` | `(value) -> str` | A storm-control level 0-100 with up to two decimals, written as the switch writes it (`10.00`) | `NxapiClient.configure_port_settings`, `port_settings` | v0.1.0 |
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
allowed_vlans=)` (one port's mode and VLANs), `configure_port_settings(name,
layer=, remove_ip=, ip_address=, speed=, mtu=, fec=, flow_receive=,
flow_send=, storm_levels=, storm_action=, old_storm_action=)` (one port's
settings, only the ones given), `breakout_port(name, mapping)` and
`join_port(name, mapping)` (split a 100G port into four, or join them;
`10g-4x` or `25g-4x` only), `set_feature(command, enabled)` (`feature X` or
`no feature X` for a name in `FEATURE_COMMANDS`; never `no feature nxapi` or
`no feature ssh`), `set_port_discovery(name, cdp=, lldp_transmit=,
lldp_receive=)` (CDP and LLDP on one port, only the ones given),
`set_mac_aging(seconds)`, `add_static_mac(mac, vlan, port)` and
`remove_static_mac(mac, vlan, port)` (on a front port, or `drop` when `port`
is None), `clear_learned_macs(port=, vlan=, mac=)` (everything, one port, one
VLAN or one address; not a configuration change), `join_port_channel(number,
ports, mode, fast_rate=, description=)` (ports into a port-channel, which the
switch creates when needed; `active`, `passive` or `on`), `leave_port_channel(port)`,
`delete_port_channel(number)`, `configure_port_channel(number, description=,
min_links=)`, `set_port_lacp(port, rate=, priority=)`,
`set_lacp_system_priority(priority)`, `configure_vlan_interface(vlan,
description=, mtu=, enabled=, remove=, add=)` (make or change one VLAN
interface: addresses off, addresses on, description, MTU, on/off last),
`delete_vlan_interface(vlan)` (never VLAN 1), `set_interface_addresses(name,
remove=, add=)` (IPv4 and IPv6 addresses on a VLAN interface or routed port)
and `save_config()`; each builds its
commands from checked values.
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
| `set_changes_enabled` | `(conn, *, pause_seconds, role_version, vlan_interfaces=None) -> None` | Records that port changes are on with that role version, and whether its port list names the VLAN interfaces (None keeps it), and pauses switch calls; never shortens a running pause | `routes/switch_page.switch_enable_changes` | v0.1.0 |
| `set_changes_off` | `(conn) -> None` | Records that port changes are off (role version 0) | `routes/switch_page.switch_repair` | v0.1.0 |
| `set_config_saved` | `(conn, saved: bool) -> None` | Records whether the switch config was saved after setup or Run setup again | `routes/switch_page.switch_setup`, `switch_repair` | v0.1.0 |
| `set_unsaved_changes` | `(conn, unsaved: bool) -> None` | Remembers whether NXray changed the switch since the last Save config | `routes/ports`, `routes/vlans`, `routes/features`, `routes/neighbors`, `routes/port_channels`, `routes/switch_page.switch_save` | v0.1.0 |

`SwitchConnection.changes_enabled` and `paused_seconds()` say whether port
changes are on and how long NXray still waits before calling the switch;
`vlan_changes_enabled` says whether the role includes the VLAN rules
(`role_version` 2 or later), `settings_changes_enabled`,
`feature_changes_enabled`, `neighbor_changes_enabled`,
`channel_changes_enabled` and `layer3_changes_enabled` the later rule sets
(3, 4, 5, 6 and 7). `vlan_interface_changes_enabled` also needs
`role_vlan_interfaces`: the role's port list names the VLAN interfaces, which
the switch takes only while interface-vlan is on.

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
| `run_commands` | `(*, host, port, username, password, lines, timeout, opener=None) -> list[str]` | Types fixed commands outside configuration mode and returns their output | `port_changes.enable_port_changes` (saving over SSH) | v0.1.0 |
| `run_config` | `(*, host, port, username, password, lines, timeout, opener=None, then=()) -> list[str]` | Types checked lines between `configure terminal` and `end`, stopping at the first refusal, then the fixed `then` commands in the same session, returning their output | `port_changes.enable_port_changes` | v0.1.0 |

Errors are `SshUnreachable`, `SshAuthError` and `SshCommandError`, all
subclasses of `SshError`. The switch's host key is accepted unchecked, as its
NX-API certificate is. Tests pass a pretend opener through
`app.state.ssh_opener`.

## `app/port_changes.py` — turning on port changes

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `account_roles` | `(user_account_body, account_name) -> set[str]` | The roles `show user-account` lists for one account | `enable_port_changes`, `switch_repair.run_repair` | v0.1.0 |
| `enable_port_changes` | `(*, host, nxapi_port, ssh_port, admin_user, admin_password, account_name, role_version=0, vlan_interfaces_listed=False, transport=None, ssh_opener=None) -> EnableResult` | Creates the `nxray-ports` role over SSH, gives it to NXray's account, checks it took, saves the config; reads `show feature` and names the VLAN interfaces only while interface-vlan is on; when the port list gains a line (`role_version` below 7, or the VLAN interfaces for the first time) the check and save go over SSH, which does not depend on NX-API answering | `routes/switch_page.switch_enable_changes` | v0.1.0 |
| `front_ports` | `(interface_brief_body) -> list[str]` | Every front-panel Ethernet port name | `enable_port_changes` | v0.1.0 |
| `pause_seconds` | `(nxapi_body) -> int` | NX-API's idle timeout plus a minute: how long NXray waits for the switch to apply the role | `enable_port_changes`, `switch_repair.run_repair` | v0.1.0 |
| `missing_changes` | `(role_version: int) -> str` | The kinds of change a role of that version lacks, in words (`neighbor and port-channel changes`); `""` when none | `routes/switch_page` (button names, notices) | v0.1.0 |
| `role_lines` | `(ports, account_name, vlan_interfaces=True) -> list[str]` | The configuration lines for the role and for giving it to the account, from checked values; the VLAN interfaces' port-list line only with `vlan_interfaces` (the switch refuses it while interface-vlan is off) | `enable_port_changes` | v0.1.0 |

`ROLE_RULES` (ports), `VLAN_RULES`, `SETTINGS_RULES`, `FEATURE_RULES`,
`NEIGHBOR_RULES`, `CHANNEL_RULES` and `LAYER3_RULES` are the role's only
rules, and its port list names the front ports one by one plus every
port-channel (`CHANNEL_PERMIT`) and every VLAN interface
(`VLAN_INTERFACE_PERMIT`); `ROLE_NAME` is `nxray-ports`, shared by every NXray
install on a switch. `ROLE_VERSION` counts the rule sets (1 ports, 2 ports and
VLANs, 3 also port settings, 4 also features, 5 also CDP and LLDP per port and
the MAC address table, 6 also port-channels and LACP, 7 also VLAN interfaces
and IPv4 and IPv6 addresses, with `VLAN_INTERFACE_PERMIT` in the port list). `EnableResult.had_role`
is true when the account already had the role, so only its rules changed and
the switch applies them at once and there is no wait.

## `app/features.py` — switch features

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `feature_states` | `(body) -> dict[str, bool]` | Every feature name in `show feature` and whether any instance of it is on | `parse_features` | v0.1.0 |
| `lacp_channels` | `(channel_body) -> list[str]` | Port-channels running LACP, with their ports, from `show port-channel summary` | `parse_features` | v0.1.0 |
| `load_features` | `(client) -> FeatureView` | The Features page, from one request of `FEATURE_COMMANDS_TO_READ` | `routes/features` | v0.1.0 |
| `parse_features` | `(feature_body, channel_body, brief_body) -> FeatureView` | Every feature with its command, group, description, state and what uses it; the NX-SDK app slots as one line | `load_features` | v0.1.0 |
| `vlan_interfaces` | `(brief_body) -> list[str]` | VLAN interfaces (`Vlan10`) in `show interface brief` | `parse_features` | v0.1.0 |

`CATALOG` maps the name `show feature` uses (`sshServer`) to the command
(`ssh`), a group and a description. `Feature.refusal(turn_on)` says why NXray
will not make a change: no feature command on this switch, NX-API or SSH
(`KEEP_ON`), or something still using it (`used_by`: LACP port-channels, VLAN
interfaces). `ON_WARNINGS` and `OFF_WARNING` go on the confirm page.

## `app/vlans.py` — VLANs

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `describe_port_vlans` | `(current, change) -> tuple[list[str], list[str]]` | A port's VLAN change in words, plus warnings (mode change, VLANs dropped, port moved) | `routes/ports.port_vlans_change` | v0.1.0 |
| `load_ports_with_vlans` | `(client) -> tuple[list[Port], VlanView]` | Everything a port's own page shows, from one request | `routes/ports` | v0.1.0 |
| `load_vlan_page` | `(client) -> VlanView` | Like `load_vlans`, plus which VLANs have a VLAN interface (`VlanView.interfaces`), in the same request | `routes/vlans` | v0.1.0 |
| `load_vlans` | `(client) -> VlanView` | The VLAN list and every port's VLAN settings, from one request | `routes/neighbors` | v0.1.0 |
| `parse_switchports` | `(body) -> dict[str, PortVlans]` | Each Ethernet port's mode, access, native and carried VLANs from `show interface switchport` | `load_vlans`, `load_ports_with_vlans` | v0.1.0 |
| `parse_vlans` | `(body) -> list[Vlan]` | Every VLAN from `show vlan brief`, lowest first | `load_vlans`, `load_ports_with_vlans` | v0.1.0 |
| `plan_port_vlans` | `(current, view, *, mode, access_vlan, native_vlan, allowed) -> PortVlanChange` | Checks a port's VLAN form against the switch (VLANs must exist) and keeps only what changes | `routes/ports.port_vlans_change` | v0.1.0 |
| `vlan_interface_ids` | `(brief_body) -> frozenset[int]` | The VLANs that have a VLAN interface, from `show interface brief` | `load_vlan_page` | v0.1.0 |

`PortVlans.uses(vlan_id)` says whether deleting a VLAN would cut a port off
(access VLAN, native VLAN, or a trunk naming it; a trunk carrying every VLAN
does not count); `VlanView.ports_using(vlan_id)` lists those ports.

## `app/port_settings.py` — port settings and breakout

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `describe_port_settings` | `(current, change, *, up) -> tuple[list[str], list[str]]` | A port's settings change in words, plus warnings (link drops, layer change, smaller MTU, shutdown action) | `routes/ports.port_settings_change` | v0.1.0 |
| `guess_breakout_map` | `(sibling_speeds: list[str]) -> str \| None` | The split four ports were made with (`10g-4x`, `25g-4x`) from their speed column, or None | `routes/ports` | v0.1.0 |
| `load_port_settings` | `(client, port, vlans) -> PortSettings` | One port's settings, from one request of `settings_commands` | `try_load_port_settings` | v0.1.0 |
| `parse_ip_addresses` | `(body) -> dict[str, tuple[str, str]]` | Each port's IPv4 address with prefix, and its VRF, from `show ip interface vrf all` | `parse_port_settings` | v0.1.0 |
| `parse_port_settings` | `(port, vlans, capabilities_body, flowcontrol_body, storm_body, ip_body, ipv6_body=None) -> PortSettings` | One port's speed, duplex, MTU, FEC, flow control, storm control, layer, addresses (main and extra IPv4, IPv6) and breakout | `load_port_settings` | v0.1.0 |
| `plan_breakout` | `(settings, action, mapping) -> BreakoutPlan` | Checks a split or join against the port, with its lines and warnings for the confirm page | `routes/ports.port_breakout` | v0.1.0 |
| `plan_port_settings` | `(current, form) -> SettingsChange` | Checks the settings form against the port (speeds it can run, MTU for its layer, FEC, levels) and keeps only what changes | `routes/ports.port_settings_change` | v0.1.0 |
| `settings_commands` | `(name: str) -> tuple[str, ...]` | The per-port show commands a port's settings need | `load_port_settings` | v0.1.0 |
| `speed_label` | `(mbps: str) -> str` | `10000` -> `10 Gb/s`, `auto` -> `Auto` | `describe_port_settings`, port page | v0.1.0 |
| `speed_mbps` | `(text: str) -> str` | The switch's speed words as the `speed` command takes them: `10G` -> `10000` | `parse_port_settings`, `guess_breakout_map` | v0.1.0 |
| `try_load_port_settings` | `(client, port, vlans) -> PortSettings \| None` | Like `load_port_settings`, None when the switch refuses a command | `routes/ports` | v0.1.0 |

NXray's account may not read the running configuration, so the settings come
from show commands. While a port is up the switch reports the speed it runs
at, which may come from Auto; the form starts from that, so leaving it alone
sends nothing. A switched port's MTU is 1500 or 9216 (`system jumbomtu`).

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
| `change_refused` | `(exc, target) -> str` | The message for a port, VLAN or settings change the switch did not make; a port the role does not name points to Update the port list | `port_change`, `port_vlans_change`, `port_settings_change`, `port_breakout`, `port_discovery_change`, `routes/vlans`, `routes/features`, `routes/neighbors` | v0.1.0 |
| `change_summary` | `(port, action, description) -> tuple[str, str \| None]` | A port change in words, and a warning when turning off an up port | `port_change` | v0.1.0 |
| `feature_set` | `(request, username, csrf, name, state, confirm) -> Response` | `POST /features/set`: asks to confirm, then turns one feature on or off; admin only; refuses what `Feature.refusal` names | router | v0.1.0 |
| `features_page` | `(request, username) -> Response` | `GET /features`: every switch feature by group with its state, read live; every role looks, admins change | router | v0.1.0 |
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
| `learned_macs_clear` | `(request, username, csrf, scope, port, vlan, mac, back, confirm) -> Response` | `POST /neighbors/clear`: asks to confirm, then clears learned addresses (all, one port, one VLAN or one address); `back=port` answers on that port's page | router | v0.1.0 |
| `mac_aging_change` | `(request, username, csrf, aging, confirm) -> Response` | `POST /neighbors/aging`: asks to confirm, then sets how long learned addresses are kept | router | v0.1.0 |
| `neighbors_page` | `(request, username, q) -> Response` | `GET /neighbors?q=`: CDP and LLDP neighbors, the MAC address table (narrowed by the search), static addresses and ARP, read live; every role; operators and admins also get the MAC table's change forms | router | v0.1.0 |
| `channel_add` | `(request, username, csrf, number, port, mode, fast_rate, confirm) -> Response` | `POST /port-channels/add`: asks to confirm, then puts a free port into a port-channel, joining the way its ports did | router | v0.1.0 |
| `channel_create` | `(request, username, csrf, number, ports, mode, fast_rate, description, confirm) -> Response` | `POST /port-channels/create`: asks to confirm, then makes a port-channel from free ports | router | v0.1.0 |
| `channel_delete` | `(request, username, csrf, number, confirm) -> Response` | `POST /port-channels/delete`: refuses a port-channel that still has ports (naming them), else asks to confirm and deletes it | router | v0.1.0 |
| `channel_remove` | `(request, username, csrf, port, confirm) -> Response` | `POST /port-channels/remove`: asks to confirm, then takes a port out of its port-channel | router | v0.1.0 |
| `channel_settings` | `(request, username, csrf, number, description, min_links, confirm) -> Response` | `POST /port-channels/settings`: asks to confirm, then sets a port-channel's description and LACP minimum links | router | v0.1.0 |
| `port_channels_page` | `(request, username) -> Response` | `GET /port-channels`: every port-channel with its ports, how they joined, their LACP rate and priority and the device at the other end, read live; operators and admins change them | router | v0.1.0 |
| `port_lacp` | `(request, username, csrf, port, rate, priority, confirm) -> Response` | `POST /port-channels/port-lacp`: asks to confirm, then sets one member's LACP rate and port priority; a rate change only while the port is off | router | v0.1.0 |
| `render_port_channels_page` | `(request, username, *, error=None, notice=None) -> Response` | Reads the switch and shows the Port-channels page with a message | `switch_save` | v0.1.0 |
| `system_priority` | `(request, username, csrf, priority, confirm) -> Response` | `POST /port-channels/system-priority`: asks to confirm, then sets the switch's LACP priority | router | v0.1.0 |
| `port_breakout` | `(request, username, csrf, name, action, mapping, confirm) -> Response` | `POST /ports/breakout`: asks to confirm, then splits a 100G port into four or joins them, and shows the port that replaced it | router | v0.1.0 |
| `port_change` | `(request, username, csrf, name, action, description, confirm) -> Response` | `POST /ports/change`: asks to confirm, then changes one port's description or on/off | router | v0.1.0 |
| `port_discovery_change` | `(request, username, csrf, name, cdp, lldp_transmit, lldp_receive, lldp_shown, confirm) -> Response` | `POST /ports/discovery`: asks to confirm, then turns CDP and LLDP sending and listening on or off on one port; an unticked box means off | router | v0.1.0 |
| `port_detail` | `(request, name, username) -> Response` | `GET /ports/detail?name=`, one port with its VLANs, settings and connected devices; 404 for an unknown name | router | v0.1.0 |
| `port_settings_change` | `(request, username, csrf, name, layer, ip_address, speed, mtu, fec, flow_receive, flow_send, storm_broadcast, storm_multicast, storm_unicast, storm_action, confirm) -> Response` | `POST /ports/settings`: asks to confirm, then sends only the settings that change | router | v0.1.0 |
| `port_vlans_change` | `(request, username, csrf, name, mode, access_vlan, native_vlan, allowed, confirm) -> Response` | `POST /ports/vlans`: asks to confirm, then sets one port's mode and VLANs | router | v0.1.0 |
| `port_label` | `(request, username, csrf, name, label) -> Response` | `POST /ports/label`: stores or removes a port's label in NXray, operator or admin; the switch is not called to change anything | router | v0.1.0 |
| `ports_page` | `(request, username, show, color) -> Response` | `GET /ports?show=all\|up\|down\|errors&color=state\|traffic\|errors\|vlan`: the front panel and the table; only `vlan` also reads the VLAN names; every mode reads the neighbors and MAC address table for the tooltips | router | v0.1.0 |
| `render_port_page` | `(request, username, name, *, error=None, notice=None) -> Response` | Reads the switch and shows one port's page with a message | `port_detail`, `switch_save` | v0.1.0 |
| `render_neighbors_page` | `(request, username, *, error=None, notice=None) -> Response` | Reads the switch and shows the Neighbors page with a message | `switch_save` | v0.1.0 |
| `render_features_page` | `(request, username, *, error=None, notice=None) -> Response` | Reads the switch and shows the Features page with a message | `switch_save` | v0.1.0 |
| `render_routing_page` | `(request, username, *, error=None, notice=None) -> Response` | Reads the switch and shows the Routing page with a message | `switch_save` | v0.1.0 |
| `routing_page` | `(request, username) -> Response` | `GET /routing?vlan=`: VLAN interfaces and routed ports with their addresses, read live; every role looks, operators and admins change; `vlan` picks that VLAN in the make form | router | v0.1.0 |
| `vlan_interface_create` | `(request, username, csrf, vlan, ipv4, ipv6, description, mtu, enabled, confirm) -> Response` | `POST /routing/vlan-interface/create`: asks to confirm, then makes a VLAN interface for a VLAN that has none | router | v0.1.0 |
| `vlan_interface_delete` | `(request, username, csrf, vlan, confirm) -> Response` | `POST /routing/vlan-interface/delete`: asks to confirm, then deletes a VLAN interface (never Vlan1); the VLAN stays | router | v0.1.0 |
| `vlan_interface_settings` | `(request, username, csrf, vlan, ipv4, description, mtu, state, confirm) -> Response` | `POST /routing/vlan-interface/settings`: asks to confirm, then sets a VLAN interface's main IPv4 address, description, MTU and on/off | router | v0.1.0 |
| `address_add` | `(request, username, csrf, name, address, confirm) -> Response` | `POST /routing/address/add`: asks to confirm, then puts an IPv4 (main or extra) or IPv6 address on a VLAN interface or routed port | router | v0.1.0 |
| `address_remove` | `(request, username, csrf, name, address, confirm) -> Response` | `POST /routing/address/remove`: asks to confirm, then takes one address off; the main IPv4 address only once the extra ones are gone | router | v0.1.0 |
| `render_vlans_page` | `(request, username, *, error=None, notice=None) -> Response` | Reads the switch and shows the VLANs page with a message | `switch_save` | v0.1.0 |
| `switch_address` | `(request, username, csrf, host, port) -> Response` | `POST /switch/address`: signs in at the new address with NXray's account, then stores it; keeps the old one on failure | router | v0.1.0 |
| `switch_enable_changes` | `(request, username, csrf, admin_user, admin_password, ssh_port, confirm_save) -> Response` | `POST /switch/enable-changes`, the Turn on port, VLAN, port settings, feature and neighbor changes button, the Turn on button for whatever an older role lacks (for example Turn on neighbor changes), and Update the port list | router | v0.1.0 |
| `switch_forget` | `(request, username, csrf) -> Response` | `POST /switch/forget` | router | v0.1.0 |
| `switch_page` | `(request, username) -> Response` | `GET /switch`, setup form or the stored connection | router | v0.1.0 |
| `switch_repair` | `(request, username, csrf, host, port, admin_user, admin_password, confirm_save) -> Response` | `POST /switch/repair`, the Run setup again button; one switch change at a time | router | v0.1.0 |
| `switch_save` | `(request, username, csrf, back, port) -> Response` | `POST /switch/save`, the Save config button; answers on the page it was pressed on (a port's page, VLANs, Features, Neighbors, Port-channels, Routing, else Switch) | router | v0.1.0 |
| `switch_setup` | `(request, username, csrf, host, port, admin_user, admin_password, account_name, confirm_save) -> Response` | `POST /switch/setup`, one at a time | router | v0.1.0 |
| `switch_test` | `(request, username, csrf) -> Response` | `POST /switch/test`, the Test connection button | router | v0.1.0 |
| `users_create` | `(request, username, csrf, new_username, password, confirm_password, role) -> Response` | `POST /users/create`, admin only | router | v0.1.0 |
| `users_2fa_off` | `(request, username, csrf, user_id) -> Response` | `POST /users/2fa-off`: an admin turns off someone else's two-factor, no code needed | router | v0.1.0 |
| `users_disable` | `(request, username, csrf, user_id, disabled) -> Response` | `POST /users/disable`: disables (signs out) or enables an account; not your own | router | v0.1.0 |
| `users_page` | `(request, username) -> Response` | `GET /users`, every account, admin only | router | v0.1.0 |
| `users_password` | `(request, username, csrf, user_id, new_password, confirm_password) -> Response` | `POST /users/password`: an admin sets an account's password and signs it out | router | v0.1.0 |
| `users_role` | `(request, username, csrf, user_id, role) -> Response` | `POST /users/role`; not your own, never the last active admin | router | v0.1.0 |
| `static_mac_add` | `(request, username, csrf, mac, vlan, where, confirm) -> Response` | `POST /neighbors/static`: asks to confirm, then adds a static MAC address on a front port or dropped | router | v0.1.0 |
| `static_mac_remove` | `(request, username, csrf, mac, vlan, confirm) -> Response` | `POST /neighbors/static/remove`: asks to confirm, then removes a static entry the table shows | router | v0.1.0 |
| `vlan_create` | `(request, username, csrf, vlan_id, name) -> Response` | `POST /vlans/create`; refuses a VLAN that exists | router | v0.1.0 |
| `vlan_delete` | `(request, username, csrf, vlan_id, confirm) -> Response` | `POST /vlans/delete`: refuses VLAN 1, a VLAN with a VLAN interface and a VLAN a port uses, else asks to confirm, then deletes | router | v0.1.0 |
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
| `device_lines` | `(devices: PortDevices) -> list[str]` | The tooltip lines for what is plugged into a port: neighbors, its port-channel, then up to three learned addresses with their makers | `tooltip` | v0.1.0 |
| `draw_face` | `(ports, mode, labels=None, vlan_names=None, neighbors=None) -> Face` | The front panel as inline SVG (each port a link with a tooltip, which with `neighbors` says what is plugged in) and a legend with a count per colour | `routes/ports.ports_page` | v0.1.0 |
| `panel_layout` | `(ports) -> tuple[list[Cage], float, float]` | Where each port sits: pairs with the odd port on top, SFP cages in blocks of six pairs, then QSFP cages (40 Gb/s or more, or broken out); plus width and height | `draw_face` | v0.1.0 |
| `port_colour` | `(port, mode, colours, vlan_names=None) -> tuple[str, str]` | A port's CSS classes and legend words in one colour mode | `draw_face` | v0.1.0 |
| `tooltip` | `(port, label="", vlan_names=None, devices=None) -> str` | What hovering over a port shows, one fact per line | `draw_face` | v0.1.0 |
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

## `app/neighbors.py` — neighbors, the MAC address table and ARP

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `cdp_enabled` | `(body) -> bool` | Whether CDP is on for the whole switch, from `show cdp global` | `load_neighbors`, `parse_neighbor_view` | v0.1.0 |
| `feature_enabled` | `(body, name: str) -> bool` | Whether `show feature` lists a feature as enabled | `load_neighbors`, `parse_neighbor_view` | v0.1.0 |
| `filter_macs` | `(macs, query: str) -> list[MacEntry]` | The MAC table entries matching a search: a VLAN number, a port (any spelling), part of a MAC address (any form) or of a maker's name | `routes/neighbors.neighbors_page` | v0.1.0 |
| `load_neighbors` | `(client) -> NeighborView` | The tables from one request of `NEIGHBOR_COMMANDS`, then the neighbor lists of whichever of CDP and LLDP is on | `routes/neighbors`, `try_load_neighbors` | v0.1.0 |
| `long_port_name` | `(name: str) -> str` | `Eth1/3` -> `Ethernet1/3`, `Po43` -> `port-channel43` | every parser here | v0.1.0 |
| `parse_aging_time` | `(body) -> int \| None` | Seconds a learned address is kept, from `show mac address-table aging-time` | `parse_neighbor_view` | v0.1.0 |
| `parse_arp` | `(body) -> list[ArpEntry]` | Every VRF's ARP entries from `show ip arp detail vrf all` | `parse_neighbor_view` | v0.1.0 |
| `parse_cdp_neighbors` | `(body) -> list[Neighbor]` | Neighbors from `show cdp neighbors detail` | `parse_neighbor_view` | v0.1.0 |
| `parse_lldp_neighbors` | `(body) -> list[Neighbor]` | Neighbors from `show lldp neighbors detail`, capability letters as words, "not advertised" as nothing | `parse_neighbor_view` | v0.1.0 |
| `parse_mac_table` | `(body) -> list[MacEntry]` | The MAC address table with each maker, by port then VLAN, the switch's own address last | `parse_neighbor_view` | v0.1.0 |
| `parse_neighbor_view` | `(feature, cdp_global, mac, aging, arp, channel, cdp=None, lldp=None) -> NeighborView` | Everything the Neighbors page shows, from the bodies | `load_neighbors` | v0.1.0 |
| `parse_port_channels` | `(body) -> list[PortChannel]` | Port-channels and their member ports from `show port-channel summary` | `parse_neighbor_view` | v0.1.0 |
| `readable_duration` | `(value) -> str` | `PT1M41S` -> `1m 41s` | `parse_arp` | v0.1.0 |
| `try_load_neighbors` | `(client) -> NeighborView \| None` | Like `load_neighbors`, None when the switch refuses a command, so the Ports and port pages keep the rest | `routes/ports` | v0.1.0 |

`NeighborView.for_port(name)` gives a port's neighbors and the addresses
learned on it; for a port in a port-channel those are the port-channel's,
because the switch learns addresses on the bundle. `ips_of(mac)` looks a MAC
address up in the ARP table. With the lldp feature off every `show lldp`
command is an error, so the LLDP list is asked for only when it is on. The
LLDP field names come from Cisco's NX-API reference; LLDP has been off on the
switch NXray was built against.

## `app/neighbor_changes.py` — CDP and LLDP per port, and the MAC address table

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `aging_words` | `(seconds: int) -> str` | `1800` -> `1800 seconds (30 minutes)`, `0` -> never | `plan_mac_aging` | v0.1.0 |
| `describe_port_discovery` | `(port, change) -> tuple[list[str], list[str]]` | A port's CDP and LLDP change in words, plus a warning for each thing turned off | `routes/ports.port_discovery_change` | v0.1.0 |
| `load_port_discovery` | `(client, port, lldp_on) -> PortDiscovery \| None` | What one port does with CDP (and LLDP, while it is on), from one request; None when refused | `routes/ports` | v0.1.0 |
| `parse_cdp_interface` | `(body) -> bool \| None` | Whether CDP is on for the port in `show cdp interface <port>` | `load_port_discovery` | v0.1.0 |
| `parse_lldp_interface` | `(body) -> tuple[bool \| None, bool \| None]` | Sending and listening from `show lldp interface <port>`, wherever `tx_enabled` and `rx_enabled` sit | `load_port_discovery` | v0.1.0 |
| `plan_clear` | `(view, *, scope, ports, port="", vlan="", mac="") -> tuple[ClearRequest, list[str], list[str]]` | Clearing learned addresses (all, one port, one VLAN, one address), checked, with how many go and the relearn warning | `routes/neighbors.learned_macs_clear` | v0.1.0 |
| `plan_mac_aging` | `(view, text) -> tuple[int, list[str], list[str]]` | A new aging time, checked, in words; refuses the one in use | `routes/neighbors.mac_aging_change` | v0.1.0 |
| `plan_port_discovery` | `(current, *, cdp, lldp_transmit, lldp_receive, lldp_shown) -> DiscoveryChange` | The CDP and LLDP settings that differ from the port's; LLDP only when the page showed it | `routes/ports.port_discovery_change` | v0.1.0 |
| `plan_static_mac` | `(view, *, mac, vlan, where, vlan_ids, ports) -> tuple[StaticMac, list[str], list[str]]` | A new static entry checked against the switch's VLANs and front ports (or `drop`), with a warning when the address was learned elsewhere | `routes/neighbors.static_mac_add` | v0.1.0 |
| `plan_static_removal` | `(view, *, mac, vlan) -> tuple[StaticMac, list[str], list[str]]` | Removing a static entry the table shows, with the port or drop it was made with | `routes/neighbors.static_mac_remove` | v0.1.0 |
| `static_entries` | `(view) -> list[MacEntry]` | The static entries someone added, not the switch's own address | `routes/neighbors`, `plan_static_mac` | v0.1.0 |
| `static_target` | `(entry) -> str \| None` | Where a static entry sends traffic as NXray names it (a front port or `drop`); None for one NXray does not remove | `routes/neighbors`, `plan_static_removal` | v0.1.0 |

`PortDiscovery` holds a port's CDP and LLDP state; its LLDP values are None
while LLDP is off on the switch, when they can be neither read nor set. The
LLDP field names come from Cisco's guides; LLDP has been off on the switch
NXray was built against. Clearing learned addresses is not a configuration
change, so it leaves nothing to save.

## `app/port_channels.py` — port-channels and LACP

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `load_channels` | `(client) -> ChannelView` | Every port-channel with its ports and how they joined, the front ports, and while LACP is on each port's LACP rate, priority and partner and the switch's LACP priority; two requests at most | `routes/port_channels` | v0.1.0 |
| `parse_brief` | `(brief_body) -> tuple[list[str], frozenset[str], frozenset[str], set[str]]` | Front ports in panel order, those turned off, those up, and routed port-channels, from `show interface brief` | `load_channels` | v0.1.0 |
| `parse_channels` | `(summary_body, modes, descriptions, routed, lacp_ports=None, partners=None) -> list[Channel]` | The port-channels in `show port-channel summary`, with each member's state letter and what the other commands add | `load_channels` | v0.1.0 |
| `parse_descriptions` | `(description_body) -> dict[str, str]` | Interface -> description from `show interface description` | `load_channels` | v0.1.0 |
| `parse_lacp_ports` | `(lacp_interface_body) -> dict[str, tuple[str, int \| None]]` | Port -> (LACP rate, port priority) from `show lacp interface`; "Short" is fast | `load_channels` | v0.1.0 |
| `parse_modes` | `(database_body) -> dict[str, str]` | Port -> how it joined (`active`, `passive`, `on`) from `show port-channel database` | `load_channels` | v0.1.0 |
| `parse_partners` | `(lacp_neighbor_body) -> dict[str, Partner]` | Port -> the device at its other end (address, priority, port, flags) from `show lacp neighbor` | `load_channels` | v0.1.0 |
| `plan_add` | `(view, *, number, port, mode, fast_rate) -> tuple[Join, list[str], list[str]]` | One free port joining an existing port-channel the way its ports did | `routes/port_channels.channel_add` | v0.1.0 |
| `plan_channel_settings` | `(view, *, number, description, min_links) -> tuple[ChannelSettings, list[str], list[str]]` | A port-channel's description and LACP minimum links (empty keeps it); warns when the minimum takes it down | `routes/port_channels.channel_settings` | v0.1.0 |
| `plan_create` | `(view, *, number, ports, mode, fast_rate, description) -> tuple[Join, list[str], list[str]]` | A new port-channel from free front ports: a free number, LACP only while LACP is on, with the matching-settings and link-drop warnings | `routes/port_channels.channel_create` | v0.1.0 |
| `plan_delete` | `(view, *, number) -> tuple[int, list[str], list[str]]` | Deleting a port-channel; refuses one that still has ports, naming them | `routes/port_channels.channel_delete` | v0.1.0 |
| `plan_port_lacp` | `(view, *, port, rate, priority) -> tuple[PortLacp, list[str], list[str]]` | A member's LACP rate and port priority, only what differs; a rate change only while the port is off | `routes/port_channels.port_lacp` | v0.1.0 |
| `plan_remove` | `(view, *, port) -> tuple[str, list[str], list[str]]` | Taking a port out of its port-channel, warning when it carries traffic or is the last one | `routes/port_channels.channel_remove` | v0.1.0 |
| `plan_system_priority` | `(view, text) -> tuple[int, list[str], list[str]]` | The switch's LACP priority, warning that every LACP port-channel agrees on its ports again | `routes/port_channels.system_priority` | v0.1.0 |

A port-channel's LACP minimum links appears only in `show running-config`,
which NXray's role may not read, so its form has no current value.
NXray refuses to delete a port-channel that still has ports; the switch itself
would take them out silently.

## `app/routing.py` — VLAN interfaces, routed ports and their addresses

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `load_routing` | `(client) -> RoutingView` | Whether interface-vlan is on, the VLANs, every VLAN interface and routed port with its VRF and addresses; one request, plus one for the VLAN interfaces | `routes/routing` | v0.1.0 |
| `long_name` | `(name: str) -> str` | `Eth1/3` (as `show ip interface` writes it) -> `Ethernet1/3` | `parse_ipv4`, `parse_ipv6` | v0.1.0 |
| `parse_brief` | `(brief_body) -> tuple[list[str], list[dict]]` | VLAN interface names, and the rows of routed front ports and port-channels, from `show interface brief` | `load_routing` | v0.1.0 |
| `parse_ipv4` | `(body) -> dict[str, tuple[str, list[Address], dict]]` | Interface -> (VRF, IPv4 addresses with the main one first, row) from `show ip interface vrf all` | `load_routing`, `port_settings.parse_port_settings` | v0.1.0 |
| `parse_ipv6` | `(body) -> dict[str, tuple[str, list[Address], str]]` | Interface -> (VRF, IPv6 addresses, link-local address) from `show ipv6 interface vrf all` | `load_routing`, `port_settings.parse_port_settings` | v0.1.0 |
| `parse_routed_port` | `(row, ipv4, ipv6, descriptions) -> L3Interface` | One routed front port or port-channel from its `show interface brief` row and the address tables | `load_routing` | v0.1.0 |
| `parse_vlan_interface` | `(name, svi_body, ipv4, ipv6, descriptions) -> L3Interface` | One VLAN interface: on/off, up/down, MTU, description and addresses, from `show interface vlan<n>` and the address tables | `load_routing` | v0.1.0 |
| `plan_add_address` | `(view, *, name, address) -> tuple[AddressChange, list[str], list[str]]` | One more address on a VLAN interface or routed port: IPv6, or IPv4 (the main one when it has none, else extra); refuses a network another interface in the VRF has | `routes/routing.address_add` | v0.1.0 |
| `plan_create_vlan_interface` | `(view, *, vlan, ipv4, ipv6, description, mtu, enabled) -> tuple[VlanInterfaceChange, list[str], list[str]]` | A new VLAN interface: interface-vlan on, the VLAN exists and has none, addresses checked | `routes/routing.vlan_interface_create` | v0.1.0 |
| `plan_delete_vlan_interface` | `(view, *, vlan) -> tuple[int, list[str], list[str]]` | Deleting a VLAN interface, naming the addresses that go with it; never Vlan1 | `routes/routing.vlan_interface_delete` | v0.1.0 |
| `plan_remove_address` | `(view, *, name, address) -> tuple[AddressChange, list[str], list[str]]` | Taking one address off; the main IPv4 address only once the extra ones are gone | `routes/routing.address_remove` | v0.1.0 |
| `plan_vlan_interface_settings` | `(view, *, vlan, ipv4, description, mtu, enabled) -> tuple[VlanInterfaceChange, list[str], list[str]]` | A VLAN interface's main IPv4 address, description, MTU and on/off; only what differs | `routes/routing.vlan_interface_settings` | v0.1.0 |

VLAN interfaces exist only while the interface-vlan feature is on; turning it
on makes Vlan1 by itself, turned off. NXray changes VLAN interfaces of VLANs 1
to `nxapi.VLAN_INTERFACE_MAX` (254) only, the range its role names. A port becomes routed on its own page;
the Routing page puts extra IPv4 and IPv6 addresses on it. An extra address
may share its main address's network, but not another interface's in the same
VRF. Link-local IPv6 addresses are never typed: the switch makes one on every
IPv6 interface.

## `app/oui.py` — MAC addresses and their makers

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `format_mac` | `(text: str) -> str` | `0cea.1439.bb3a` -> `0c:ea:14:39:bb:3a`; other text as is | `neighbors.parse_mac_table`, `parse_arp` | v0.1.0 |
| `is_local_mac` | `(text: str) -> bool` | A locally administered address (made up by a VM, a container or a phone), which has no maker | `mac_maker`, `neighbors.parse_mac_table` | v0.1.0 |
| `mac_maker` | `(text: str) -> str` | The organisation the IEEE assigned the address block to (the smallest matching MA-S, MA-M or MA-L block), or "" | `neighbors.parse_mac_table` | v0.1.0 |
| `normalize_mac` | `(text: str) -> str \| None` | The 12 hex digits of a MAC address written any common way, or None | everything here, `NeighborView.ips_of` | v0.1.0 |

The list lives in `app/oui.tsv.gz` and is read once, on first use.
`scripts/update_oui.py` downloads it from the IEEE; the image build runs it,
and keeps the committed copy when the IEEE cannot be reached.

## `app/routes/history.py` — the History page

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `history_page` | `(request, username, period) -> Response` | `GET /history`: the charts for the chosen range, from the database only | the router | v0.1.0 |
