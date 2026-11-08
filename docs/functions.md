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
| Know which of NXray's switches a page is for | `app/switch_choice.py`, `selected_switch_id`; every per-switch table (history, port labels, backups, open problems) is keyed by that id |
| Check NXray can reach the switch | `app/switch_setup.py`, `check_connection` |
| Give NXray's account a new password, or make it again | `app/switch_repair.py`, `run_repair` |
| Encrypt a secret for the database | `app/crypto.py` |
| Protect a form against forgery | `app/dependencies.py`, `require_csrf`; token from `security.csrf_token` |
| Turn switch output into page data | `app/switch.py` (health), `app/ports.py` (ports), `app/neighbors.py` (neighbors and tables) |
| Read the switch with NXray's account from a route | `dependencies.stored_switch`, then `switch_setup.read_switch` |
| Show a byte count or a bit rate | the `bytes` and `rate` template filters (`ports.human_bytes`, `ports.human_rate`) |
| Change a port on the switch | `app/nxapi.py`, `NxapiClient.configure_port` (checked by `validate_port_name`, `validate_description`); several at once, with one shared configuration: `app/port_bulk.py`, `plan_bulk` |
| Read or change a port's speed, MTU, FEC, flow control, storm control, layer, or split it | `app/port_settings.py` (`plan_port_settings`, `plan_breakout`); commands from `NxapiClient.configure_port_settings`, `breakout_port`, `join_port` |
| Type configuration lines NX-API refuses (they contain `;`) | `app/switch_ssh.py`, `run_config` |
| Give NXray's account the port-changes role | `app/port_changes.py`, `enable_port_changes` |
| Draw the front panel, or colour a port by state, speed, VLAN, port-channel, traffic or errors | `app/face.py`, `draw_face` |
| Refresh figures on a page by themselves, or share one switch reading between browsers | `app/live.py`, `LiveCache.get`; the answers are in `app/routes/live.py`; `app/static/live.js` is the browser side ([Live figures](live.md)) |
| Know a browser's theme (system, light, dark) or menu width | `app/preferences.py`, `ui_preferences` (a template global) |
| Read CDP and LLDP neighbors, the MAC address table, ARP, or what is plugged into a port | `app/neighbors.py`, `load_neighbors` and `NeighborView.for_port` |
| Write a MAC address, or name the maker it belongs to | `app/oui.py`, `format_mac` and `mac_maker` |
| Turn CDP or LLDP on or off on a port, set the MAC aging time, add or remove a static MAC address, clear learned ones | `app/neighbor_changes.py` (`plan_port_discovery`, `plan_mac_aging`, `plan_static_mac`, `plan_static_removal`, `plan_clear`); commands from `NxapiClient.set_port_discovery`, `set_mac_aging`, `add_static_mac`, `remove_static_mac`, `clear_learned_macs` |
| Read port-channels and LACP, or make, change and delete them | `app/port_channels.py` (`load_channels`; `plan_create`, `plan_add`, `plan_remove`, `plan_delete`, `plan_channel_settings`, `plan_port_lacp`, `plan_system_priority`); commands from `NxapiClient.join_port_channel`, `leave_port_channel`, `delete_port_channel`, `configure_port_channel`, `set_port_lacp`, `set_lacp_system_priority` |
| Read VLAN interfaces and routed ports with their IPv4 and IPv6 addresses, or make, change and delete them | `app/routing.py` (`load_routing`; `plan_create_vlan_interface`, `plan_vlan_interface_settings`, `plan_delete_vlan_interface`, `plan_add_address`, `plan_remove_address`); commands from `NxapiClient.configure_vlan_interface`, `delete_vlan_interface`, `set_interface_addresses` |
| Read a routing protocol (OSPF, BGP, HSRP, ...) or change one of its settings | `app/routing_protocols.py` (`load_protocol_page`, `build_protocol_change`); each protocol is data in `app/protocols_*.py` on `app/protocols.py`; command from `NxapiClient.configure_protocol` |
| Read spanning tree (trees, ports, the MST region) or change it for the whole switch, a VLAN, the MST region or a port | `app/spanning_tree.py` (`load_spanning_tree_page`, `build_stp_change`), on the same parts as the protocol pages (`app/protocols.py`); command from `NxapiClient.configure_spanning_tree` |
| Read or change the switch's hostname, banner, clock and NTP, DNS, logging or SNMP settings, or read its log | `app/switch_admin.py` (`load_switch_admin_page`, `build_admin_change`, `load_switch_log`, `parse_log`), on the same parts as the protocol pages (`app/protocols.py`); command from `NxapiClient.configure_switch_admin` |
| Read, make, change or apply IPv4, IPv6 and MAC ACLs, object groups and VLAN access maps, or size the TCAM regions | `app/acls.py` (`load_acls_page`, `build_acl_change`, `parse_acl_config`), on the same parts as the protocol pages; command from `NxapiClient.configure_acl` |
| Read or change DHCP snooping, the DHCP relay, ARP inspection or IP Source Guard | `app/dhcp_security.py` (`load_dhcp_page`, `build_dhcp_change`); command from `NxapiClient.configure_dhcp` |
| Restart the switch | `app/switch_ssh.py`, `reload_switch`, with the admin login the Config page asks for |
| Read or change a port's port security | `app/port_security.py` (`load_port_security_page`, `build_port_security_change`); command from `NxapiClient.configure_port_security` |
| Keep a backup of the switch's configuration, compare two configurations, or roll back | `app/config_tools.py` (`store_backup`, `config_diff`, `load_configs`); commands from `NxapiClient.create_checkpoint`, `delete_checkpoint`, `rollback_to_checkpoint` |
| Split a configuration's text into its top-level lines and the lines under them | `app/config_tools.py`, `config_sections` |
| Record a change in the activity log, or list the log | `dependencies.note_activity` from a route; `app/activity.py` (`record_activity`, `list_activity`) |
| Send an alert by e-mail or webhook, notice a problem in a sample, or keep the alert settings | `app/alerts.py` (`AlertMonitor`, `dispatch`, `notify_change`, `deliver`, `send_test`); checked from `history.Sampler` |
| Read the switch's route table | `app/routing_protocols.py`, `load_overview` / `parse_routes` |
| Read, add or remove static routes | `app/routing.py` (`load_routing`, `plan_add_static_route`, `plan_remove_static_route`); command from `NxapiClient.set_static_route` |
| Read the VRFs, make or delete one, or move an interface into another | `app/routing.py` (`load_routing`, `plan_create_vrf`, `plan_delete_vrf`, `plan_interface_vrf`); commands from `NxapiClient.create_vrf`, `delete_vrf`, `set_interface_vrf` |
| List the switch's features, or turn one on or off | `app/features.py`, `load_features` and `Feature.refusal`; the command from `NxapiClient.set_feature` |
| Read or set a port's label (NXray only, never the switch) | `app/port_labels.py` |
| Record or draw history | `app/history.py` (`Sampler`, `system_charts`, `port_charts`, `vlan_charts`); the SVG itself is `app/charts.py`, `line_chart` |
| Estimate a device's or a VLAN's traffic from the ports' | `app/traffic.py` (`device_traffic`, `port_device`, `vlan_traffic`); each VLAN's over time is stored by `history.build_rows` |
| Check for a newer image, or replace this container with it | `app/update.py`, `check_for_updates` / `apply_update` |
| Rank NXray versions, or pick between the `:beta` and `:latest` tags | `app/update.py`, `parse_version` / `pick_target` |

---

## `app/config.py` — settings

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `env_bool` | `(name: str, default: bool = False) -> bool` | A true/false environment setting (true/yes/on/1, false/no/off/0); raises `ConfigError` for any other word | `load_settings`, `healthcheck.https_enabled` | v0.1.0 |
| `load_settings` | `() -> Settings` | Reads and validates the environment; raises `ConfigError` with the fix | `main.create_app` | v0.1.0 |

`Settings` is a frozen dataclass; `ConfigError` means the app must not start.

## `app/db.py` — SQLite

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `connect` | `(db_path: Path) -> Connection` | Opens a connection with WAL and foreign keys on; creates a new file mode 600 | `db.open_db` | v0.1.0 |
| `current_version` | `(conn) -> int` | The applied schema version, 0 for a new file | `db.migrate` | v0.1.0 |
| `init_db` | `(db_path: Path) -> int` | Creates or upgrades the database, returns its version | `main.lifespan` | v0.1.0 |
| `migrate` | `(conn) -> int` | Applies pending migrations in order | `db.init_db` | v0.1.0 |
| `open_db` | `(db_path: Path) -> Iterator[Connection]` | Context manager: one connection per unit of work, always closed | routes, `security.current_user`, `main.lifespan` | v0.1.0 |
| `restrict_files` | `(db_path: Path) -> None` | Sets the database and its `-wal`/`-shm` files to mode 600 (owner only); skips a file it does not own | `db.init_db` | v0.3.0 |

Migrations are append-only. Editing an applied one leaves existing databases
behind.

## `app/security.py` — authentication

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `clear_login_failures` | `(conn, ip: str) -> None` | Forgets an address's failures after success | `routes/auth.login_submit` | v0.1.0 |
| `client_ip` | `(request) -> str` | The peer address login throttling counts against | `routes/auth.login_submit` | v0.1.0 |
| `create_session` | `(conn, username: str, session_hours: int) -> str` | Records a session, returns its id | `routes/auth.login_submit` | v0.1.0 |
| `csrf_token` | `(request) -> str` | This session's anti-forgery token, derived from the session id and the switch the page is for (`switch_choice.selected_switch_id`), so a form shown for one switch is refused once another is picked | routes rendering forms | v0.1.0 |
| `csrf_valid` | `(request, token: str) -> bool` | True when a form carries this session's token for the switch this request is for | `dependencies.require_csrf` | v0.1.0 |
| `csrf_valid_any_switch` | `(request, token, switch_ids) -> bool` | True when the token is this session's for any of those switches or none; only for forms that change no switch (the switch picker, the theme and menu buttons) | `routes/switch_page.switches_select`, `routes/preferences.preferences` | v0.1.0 |
| `current_user` | `(request, *, touch=True) -> str \| None` | Resolves the cookie to a username and slides the expiry (not with `touch=False`) | `dependencies.login_required`, `routes/auth.login_form` | v0.1.0 |
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
| `admin_required` | `(request) -> str` | FastAPI dependency for the Switch, Users, Config and Activity pages; raises `Forbidden` for other roles | `routes/switch_page`, `routes/users`, `routes/config_page`, `routes/activity` | v0.1.0 |
| `current_account` | `(request) -> User \| None` | The signed-in account, looked up once per request | the role guards, `current_role`, `routes/users` | v0.1.0 |
| `current_role` | `(request) -> str \| None` | The signed-in account's role; a template global so pages hide buttons the role can't use | templates, `main.create_app` | v0.1.0 |
| `may_change` | `(request) -> bool` | True when the signed-in account may change the switch (`User.can_change`: operator or admin); a page adds its own `*_changes_enabled` flag | `routes/routing`, `routes/protocols`, `routes/port_channels`, `routes/neighbors`, `routes/live`, `routes/traffic` | v0.2.1 |
| `request_target` | `(request) -> str` | The request's path plus query string, kept in `?next=` across sign-in | `dependencies.login_required`, `dependencies.live_login_required` | v0.2.1 |
| `login_required` | `(request) -> str` | FastAPI dependency; sends anonymous callers to `/login` | every protected route | v0.1.0 |
| `share_switch_reads` | `(request, call_next) -> Response` | HTTP middleware: a whole-page refresh (`X-Requested-With: nxray-live` on a page `refreshes_whole_page` names) reads the switch through the live cache, so many open pages cost one read per interval; any other request reads the switch itself | `main.create_app` | v0.2.0 |
| `live_login_required` | `(request) -> str` | Like `login_required` for self-refreshing figures: does not slide the session | `routes/live` | v0.2.0 |
| `note_activity` | `(request, username, area, what, switch="") -> None` | Records one change in the activity log after it worked (`activity.record_activity`), and sends it as an alert when the Alerts page asks for changes (`alerts.notify_change`) | every route that changes something | v0.1.0 |
| `operator_required` | `(request) -> str` | FastAPI dependency for forms that change the switch (port, VLAN, Save config); operator or admin | `routes/ports`, `routes/vlans`, `switch_save` | v0.1.0 |
| `paused_message` | `(seconds: int) -> str` | What the pages say while NXray leaves the switch alone after a role change | `stored_switch`, Switch page | v0.1.0 |
| `redirect` | `(url: str, status_code: int = 303) -> RedirectResponse` | Redirect, defaulting to see-other | `routes/auth` | v0.1.0 |
| `selected_connection` | `(request) -> SwitchConnection \| None` | The switch this request is for, without its login | `routes/alerts` | v0.1.0 |
| `stored_switch` | `(request) -> tuple[SwitchConnection \| None, SwitchTarget \| None, str \| None]` | The switch this request is for (`switch_choice.selected_switch_id`), its decrypted login, or why it can't be used (key changed, waiting after a role change) | dashboard, ports routes, Save config | v0.1.0 |
| `switch_picker` | `(request) -> tuple[list[SwitchConnection], int \| None]` | Every switch and the one this page is for; a template global for the top bar's picker | `base.html` | v0.1.0 |
| `role_behind` | `(request) -> list[tuple[SwitchConnection, str]]` | Switches whose NXray role lacks rules this version can use, with the missing kinds of change in words; admins only, empty on the Switch page; a template global for the banner | `base.html` | v0.2.0 |
| `require_csrf` | `(request, token: str) -> None` | Raises `CsrfFailed` (a 403 page) unless the form carries the session's token | every state-changing POST | v0.1.0 |
| `safe_next` | `(target: str) -> str` | A `?next=` destination on this site only, else `/` | `routes/auth` | v0.1.0 |

`templates` is the shared Jinja environment (its global `form_token` is
`security.csrf_token`, for the top bar's own form); `RedirectToLogin` is the
exception `login_required` raises, `Forbidden` the one the role guards raise
(a 403 page naming the role needed) and `CsrfFailed` the one `require_csrf`
raises, all handled in `main.create_app`.

## `app/nxapi.py` — the NX-API client

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `breakout_numbers` | `(name: str) -> tuple[int, int]` | Module and port of a port or split port: Ethernet1/50/2 gives (1, 50) | `NxapiClient.breakout_port`, `join_port` | v0.1.0 |
| `build_payload` | `(commands: list[str], method="cli") -> list[dict]` | The JSON-RPC request body for running commands in order; `method="cli_ascii"` asks for the printed text instead | `NxapiClient._send`, `show_text` | v0.1.0 |
| `check_switch_password` | `(password: str) -> str` | A password NXray may send to the switch: 8 to 64 letters and digits; the message never repeats it | `NxapiClient.create_person_account`, `set_person_password`, `switch_accounts.check_switch_side_password` | v0.2.0 |
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
| `validate_checkpoint_name` | `(name: str) -> str` | Refuses any checkpoint name but NXray's own, `nxray-<number>` | `NxapiClient.create_checkpoint`, `delete_checkpoint`, `rollback_to_checkpoint` | v0.1.0 |
| `sflow_data_source` | `(name) -> str` | `Ethernet1/5` -> `ethernet 1/5` and `port-channel41` -> `port-channel 41`, as `sflow data-source interface` takes them | `NxapiClient.configure_sflow` | v0.2.0 |
| `validate_sflow_address` | `(text) -> str` | An IPv4 address for sFlow's collector or agent; refuses 0.0.0.0, broadcast, multicast and loopback | `NxapiClient.configure_sflow`, `sflow_switch.plan_sflow` | v0.2.0 |
| `validate_sflow_vrf` | `(name) -> str` | The VRF the switch reaches the collector in: `default`, `management` or a VRF name | `NxapiClient.configure_sflow`, `sflow_switch.plan_sflow` | v0.2.0 |
| `validate_storm_level` | `(value) -> str` | A storm-control level 0-100 with up to two decimals, written as the switch writes it (`10.00`) | `NxapiClient.configure_port_settings`, `port_settings` | v0.1.0 |
| `validate_vlan_id` | `(value: int \| str) -> int` | A VLAN number 1-4094, else `ValueError` | VLAN client methods, `vlans`, `routes/vlans` | v0.1.0 |
| `validate_vlan_name` | `(name: str) -> str` | A VLAN name the switch stores: 1-32 letters, digits, `.`, `-`, `_` | `NxapiClient.configure_vlan`, `routes/vlans` | v0.1.0 |
| `validate_next_hop` | `(text: str) -> str` | A static route's next hop: one IPv4 or IPv6 address a router can have; never link-local IPv6, multicast, loopback or unspecified | `static_route_line`, `routing` | v0.1.0 |
| `validate_route_prefix` | `(text: str) -> str` | A static route's destination network with its prefix length (`0.0.0.0/0` allowed); refuses an address that is not the start of its network, naming the one meant | `static_route_line`, `routing` | v0.1.0 |
| `static_route_line` | `(prefix: str, next_hop: str) -> str` | `ip route P NH` or `ipv6 route P NH`, both of one family; its `no` form removes the route | `NxapiClient.set_static_route` | v0.1.0 |
| `validate_vrf_name` | `(name: str) -> str` | A VRF name NXray may create, delete or move interfaces into: 1-32 letters, digits, `-`, `_`; never `default`, `management` or `all` | VRF client methods, `routing` | v0.1.0 |

`NxapiClient(target).show(*commands)` runs show commands in one request.
The only configuration methods are `create_user(name, password, role)`
(letters-and-digits password, role `network-operator` only),
`give_role(name, role)` (role `nxray-ports` only), `delete_user(name)`
(those three for NXray's own account only), `create_person_account(name,
password, roles)`, `set_person_password(name, password)`,
`set_person_roles(name, add=, remove=)` and `remove_person_account(name)`
(a person's switch account; letters-and-digits password, roles from
`PERSON_ROLES` only; app/switch_accounts.py refuses NXray's own account and
reserved names before calling them),
`configure_port(name, description=, enabled=)` (one
port's description and on/off, nothing else), `configure_vlan(vlan_id,
name=None)` (create or rename), `delete_vlan(vlan_id)` (never VLAN 1),
`configure_port_vlans(name, mode=, access_vlan=, native_vlan=,
allowed_vlans=)` (one port's mode and VLANs), `configure_port_settings(name,
layer=, remove_ip=, ip_address=, speed=, mtu=, fec=, flow_receive=,
flow_send=, storm_levels=, storm_action=, old_storm_action=)` (one port's
settings, only the ones given), `breakout_port(name, mapping)` and
`join_port(name, mapping)` (split a 100G port into four, or join them;
`10g-4x` or `25g-4x` only), `set_load_interval(name, seconds)` (how long one
port averages its In and Out over: `load-interval counter 1 <seconds>` for one
of `LOAD_INTERVALS`, or `no load-interval counter 1` for None),
`configure_sflow(sampling_rate=, collector=, vrf=, collector_port=, agent=,
add_ports=, remove_ports=)` (where the switch sends its sFlow samples, how
often, and which front ports and port-channels it samples; only the values given; the collector
with its VRF), `set_feature(command, enabled)` (`feature X` or
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
description=, mtu=, enabled=, remove=, add=, vrf=)` (make or change one VLAN
interface: its VRF first, addresses off, addresses on, description, MTU,
on/off last), `delete_vlan_interface(vlan)` (never VLAN 1),
`set_interface_addresses(name, remove=, add=)` (IPv4 and IPv6 addresses on a
VLAN interface or routed port), `create_vrf(name)`, `delete_vrf(name)`,
`set_interface_vrf(name, vrf, current=)` (`no vrf member` the old VRF, `vrf
member` the new one; the switch deletes the interface's addresses),
`set_static_route(vrf, prefix, next_hop, add=)` (one static route in default,
or inside `vrf context`; never management),
`configure_protocol(protocol, scope, setting, action, ident, values)` (one
change on a routing protocol page; the lines come from
`routing_protocols.build_protocol_change`),
`configure_spanning_tree(scope, setting, action, ident, values)` (one change on
the Spanning tree page; the lines come from `spanning_tree.build_stp_change`),
`configure_switch_admin(scope, setting, action, ident, values)` (one change on
the Switch admin page; the lines come from `switch_admin.build_admin_change`),
`configure_acl(...)`, `configure_port_security(...)` and `configure_dhcp(...)`
(the same for the ACLs, Port security and DHCP and ARP pages, from
`acls.build_acl_change`, `port_security.build_port_security_change` and
`dhcp_security.build_dhcp_change`), `create_checkpoint(name)` and
`delete_checkpoint(name)` (NXray's own `nxray-<n>` switch checkpoints),
`rollback_to_checkpoint(name)` (sent only with the switch admin login the
Config page asks for; NX-OS rolls back all or nothing),
`reset_ports(names)` (`default interface <name>` for one or more front
ports: back to how they came out of the box) and `reset_port_channel(number)`
(the same for a port-channel's own settings; its members keep their
channel-group membership)
and `save_config()`; each builds its commands from checked values.
`show_text(command)` runs one show command whose answer NX-API gives only as
printed text (`show running-config spanning-tree`, `show running-config`, `show
logging last <n>`, `show hardware access-list tcam region`, `show ip dhcp
snooping binding`, through the `cli_ascii` method).
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
| `text` | `(value) -> str` | A value from NX-OS JSON as stripped text; `""` for missing or null | every parser | v0.2.1 |
| `int_or` | `(value, default=0) -> int` | A whole number from text such as `"10"`; `default` if it is not one (a sign is fine) | `vlans`, `ports` | v0.2.1 |
| `digits_int` | `(value) -> int \| None` | A whole number from text made only of digits; None for anything else, a sign included | `routing` | v0.2.1 |
| `duration_text` | `(value) -> str` | An ISO 8601 duration (`P7DT11H59M45S`) as `7d 11h 59m 45s`: zero parts left out, seconds may be fractional, anything else unchanged | `protocols_ospf`, `protocols_multicast` | v0.2.1 |
| `is_true` | `(value) -> bool` | True only for the word `true`, in any case | `protocols_igp`, `protocols_ospf` | v0.2.1 |
| `is_enabled` | `(value) -> bool` | True for `true`, `yes` or `enabled`, in any case | `protocols_bgp` | v0.2.1 |
| `row_vrf` | `(row, *keys) -> str` | The VRF a row names, from the first of `keys` that holds text; `default` if none | `protocols_bgp`, `protocols_multicast` | v0.2.1 |
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

## `app/switch_connection.py` — the stored switches

Each switch is a row named by its `id`; every function takes that id, so
none reads or changes "the" switch by default.

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `delete_connection` | `(conn, switch_id) -> bool` | Forgets a switch: its login, history, port labels, config backups and open problems; the switch account stays | `routes/switch_page.switch_forget` | v0.1.0 |
| `find_by_address` | `(conn, host, port) -> int \| None` | The id of the switch stored at that address and NX-API port (host in any case) | `save_connection`, `routes/switch_page` (setup, address, repair) | v0.1.0 |
| `get_connection` | `(conn, switch_id) -> SwitchConnection \| None` | One stored switch without its password; None for no such switch (or `None`) | Switch page, dashboard | v0.1.0 |
| `list_connections` | `(conn) -> list[SwitchConnection]` | Every stored switch, in the order they were added | `history.Sampler`, the switch picker, Switch page | v0.1.0 |
| `load_target` | `(conn, switch_id, secret_key) -> SwitchTarget` | A switch's login, decrypted; `LookupError` / `DecryptionError` | Switch page test, dashboard | v0.1.0 |
| `record_test_result` | `(conn, switch_id, *, ok, message) -> None` | Remembers the last connection test | Switch page | v0.1.0 |
| `replace_login` | `(conn, switch_id, *, host, port, password, switch_hostname, secret_key) -> None` | Stores the new password Run setup again gave the account, and the address it worked at | `routes/switch_page.switch_repair` | v0.1.0 |
| `save_connection` | `(conn, *, host, port, username, password, switch_hostname, config_saved, secret_key) -> int` | Stores a new switch, password encrypted; its id. Refuses one at an address already stored | `routes/switch_page.switch_setup` | v0.1.0 |
| `set_address` | `(conn, switch_id, *, host, port, switch_hostname) -> None` | Stores a new switch address NXray's account already signed in at | `routes/switch_page.switch_address` | v0.1.0 |
| `set_switch_identity` | `(conn, connection, system: SystemInfo) -> None` | Stores the model and NX-OS version the switch just reported (for the strip at the top of every page); writes only when they changed | `routes/dashboard`, `routes/switch_page` (test, address) | v0.1.0 |
| `set_switch_hostname` | `(conn, switch_id, switch_hostname) -> None` | Stores the switch's new name after NXray renamed it on the Switch admin page | `routes/switch_admin` (the site's `after`) | v0.1.0 |
| `set_changes_enabled` | `(conn, switch_id, *, pause_seconds, role_version, vlan_interfaces=None, role_mode=None) -> None` | Records that port changes are on with that role version, and whether its port list names the VLAN interfaces (None keeps it), and the role mode (None keeps it; a broad role is stored with `BROAD_ROLE_VERSION`), and pauses switch calls; never shortens a running pause | `routes/switch_page.switch_enable_changes`, `switch_setup` | v0.1.0 |
| `set_changes_off` | `(conn, switch_id) -> None` | Records that port changes are off (role version 0) | `routes/switch_page.switch_repair` | v0.1.0 |
| `set_admin_login` | `(conn, switch_id, *, admin_user, admin_password, ssh_port, secret_key) -> None` | Keeps the switch admin login, encrypted, for the stored-login role mode | `routes/switch_page.switch_enable_changes`, `switch_setup` | v0.1.0 |
| `delete_admin_login` | `(conn, switch_id) -> None` | Forgets the stored admin login; a switch in the stored-login mode goes back to the limited mode | `routes/switch_page.switch_forget_admin_login`, `switch_enable_changes` | v0.1.0 |
| `stored_admin_login` | `(conn, switch_id, secret_key) -> (user, password, ssh_port) \| None` | The stored admin login, decrypted; None when none is stored, `DecryptionError` when the secret key changed | `routes/switch_page`, `role_upgrade.upgrade_stored_roles` | v0.1.0 |
| `set_config_saved` | `(conn, switch_id, saved: bool) -> None` | Records whether the switch config was saved after setup or Run setup again | `routes/switch_page.switch_setup`, `switch_repair` | v0.1.0 |
| `set_sflow_agent` | `(conn, switch_id, agent) -> None` | Remembers the sFlow agent address NXray set on a switch, so the collector knows its datagrams | `routes/traffic.traffic_sflow_setup` | v0.2.0 |
| `set_unsaved_changes` | `(conn, switch_id, unsaved: bool) -> None` | Remembers whether NXray changed the switch since the last Save config | `routes/ports`, `routes/vlans`, `routes/features`, `routes/neighbors`, `routes/port_channels`, `routes/switch_page.switch_save` | v0.1.0 |

`SwitchConnection.changes_enabled` and `paused_seconds()` say whether port
changes are on and how long NXray still waits before calling the switch;
`vlan_changes_enabled` says whether the role includes the VLAN rules
(`role_version` 2 or later), `settings_changes_enabled`,
`feature_changes_enabled`, `neighbor_changes_enabled`,
`channel_changes_enabled`, `layer3_changes_enabled`, `vrf_changes_enabled` and
`route_changes_enabled` the later rule sets (3, 4, 5, 6, 7, 8 and 9). `vlan_interface_changes_enabled` also needs
`role_vlan_interfaces`: the role's port list names the VLAN interfaces, which
the switch takes only while interface-vlan is on.

## `app/switch_choice.py` — which switch a browser is looking at

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `choose_switch` | `(request, switch_id) -> None` | Makes that switch the one for the rest of this request (after adding, forgetting or picking one) | `routes/switch_page` | v0.1.0 |
| `remember_switch` | `(request, response) -> Response` | Sets the `nxray_switch` cookie to the switch the request ended on (deletes it with none) | `routes/switch_page` | v0.1.0 |
| `resolve_switch_id` | `(conn, wanted) -> int \| None` | `wanted` when that switch exists, else the first one added; None with none | `selected_switch_id`, `routes/switch_page.switch_forget` | v0.1.0 |
| `selected_switch_id` | `(request) -> int \| None` | The switch this request is for, from the cookie; looked up once per request | `dependencies.stored_switch`, `security.csrf_token`, every route that stores something per switch | v0.1.0 |

`SWITCH_COOKIE` is the cookie's name.

## `app/preferences.py` — how a browser wants NXray to look

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `remember_preferences` | `(request, response, *, theme="", menu="", live="") -> Response` | Sets the `nxray_theme` / `nxray_menu` / `nxray_live` cookie for whichever value is known; ignores anything else | `routes/preferences.preferences` | v0.1.0 |
| `ui_preferences` | `(request) -> UiPreferences` | The theme (`system`, `light`, `dark`), menu width (`wide`, `narrow`) and refresh interval (`LIVE_CHOICES`, default `off`) this browser picked; the defaults for anything unknown | `base.html` (template global) | v0.1.0 |

## `app/switch_setup.py` — creating NXray's account

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `account_names` | `(user_account_body) -> set[str]` | Lower-cased local account names from `show user-account` | `switch_setup.run_setup`, `switch_repair.run_repair` | v0.1.0 |
| `password_strong_enough` | `(password) -> bool` | True when NX-OS's password strength check takes it: upper, lower, digits, no runs like `aaa` or `abc` | `generate_password`, `switch_accounts.check_switch_side_password` | v0.2.0 |
| `check_connection` | `(target, transport=None) -> ConnectionStatus` | Signs in with NXray's account and reads `show version` | Switch page Test connection | v0.1.0 |
| `connection_error` | `(exc, target) -> str` | The message for a failed call with NXray's own account, password scrubbed | `check_connection`, `read_switch` | v0.1.0 |
| `describe_error` | `(exc, host, port, who) -> str` | Plain-words message for an NX-API failure, with the fix | `run_setup`, `connection_error` | v0.1.0 |
| `load_dashboard_status` | `(target, transport=None) -> tuple[ConnectionStatus, Dashboard \| None]` | The whole dashboard from one request, or why it failed | `routes/dashboard.dashboard` | v0.1.0 |
| `read_switch` | `(target, reader, transport=None) -> tuple[ConnectionStatus, T \| None]` | Runs `reader(client)` with NXray's account; result or the failure message | `load_dashboard_status`, `routes/ports` | v0.1.0 |
| `generate_password` | `() -> str` | 32 random letters and digits that pass NX-OS's strength check | `switch_setup.run_setup`, `switch_repair.run_repair` | v0.1.0 |
| `run_setup` | `(*, host, port, admin_user, admin_password, account_name, store, transport=None) -> SetupResult` | Creates the account, checks it signs in, stores it, saves the config; undoes the account if a later step fails | `routes/switch_page.switch_setup` | v0.1.0 |
| `scrub_secrets` | `(text, *secrets_to_hide) -> str` | The text with every secret given replaced by `***`, for a page or a log | `run_setup`, `connection_error`, `switch_accounts.run_as_admin`, `switch_repair`, `port_changes`, `protocols`, `routes/protocols`, `routes/config_page` | v0.2.0 |
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
| `reload_switch` | `(*, host, port, username, password, timeout, opener=None) -> None` | Types `terminal dont-ask` and `reload`; the session dropping means the switch is restarting, a prompt coming back raises SshCommandError | `routes/config_page.config_reload` | v0.1.0 |
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
| `enable_port_changes` | `(*, host, nxapi_port, ssh_port, admin_user, admin_password, account_name, role_version=0, vlan_interfaces_listed=False, mode="limited", previous_mode=None, transport=None, ssh_opener=None) -> EnableResult` | Creates the `nxray-ports` role over SSH in the role `mode` (limited, broad or stored; `previous_mode` is the one it has now), gives it to NXray's account, checks it took, saves the config; reads `show feature` and names the VLAN interfaces only while interface-vlan is on; when the port list gains a line (`role_version` below 7, or the VLAN interfaces for the first time) the check and save go over SSH, which does not depend on NX-API answering | `routes/switch_page.switch_enable_changes`, `switch_setup` | v0.1.0 |
| `front_ports` | `(interface_brief_body) -> list[str]` | Every front-panel Ethernet port name | `enable_port_changes` | v0.1.0 |
| `pause_seconds` | `(nxapi_body) -> int` | NX-API's idle timeout plus a minute: how long NXray waits for the switch to apply the role | `enable_port_changes`, `switch_repair.run_repair` | v0.1.0 |
| `missing_changes` | `(role_version: int) -> str` | The kinds of change a role of that version lacks, in words (`neighbor and port-channel changes`); `""` when none | `routes/switch_page` (button names, notices) | v0.1.0 |
| `role_lines` | `(ports, account_name, vlan_interfaces=True, mode="limited", previous_mode=None) -> list[str]` | The configuration lines for the role and for giving it to the account, from checked values; a changed mode first removes every rule of the old one (`no rule N`); the VLAN interfaces' port-list line only with `vlan_interfaces` (the switch refuses it while interface-vlan is off) | `enable_port_changes` | v0.1.0 |
| `rules_for_mode` | `(mode) -> tuple[str, ...]` | The role's command rules in a mode: the broad set, or the listed rules (shared by the limited and stored-login modes); `ValueError` for an unknown mode | `role_lines` | v0.1.0 |
| `check_role_mode` | `(mode) -> str` | `mode` when it is a role mode, else `ValueError` | `rules_for_mode` | v0.1.0 |

`ROLE_RULES` (ports), `VLAN_RULES`, `SETTINGS_RULES`, `FEATURE_RULES`,
`NEIGHBOR_RULES`, `CHANNEL_RULES`, `LAYER3_RULES`, `VRF_RULES`, `ROUTE_RULES`,
`PROTOCOL_RULES`, `STP_RULES`, `ADMIN_RULES`, `SECURITY_RULES`, `LAYER2_RULES` and
`TRAFFIC_RULES` are the role's only rules, and its port list names the front ports one by one plus every
port-channel (`CHANNEL_PERMIT`) and every VLAN interface
(`VLAN_INTERFACE_PERMIT`); `ROLE_NAME` is `nxray-ports`, shared by every NXray
install on a switch. `ROLE_VERSION` counts the rule sets (1 ports, 2 ports and
VLANs, 3 also port settings, 4 also features, 5 also CDP and LLDP per port and
the MAC address table, 6 also port-channels and LACP, 7 also VLAN interfaces
and IPv4 and IPv6 addresses, with `VLAN_INTERFACE_PERMIT` in the port list, 8
also VRFs, 9 also static routes, 10 also routing protocols, 11 also spanning
tree, 12 also switch admin and reading the running configuration, 13 also ACLs,
port security, reading the saved configuration and NXray's checkpoints, 14 also
DHCP snooping and relay, ARP inspection, IP Source Guard, MAC ACLs, object
groups, VLAN access maps and TCAM regions, 15 also how long the front ports
average their rates over, `TRAFFIC_RULES`). `EnableResult.had_role`
is true when the account already had the role, so only its rules changed and
the switch applies them at once and there is no wait.

## `app/role_upgrade.py` — new role rules with the stored admin login

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `needs_upgrade` | `(connection) -> bool` | True when the switch is in the stored-login mode and its role lacks rules this version knows | `upgrade_stored_roles` | v0.1.0 |
| `upgrade_stored_roles` | `(settings, *, transport=None, ssh_opener=None, alert_transport=None) -> int` | Adds the new rules to the role of every such switch with the stored admin login, at start-up; logs a failure and never raises | `main.lifespan` | v0.1.0 |

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
| `plan_port_vlans` | `(current, view, *, mode, access_vlan, native_vlan, allowed) -> PortVlanChange` | Checks a port's VLAN form against the switch (VLANs must exist), adds a trunk's native VLAN to the VLANs it carries (`PortVlanChange.native_added`), sets an access port's leftover trunk native and allowed VLANs back to the defaults (`trunk_reset`) and keeps only what changes | `routes/ports.port_vlans_change` | v0.1.0 |
| `vlan_grid` | `(view) -> tuple[list[str], list[tuple[Vlan, list[str]]]]` | The VLANs page's grid: the ports that carry VLANs (Ethernet in front-panel order, then port-channels) and each VLAN's mark on each | `routes/vlans` | v0.1.0 |
| `vlan_interface_ids` | `(brief_body) -> frozenset[int]` | The VLANs that have a VLAN interface, from `show interface brief` | `load_vlan_page` | v0.1.0 |
| `vlan_mark` | `(port, vlan_id) -> str` | How a port carries a VLAN: `U` untagged (access VLAN, or a trunk's native VLAN it carries), `T` tagged, `""` not at all | `vlan_grid` | v0.1.0 |

`PortVlans.uses(vlan_id)` says whether deleting a VLAN would cut a port off
(access VLAN, native VLAN, or a trunk naming it; a trunk carrying every VLAN
does not count); `VlanView.ports_using(vlan_id)` lists those ports.
`PortVlans.native_carried` is False for a trunk whose native VLAN is not
among the VLANs it carries, so the switch drops its untagged traffic.

## `app/port_settings.py` — port settings and breakout

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `describe_port_settings` | `(current, change, *, up) -> tuple[list[str], list[str]]` | A port's settings change in words, plus warnings (link drops, layer change, smaller MTU, shutdown action) | `routes/ports.port_settings_change` | v0.1.0 |
| `guess_breakout_map` | `(sibling_speeds: list[str]) -> str \| None` | The split four ports were made with (`10g-4x`, `25g-4x`) from their speed column, or None | `routes/ports` | v0.1.0 |
| `load_interval_label` | `(seconds: int) -> str` | `30` -> `30 seconds (the switch's default)`, `60` -> `1 minute`, `0` -> `unknown` | `plan_load_interval`, port page | v0.2.0 |
| `load_port_settings` | `(client, port, vlans) -> PortSettings` | One port's settings, from one request of `settings_commands` | `try_load_port_settings` | v0.1.0 |
| `parse_ip_addresses` | `(body) -> dict[str, tuple[str, str]]` | Each port's IPv4 address with prefix, and its VRF, from `show ip interface vrf all` | `parse_port_settings` | v0.1.0 |
| `parse_port_settings` | `(port, vlans, capabilities_body, flowcontrol_body, storm_body, ip_body, ipv6_body=None) -> PortSettings` | One port's speed, duplex, MTU, FEC, flow control, storm control, layer, addresses (main and extra IPv4, IPv6) and breakout | `load_port_settings` | v0.1.0 |
| `plan_breakout` | `(settings, action, mapping) -> BreakoutPlan` | Checks a split or join against the port, with its lines and warnings for the confirm page | `routes/ports.port_breakout` | v0.1.0 |
| `plan_load_interval` | `(name, current, choice) -> LoadIntervalPlan` | Checks a rate-average choice (one of `LOAD_INTERVALS`, or `default`) against what the port has; `empty` when it already has it, else the confirm page's line and a warning for a shorter average | `routes/ports.port_rate_interval_change` | v0.2.0 |
| `plan_port_settings` | `(current, form) -> SettingsChange` | Checks the settings form against the port (speeds it can run, MTU for its layer, FEC, levels) and keeps only what changes | `routes/ports.port_settings_change` | v0.1.0 |
| `settings_form` | `(current) -> dict[str, str]` | The settings form filled with what the switch reports now (empty storm level = no limit), as `plan_port_settings` takes it | `routes/ports.port_forms`, `port_bulk.plan_port` | v0.2.0 |
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
| `change_refused` | `(exc, target) -> str` | The message for a port, VLAN or settings change the switch did not make; a port the role does not name points to Update the port list | `port_change`, `ports_bulk_change`, `port_vlans_change`, `port_settings_change`, `port_breakout`, `port_discovery_change`, `routes/vlans`, `routes/features`, `routes/neighbors` | v0.1.0 |
| `feature_set` | `(request, username, csrf, name, state, confirm) -> Response` | `POST /features/set`: asks to confirm, then turns one feature on or off; admin only; refuses what `Feature.refusal` names | router | v0.1.0 |
| `features_page` | `(request, username) -> Response` | `GET /features`: every switch feature by group with its state, read live; every role looks, admins change | router | v0.1.0 |
| `device_rows` | `(sends, receives, neighbors) -> list[DeviceRow]` | The Traffic page's busiest devices both ways, with each one's maker, IP addresses and port from the MAC and ARP tables | `routes/traffic._render` | v0.2.0 |
| `render_traffic_page` | `(request, username, *, error=None, notice=None) -> Response` | Reads the switch fresh and shows the Traffic page with a message | `routes/switch_page.switch_save` | v0.2.0 |
| `traffic_page` | `(request, username) -> Response` | `GET /traffic?range=&mac=`: traffic per VLAN and per device measured with sFlow, the collector's state and sFlow on the switch; every role looks | router | v0.2.0 |
| `traffic_sflow_off` | `(request, username, csrf, confirm) -> Response` | `POST /traffic/sflow-off`: asks to confirm, then turns the sflow feature off; needs traffic measuring changes | router | v0.2.0 |
| `traffic_sflow_setup` | `(request, username, csrf, collector, vrf, collector_port, agent, sampling_rate, scope, ports, confirm) -> Response` | `POST /traffic/sflow`: asks to confirm, then turns sflow on if needed and sends only what changes; stores the agent address; needs traffic measuring changes | router | v0.2.0 |
| `healthz` | `() -> dict[str, str]` | `GET /healthz`, unauthenticated liveness | router, container healthcheck | v0.1.0 |
| `settings_certificate` | `(request, username, csrf, cert_file, key_file) -> Response` | `POST /settings/certificate`: checks and installs an uploaded certificate, admin only | router | v0.1.0 |
| `settings_page` | `(request, username) -> Response` | `GET /settings`, built-in HTTPS, its certificate and self-update, admin only | router | v0.1.0 |
| `settings_update_beta` | `(request, username, csrf, include_beta) -> Response` | `POST /settings/update/beta`: stores **Include beta versions** and checks again; refused while an update runs | router | v0.2.0 |
| `settings_update_apply` | `(request, username, csrf) -> Response` | `POST /settings/update/apply`: refuses unless an update is waiting and none is running, then starts it | router | v0.1.0 |
| `settings_update_check` | `(request, username, csrf) -> Response` | `POST /settings/update/check`: compares ghcr.io with this container now | router | v0.1.0 |
| `settings_update_dismiss` | `(request, username, csrf) -> Response` | `POST /settings/update/dismiss`: hides the last update result | router | v0.1.0 |
| `login_2fa_form` | `(request, next: str = "/") -> Response` | `GET /login/2fa`, the code step; back to `/login` without a recent password step | router | v0.1.0 |
| `login_2fa_submit` | `(request, code, next) -> Response` | `POST /login/2fa`: an app code (once) or a backup code, throttled like sign-in | router | v0.1.0 |
| `login_form` | `(request, next: str = "/") -> Response` | `GET /login` | router | v0.1.0 |
| `login_submit` | `(request, username, password, next) -> Response` | `POST /login`; for an account with two-factor, on to `/login/2fa` without a session | router | v0.1.0 |
| `logout` | `(request) -> Response` | `POST /logout` | router | v0.1.0 |
| `learned_macs_clear` | `(request, username, csrf, scope, port, vlan, mac, back, show, color, confirm) -> Response` | `POST /neighbors/clear`: asks to confirm, then clears learned addresses (all, one port, one VLAN or one address); `back=port` answers on that port's page, `back=ports` on the Ports page with its side panel open | router | v0.1.0 |
| `mac_aging_change` | `(request, username, csrf, aging, confirm) -> Response` | `POST /neighbors/aging`: asks to confirm, then sets how long learned addresses are kept | router | v0.1.0 |
| `neighbors_page` | `(request, username, q) -> Response` | `GET /neighbors?q=`: CDP and LLDP neighbors, the MAC address table (narrowed by the search), static addresses and ARP, read live; every role; operators and admins also get the MAC table's change forms | router | v0.1.0 |
| `channel_add` | `(request, username, csrf, number, port, mode, fast_rate, confirm) -> Response` | `POST /port-channels/add`: asks to confirm, then puts a free port into a port-channel, joining the way its ports did | router | v0.1.0 |
| `channel_create` | `(request, username, csrf, number, ports, mode, fast_rate, description, confirm) -> Response` | `POST /port-channels/create`: asks to confirm, then makes a port-channel from free ports | router | v0.1.0 |
| `channel_delete` | `(request, username, csrf, number, confirm) -> Response` | `POST /port-channels/delete`: refuses a port-channel that still has ports (naming them), else asks to confirm and deletes it | router | v0.1.0 |
| `channel_remove` | `(request, username, csrf, port, confirm) -> Response` | `POST /port-channels/remove`: asks to confirm, then takes a port out of its port-channel | router | v0.1.0 |
| `channel_reset` | `(request, username, csrf, number, confirm) -> Response` | `POST /port-channels/reset`: asks to confirm, then resets a port-channel's own settings (`default interface`); needs reset changes (role version 16) | router | v0.2.0 |
| `channel_settings` | `(request, username, csrf, number, description, min_links, confirm) -> Response` | `POST /port-channels/settings`: asks to confirm, then sets a port-channel's description and LACP minimum links | router | v0.1.0 |
| `port_channels_page` | `(request, username) -> Response` | `GET /port-channels`: every port-channel with its ports, how they joined, their LACP rate and priority and the device at the other end, read live; operators and admins change them | router | v0.1.0 |
| `port_lacp` | `(request, username, csrf, port, rate, priority, confirm) -> Response` | `POST /port-channels/port-lacp`: asks to confirm, then sets one member's LACP rate and port priority; a rate change only while the port is off | router | v0.1.0 |
| `render_port_channels_page` | `(request, username, *, error=None, notice=None) -> Response` | Reads the switch and shows the Port-channels page with a message | `switch_save` | v0.1.0 |
| `system_priority` | `(request, username, csrf, priority, confirm) -> Response` | `POST /port-channels/system-priority`: asks to confirm, then sets the switch's LACP priority | router | v0.1.0 |
| `port_breakout` | `(request, username, csrf, name, action, mapping, back, show, color, confirm) -> Response` | `POST /ports/breakout`: asks to confirm, then splits a 100G port into four or joins them, and shows the port that replaced it (its page, or its side panel when `back=ports`) | router | v0.1.0 |
| `port_change` | `(request, username, csrf, name, action, description, back, show, color, confirm) -> Response` | `POST /ports/change`: asks to confirm, then changes one port's description or on/off; `back=ports` answers on the Ports page with the port's side panel open | router | v0.1.0 |
| `port_discovery_change` | `(request, username, csrf, name, cdp, lldp_transmit, lldp_receive, lldp_shown, back, show, color, confirm) -> Response` | `POST /ports/discovery`: asks to confirm, then turns CDP and LLDP sending and listening on or off on one port; an unticked box means off | router | v0.1.0 |
| `port_detail` | `(request, name, username) -> Response` | `GET /ports/detail?name=`, one port with its VLANs, settings and connected devices; 404 for an unknown name | router | v0.1.0 |
| `port_rate_interval_change` | `(request, username, csrf, name, seconds, back, show, color, confirm) -> Response` | `POST /ports/rate-interval`: asks to confirm, then sets how long the switch averages one port's In and Out over; needs traffic measuring changes (role version 15) | router | v0.2.0 |
| `port_reset` | `(request, username, csrf, name, back, show, color, confirm) -> Response` | `POST /ports/reset`: asks to confirm, then resets one port to how it came out of the box (`default interface`); needs reset changes (role version 16); `back=ports` answers on the Ports page with the port's side panel open | router | v0.2.0 |
| `ports_reset_bulk` | `(request, username, csrf, names, show, color, confirm) -> Response` | `POST /ports/reset-bulk`: asks to confirm, naming every ticked port and what it removes, then resets each; needs reset changes (role version 16) | router | v0.2.0 |
| `port_settings_change` | `(request, username, csrf, name, layer, ip_address, speed, mtu, fec, flow_receive, flow_send, storm_broadcast, storm_multicast, storm_unicast, storm_action, back, show, color, confirm) -> Response` | `POST /ports/settings`: asks to confirm, then sends only the settings that change | router | v0.1.0 |
| `port_vlans_change` | `(request, username, csrf, name, mode, access_vlan, native_vlan, allowed, back, show, color, confirm) -> Response` | `POST /ports/vlans`: asks to confirm, then sets one port's mode and VLANs | router | v0.1.0 |
| `port_label` | `(request, username, csrf, name, label, back, show, color) -> Response` | `POST /ports/label`: stores or removes a port's label in NXray, operator or admin; the switch is not called to change anything | router | v0.1.0 |
| `ports_origin` | `(back, show, color) -> PortsOrigin \| None` | For `back=ports`, the Ports page filter and colour mode a change from a port's side panel answers on (unknown values fall back to the defaults); else None, the port's own page | the `routes/ports` change routes, `learned_macs_clear`, `switch_save` | v0.1.1 |
| `port_forms` | `(request, name, ports, view, port_settings, neighbors, discovery, *, description=None, vlan_form=None, settings_form=None, label=None) -> dict` | What the forms that change one port need (`_port_forms.html`), for its own page and its side panel alike; the keyword values keep what was typed after a refusal | `_render_port`, `render_ports_page` | v0.1.1 |
| `answer_port_change` | `(request, username, name, origin, found=None, **kwargs) -> Response` | The page a change of one port answers on: its own page, or the Ports page with its side panel open when `origin` is set | the `routes/ports` change routes, `learned_macs_clear` | v0.1.1 |
| `change_back` | `(origin, name) -> tuple[str, str]` | Where a confirm page's Cancel goes for a change of one port, and its words: the side panel or the port's page | the `routes/ports` change routes, `learned_macs_clear` | v0.1.1 |
| `live_ports_link` | `(show, color, port="") -> str` | The address of the Ports page's refreshing figures for the same filter, colour and open panel | `render_ports_page` | v0.2.0 |
| `ports_summary` | `(ports, neighbors, show) -> (channels, shown, counts)` | Each port's port-channel, the ports a filter keeps and how many each filter keeps | `render_ports_page`, `routes/live.live_ports` | v0.2.0 |
| `ports_link` | `(show, color, port="") -> str` | The Ports page's address with a filter, a colour mode and the port whose side panel is open | `render_ports_page`, `ports.html` | v0.1.0 |
| `ports_page` | `(request, username, show, color, select, port, tick) -> Response` | `GET /ports?show=<filter>&color=state\|speed\|vlan\|channel\|traffic\|errors&select=all&tick=<name>&port=<name>`: the front panel and the table (`select=all` ticks every port shown; each `tick` keeps that port ticked, as `static/keep-ticks.js` asks when a colour tab, filter or Read again is followed; `port` opens that port's side panel); only `vlan` and an open side panel also read the VLANs (the panel also its port's settings and CDP/LLDP); every mode reads the neighbors and MAC address table | router | v0.1.0 |
| `preferences` | `(request, username, csrf, theme, menu, live, next) -> Response` | `POST /preferences`, the theme, menu-width and refresh buttons (any role): sets the cookie and goes back to `next` | router | v0.1.0 |
| `ports_bulk_change` | `(request, username, csrf, names, power, set_description, description, mode, access_vlan, native_vlan, allowed, layer, speed, mtu, fec, flow_receive, flow_send, storm_broadcast, storm_multicast, storm_unicast, storm_action, cdp, lldp_transmit, lldp_receive, clear_macs, start, fill, show, color, confirm) -> Response` | `POST /ports/bulk`: applies one shared configuration (see `app/port_bulk.py`) to every ticked port; each kind of change needs its own switch on the Switch page; asks to confirm, listing every port with old → new, then sends each port's changes one request per kind, through the same `NxapiClient` methods as a single port; the first refusal stops the rest and the page names what changed (in part, too), what was refused and what was not tried. With `fill=yes`, fills the form from the port named in `start` and changes nothing | router | v0.2.0 |
| `render_ports_page` | `(request, username, *, show="all", color="state", error=None, notice=None, tick_all=False, ticked=None, bulk=None, selected="", form_values=None, found=None, status_code=200) -> Response` | Reads the switch and shows the Ports page with a message, keeping ticked ports and what the shared form holds after a refusal or a fill from one port; with `selected`, that port's side panel is open with every change form, `form_values` keeping what was typed in one after a refusal | `ports_page`, `ports_bulk_change`, `answer_port_change`, `switch_save` | v0.1.0 |
| `render_port_page` | `(request, username, name, *, error=None, notice=None) -> Response` | Reads the switch and shows one port's page with a message | `port_detail`, `switch_save` | v0.1.0 |
| `render_neighbors_page` | `(request, username, *, error=None, notice=None) -> Response` | Reads the switch and shows the Neighbors page with a message | `switch_save` | v0.1.0 |
| `render_features_page` | `(request, username, *, error=None, notice=None) -> Response` | Reads the switch and shows the Features page with a message | `switch_save` | v0.1.0 |
| `form_fields` | `(request) -> dict[str, str]` | The posted form as plain strings, for the protocol forms whose field names vary | `protocol_change`, `spanning_tree_change`, `switch_admin_change` | v0.1.0 |
| `render_protocols_page` | `(request, username, *, error=None, notice=None) -> Response` | Reads the switch and shows the Routing protocols overview with a message | `protocols_page`, `switch_save` | v0.1.0 |
| `protocols_page` | `(request, username) -> Response` | `GET /routing/protocols`: every protocol with whether its feature is on, and the route table per VRF | router | v0.1.0 |
| `render_protocol_page` | `(request, username, key, *, error=None, notice=None, form=None) -> Response` | Reads the switch and shows one protocol's page with a message; `form` keeps what was typed (never secrets) | `protocol_page`, `protocol_change`, `switch_save` | v0.1.0 |
| `protocol_page` | `(key, request, username) -> Response` | `GET /routing/protocols/<key>`: one protocol read live; every role looks, operators and admins change | router | v0.1.0 |
| `protocol_change` | `(key, request, username, form) -> Response` | `POST /routing/protocols/<key>/change`: checks the role version, feature, interface and VRF, asks to confirm showing the lines, then sends them; switch errors have secrets masked | router | v0.1.0 |
| `render_site_page` | `(request, username, proto, site, *, error=None, notice=None, form=None) -> Response` | Reads the switch and shows a page built from `app/protocols.py` (a protocol page, Spanning tree or Switch admin) with a message; the `ProtocolSite` says where it lives and how it reads, checks and sends | `render_protocol_page`, `render_spanning_tree_page`, `render_switch_admin_page`, `site_change` | v0.1.0 |
| `site_change` | `(request, username, form, proto, site) -> Response` | One change on such a page: CSRF, role version, feature, the place's identity values, confirm page with the lines, then sends and runs the site's `after`; switch errors have secrets masked; a change that is no configuration (`clock set`) asks for no save | `protocol_change`, `spanning_tree_change`, `switch_admin_change` | v0.1.0 |
| `render_spanning_tree_page` | `(request, username, *, error=None, notice=None, form=None) -> Response` | Reads the switch and shows the Spanning tree page with a message | `spanning_tree_page`, `switch_save` | v0.1.0 |
| `spanning_tree_page` | `(request, username) -> Response` | `GET /spanning-tree`: the trees, the ports in them and every setting, read live; every role looks, operators and admins change | router | v0.1.0 |
| `spanning_tree_change` | `(request, username, form) -> Response` | `POST /spanning-tree/change`: one change, after a confirm page showing the lines (role version 11) | router | v0.1.0 |
| `render_switch_admin_page` | `(request, username, *, error=None, notice=None, form=None) -> Response` | Reads the switch and shows the Switch admin page with a message | `switch_admin_page`, `switch_save` | v0.1.0 |
| `switch_admin_page` | `(request, username) -> Response` | `GET /switch-admin`: the hostname, clock, NTP, DNS, logging, SNMP and banner, read live; every role looks, operators and admins change | router | v0.1.0 |
| `switch_admin_change` | `(request, username, form) -> Response` | `POST /switch-admin/change`: one change, after a confirm page showing the lines (role version 12); a new hostname is stored too | router | v0.1.0 |
| `check_admin_place` | `(page, ident) -> None` | Refuses a VRF the switch lacks, and the default VRF where a VRF's own configuration is meant | `SITE.check_place` in `routes/switch_admin` | v0.1.0 |
| `switch_log_page` | `(request, username, lines, search, level) -> Response` | `GET /switch-admin/log?lines=&search=&level=`: the newest 50, 200 or 1000 lines of the switch's log, newest first, kept to those containing `search` and of `level` or worse; every role | router | v0.1.0 |
| `render_acls_page` | `(request, username, *, error=None, notice=None, form=None) -> Response` | Reads the switch and shows the ACLs page with a message | `acls_page`, `switch_save` | v0.1.0 |
| `acls_page` | `(request, username) -> Response` | `GET /security/acls`: the IPv4 and IPv6 ACLs, their entries and where they apply, read live; every role looks, operators and admins change | router | v0.1.0 |
| `acls_change` | `(request, username, form) -> Response` | `POST /security/acls/change`: one change, after a confirm page showing the lines (role version 13) | router | v0.1.0 |
| `check_acl_place` | `(page, ident) -> None` | Refuses a layer 3 interface or switched port the switch lacks, or of the other kind | `ACL_SITE.check_place` in `routes/security` | v0.1.0 |
| `render_port_security_page` | `(request, username, *, error=None, notice=None, form=None) -> Response` | Reads the switch and shows the Port security page with a message | `port_security_page`, `switch_save` | v0.1.0 |
| `port_security_page` | `(request, username) -> Response` | `GET /security/port-security`: each port's port security, read live; every role looks, operators and admins change | router | v0.1.0 |
| `port_security_change` | `(request, username, form) -> Response` | `POST /security/port-security/change`: one change, after a confirm page (role version 13, the port-security feature on) | router | v0.1.0 |
| `check_port_security_place` | `(page, ident) -> None` | Refuses a port that is not a switched front port | `PORT_SECURITY_SITE.check_place` in `routes/security` | v0.1.0 |
| `render_dhcp_page` | `(request, username, *, error=None, notice=None, form=None) -> Response` | Reads the switch and shows the DHCP and ARP page with a message | `dhcp_page`, `switch_save` | v0.1.0 |
| `dhcp_page` | `(request, username) -> Response` | `GET /security/dhcp`: DHCP snooping and relay, ARP inspection, IP Source Guard and the bindings, read live; every role looks, operators and admins change | router | v0.1.0 |
| `dhcp_change` | `(request, username, form) -> Response` | `POST /security/dhcp/change`: one change, after a confirm page showing the lines (role version 14, the dhcp feature on) | router | v0.1.0 |
| `check_dhcp_place` | `(page, ident) -> None` | Refuses a switched port or layer 3 interface the switch lacks, or of the other kind | `DHCP_SITE.check_place` in `routes/security` | v0.1.0 |
| `acl_needs` | `(connection, scope, setting) -> str` | Why the ACLs page may not make a change yet: MAC ACLs, object groups, VLAN access maps and TCAM regions need role version 14; "" when it may | `ACL_SITE.needs` in `routes/security` | v0.1.0 |
| `render_config_page` | `(request, username, *, error=None, notice=None, a="", b="") -> Response` | Reads the switch and shows the Config page: running against saved, the backups with their checkpoints, and a comparison of `a` with `b` | the `routes/config_page` routes, `switch_save` | v0.1.0 |
| `config_page` | `(request, username, a, b) -> Response` | `GET /config?a=&b=`: the Config page, comparing two of `running`, `startup` and `backup-<n>`; admins only | router | v0.1.0 |
| `config_download` | `(number, request, username) -> Response` | `GET /config/backup/<n>.txt`: one backup's text as a file; admins only | router | v0.1.0 |
| `config_backup` | `(request, username, csrf, note) -> Response` | `POST /config/backup`: store the running configuration, and make its `nxray-<n>` checkpoint when the role allows | router | v0.1.0 |
| `config_backup_delete` | `(request, username, csrf, id, confirm) -> Response` | `POST /config/backup/delete`: delete a backup and its checkpoint on the switch, after a confirm page | router | v0.1.0 |
| `config_rollback` | `(request, username, csrf, id, admin_user, admin_password, confirm) -> Response` | `POST /config/rollback`: shows what changes and asks for the switch admin login, then takes a backup of the configuration it replaces and rolls back with that login (never stored) | router | v0.1.0 |
| `config_reload` | `(request, username, csrf, admin_user, admin_password, ssh_port, save, confirm) -> Response` | `POST /config/reload`: with the restart rules in the role (v18) and nothing unsaved, restarts at once over NX-API; otherwise shows what is unsaved, saves first when asked (NXray's account) and restarts over NX-API, or over SSH with the switch admin login (never stored) while the role is older; admins only | router | v0.1.0 |
| `activity_page` | `(request, username, user, area, search) -> Response` | `GET /activity?user=&area=&search=`: who changed what through NXray, newest first; admins only | router | v0.1.0 |
| `activity_download` | `(request, username, user, area, search) -> Response` | `GET /activity.csv`: the same list as a CSV file | router | v0.1.0 |
| `alerts_page` | `(request, username) -> Response` | `GET /alerts`: the problems open now, the rules, e-mail, webhooks and the alerts sent; admins only | router | v0.1.0 |
| `alerts_rules` | `(request, username) -> Response` | `POST /alerts/rules`: what NXray alerts on | router | v0.1.0 |
| `alerts_email` | `(request, username, csrf, host, port, security, smtp_username, smtp_password, clear_password, sender, recipients) -> Response` | `POST /alerts/email`: the mail server and addresses; an empty password keeps the stored one | router | v0.1.0 |
| `alerts_email_delete` | `(request, username, csrf) -> Response` | `POST /alerts/email/delete`: forgets the e-mail settings | router | v0.1.0 |
| `alerts_email_test` | `(request, username, csrf) -> Response` | `POST /alerts/email/test`: sends a test e-mail now | router | v0.1.0 |
| `alerts_webhook_add` | `(request, username, csrf, name, url, format, secret) -> Response` | `POST /alerts/webhook/add`: keeps a webhook, URL and secret encrypted | router | v0.1.0 |
| `alerts_webhook_delete` | `(request, username, csrf, id) -> Response` | `POST /alerts/webhook/delete`: forgets one webhook | router | v0.1.0 |
| `alerts_webhook_test` | `(request, username, csrf, id) -> Response` | `POST /alerts/webhook/test`: sends a test to one webhook now | router | v0.1.0 |
| `check_stp_place` | `(page, ident) -> None` | Refuses a port that is not a switched front port or port-channel on the switch, or a VLAN the switch lacks | `SITE.check_place` | v0.1.0 |
| `render_routing_page` | `(request, username, *, error=None, notice=None) -> Response` | Reads the switch and shows the Routing page with a message | `switch_save` | v0.1.0 |
| `routing_page` | `(request, username) -> Response` | `GET /routing?vlan=`: VLAN interfaces and routed ports with their addresses, the VRFs and the static routes, read live; every role looks, operators and admins change; `vlan` picks that VLAN in the make form | router | v0.1.0 |
| `vlan_interface_create` | `(request, username, csrf, vlan, ipv4, ipv6, description, mtu, enabled, vrf, confirm) -> Response` | `POST /routing/vlan-interface/create`: asks to confirm, then makes a VLAN interface for a VLAN that has none, in the default VRF or another one | router | v0.1.0 |
| `vlan_interface_delete` | `(request, username, csrf, vlan, confirm) -> Response` | `POST /routing/vlan-interface/delete`: asks to confirm, then deletes a VLAN interface (never Vlan1); the VLAN stays | router | v0.1.0 |
| `vlan_interface_settings` | `(request, username, csrf, vlan, ipv4, description, mtu, state, confirm) -> Response` | `POST /routing/vlan-interface/settings`: asks to confirm, then sets a VLAN interface's main IPv4 address, description, MTU and on/off | router | v0.1.0 |
| `address_add` | `(request, username, csrf, name, address, confirm) -> Response` | `POST /routing/address/add`: asks to confirm, then puts an IPv4 (main or extra) or IPv6 address on a VLAN interface or routed port | router | v0.1.0 |
| `address_remove` | `(request, username, csrf, name, address, confirm) -> Response` | `POST /routing/address/remove`: asks to confirm, then takes one address off; the main IPv4 address only once the extra ones are gone | router | v0.1.0 |
| `route_add` | `(request, username, csrf, vrf, prefix, next_hop, confirm) -> Response` | `POST /routing/route/add`: asks to confirm (warning for a default route or an unreachable next hop), then adds a static route in default or a VRF | router | v0.1.0 |
| `route_remove` | `(request, username, csrf, vrf, prefix, next_hop, confirm) -> Response` | `POST /routing/route/remove`: asks to confirm, then removes a static route; never one in management | router | v0.1.0 |
| `vrf_create` | `(request, username, csrf, name, confirm) -> Response` | `POST /routing/vrf/create`: asks to confirm, then makes an empty VRF | router | v0.1.0 |
| `vrf_delete` | `(request, username, csrf, name, confirm) -> Response` | `POST /routing/vrf/delete`: refuses a VRF interfaces are in (naming them), else asks to confirm, then deletes it | router | v0.1.0 |
| `vrf_move` | `(request, username, csrf, name, vrf, confirm) -> Response` | `POST /routing/vrf/move`: asks to confirm, naming the addresses the switch deletes, then moves a VLAN interface or routed port into another VRF | router | v0.1.0 |
| `render_vlans_page` | `(request, username, *, error=None, notice=None) -> Response` | Reads the switch and shows the VLANs page with a message | `switch_save` | v0.1.0 |
| `switch_address` | `(request, username, csrf, host, port) -> Response` | `POST /switch/address`: signs in at the new address with NXray's account, then stores it; keeps the old one on failure | router | v0.1.0 |
| `switch_enable_changes` | `(request, username, csrf, admin_user, admin_password, ssh_port, confirm_save, role_mode) -> Response` | `POST /switch/enable-changes` and `POST /switch/role-mode` (the same handler), also the role mode change (blank `role_mode` keeps it; with the login stored and none typed, the stored one signs in), the Turn on port, VLAN, port settings, feature and neighbor changes button, the Turn on button for whatever an older role lacks (for example Turn on neighbor changes), and Update the port list | router | v0.1.0 |
| `switch_forget` | `(request, username, csrf) -> Response` | `POST /switch/forget`: forgets the switch shown, with what NXray kept about it; the pages then show the first switch left | router | v0.1.0 |
| `switch_forget_admin_login` | `(request, username, csrf) -> Response` | `POST /switch/forget-admin-login`: deletes the stored switch admin login; the switch goes from the stored-login mode back to the limited role, the role on the switch untouched | router | v0.1.0 |
| `switch_page` | `(request, username) -> Response` | `GET /switch`, the setup form, or the switch shown with every switch listed and a form to add another | router | v0.1.0 |
| `switches_select` | `(request, username, csrf, switch_id, next) -> Response` | `POST /switches/select`, the top bar's switch picker (any role): remembers the switch and goes back to `next` | router | v0.1.0 |
| `switch_repair` | `(request, username, csrf, host, port, admin_user, admin_password, confirm_save) -> Response` | `POST /switch/repair`, the Run setup again button; one switch change at a time | router | v0.1.0 |
| `switch_save` | `(request, username, csrf, back, port, protocol, show, color) -> Response` | `POST /switch/save`, the Save config button; answers on the page it was pressed on (a port's page, Ports with its filter, colour mode and open side panel, VLANs, Features, Neighbors, Port-channels, Routing, else Switch) | router | v0.1.0 |
| `switch_setup` | `(request, username, csrf, host, port, admin_user, admin_password, account_name, confirm_save, turn_on_changes, ssh_port) -> Response` | `POST /switch/setup`, one at a time: adds a switch (never one at an address already stored) and shows it; with Also turn on changes ticked, also gives the account the `nxray-ports` role with the same admin login, keeping the switch set up read-only if that step fails | router | v0.1.0 |
| `switch_test` | `(request, username, csrf) -> Response` | `POST /switch/test`, the Test connection button | router | v0.1.0 |
| `users_create` | `(request, username, csrf, new_username, password, confirm_password, role, switches, admin_user, admin_password, confirm_switch) -> Response` | `POST /users/create`, admin only; with switches ticked ("NXray and the switch") also makes a local account on each with the same name and password, after checking the switch's rules first and asking to confirm the role | router | v0.1.0 |
| `switch_status` | `(conn, user) -> list[dict]` | The user's switch accounts, each with its connection, link and what is out of step | `_render_users`, `account_page`, `account_password` | v0.2.0 |
| `user_switch_page` | `(request, user_id, username) -> Response` | `GET /users/switch`: one user's accounts on every switch, with the forms that change them; admin only | router | v0.2.0 |
| `render_user_switch` | `(request, username, user_id, *, error=None, notice=None, status_code=200) -> Response` | Reads each switch's local accounts with NXray's own account and shows the user's Switch accounts page | the `/users/switch` routes | v0.2.0 |
| `read_accounts` | `(request, connection) -> tuple[list[SwitchAccount] \| None, str \| None]` | A switch's local accounts read with NXray's own account, or why not | `render_user_switch`, `user_switch_link`, `routes/users._render_users` | v0.2.0 |
| `user_switch_create` | `(request, username, csrf, user_id, switch_id, password, confirm_password, admin_user, admin_password, confirm_roles) -> Response` | `POST /users/switch/create`: makes an existing user's account on one switch; the password typed becomes the NXray one too | router | v0.2.0 |
| `user_switch_link` | `(request, username, csrf, user_id, switch_id, account_name) -> Response` | `POST /users/switch/link`: links an account already on the switch; changes nothing there | router | v0.2.0 |
| `user_switch_password` | `(request, username, csrf, user_id, password, confirm_password, admin_user, admin_password) -> Response` | `POST /users/switch/password`: one new password for NXray and every linked switch account, both sides' rules checked first; opens a locked account; a switch that refuses stays out of step | router | v0.2.0 |
| `user_switch_roles` | `(request, username, csrf, user_id, switch_id, admin_user, admin_password) -> Response` | `POST /users/switch/roles`: gives the switch account the role its NXray role maps to; other roles stay | router | v0.2.0 |
| `user_switch_lock` | `(request, username, csrf, user_id, switch_id, admin_user, admin_password, confirm) -> Response` | `POST /users/switch/lock`: a random password nobody knows, saved so a restart keeps it locked | router | v0.2.0 |
| `user_switch_remove` | `(request, username, csrf, user_id, switch_id, admin_user, admin_password, confirm) -> Response` | `POST /users/switch/remove`: removes the account from the switch and the link; the NXray user stays | router | v0.2.0 |
| `user_switch_unlink` | `(request, username, csrf, user_id, switch_id) -> Response` | `POST /users/switch/unlink`: forgets the link; the switch is not touched | router | v0.2.0 |
| `create_with_switches` | `(request, username, user, password, switch_ids, admin_user, admin_password) -> tuple[list[str], list[str]]` | After an NXray user was added with switches ticked: makes its account on each; what was made, and what was not and why | `users_create` | v0.2.0 |
| `switch_account_create` | `(request, username, csrf, account_name, password, confirm_password, role, switches, admin_user, admin_password, confirm_switch) -> Response` | `POST /users/switch-account/create`: a local account on the ticked switches with no NXray user, checked on the switch's side first; the role is an NXray role's switch roles | router | v0.2.0 |
| `switch_account_delete_page` | `(request, name, switch_id, username) -> Response` | `GET /users/switch-account/delete`: every switch that has the account, who it is linked to there, and the confirm form | router | v0.2.0 |
| `switch_account_delete` | `(request, username, csrf, name, switches, admin_user, admin_password, confirm) -> Response` | `POST /users/switch-account/delete`: deletes a local account from the ticked switches; a linked NXray user stays, only the link goes | router | v0.2.0 |
| `render_switch_account_delete` | `(request, username, name, *, ticked=None, error=None, notice=None, status_code=200) -> Response` | The delete-a-switch-account page | `switch_account_delete_page`, `switch_account_delete` | v0.2.0 |
| `delete_on_switches` | `(request, username, name, connections, admin_user, admin_password) -> tuple[list[str], list[str]]` | Removes the account from each switch and any link to an NXray user there; what went and what stayed with why | `switch_account_delete`, `user_delete` | v0.2.0 |
| `user_delete_page` | `(request, user_id, username) -> Response` | `GET /users/delete`: what deleting an NXray user takes with it, with their linked switch accounts to tick | router | v0.2.0 |
| `user_delete` | `(request, username, csrf, user_id, switches, admin_user, admin_password, confirm) -> Response` | `POST /users/delete`: deletes the ticked switch accounts first, then the NXray user; a refusing switch keeps the user | router | v0.2.0 |
| `render_user_delete` | `(request, username, user_id, *, error=None, status_code=200) -> Response` | The delete-an-NXray-user page | `user_delete_page`, `user_delete` | v0.2.0 |
| `own_session` | `(request, target) -> str \| None` | This session's id when the target is the signed-in account, so a new password leaves it signed in | `routes/users`, `user_switch_create`, `user_switch_password` | v0.1.0 |
| `switch_ids` | `(values) -> list[int]` | The ticked switches of the Add an account form, as ids | `users_create` | v0.2.0 |
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
| `https_enabled` | `() -> bool` | `NXRAY_ENABLE_HTTPS` read by `config.env_bool`, so a value the app refuses is also refused here | `healthcheck.main` | v0.1.0 |
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
| `check_can_delete` | `(conn, user_id) -> User` | The account, or UserError when it is gone or is the only active admin | `delete_user`, `routes/switch_accounts.user_delete` | v0.2.0 |
| `delete_user` | `(conn, user_id) -> User` | Deletes an account, its links to switch accounts and its sessions; keeps the last active admin | `routes/switch_accounts.user_delete` | v0.2.0 |
| `set_password` | `(conn, user_id, password, *, keep_session=None) -> None` | Stores a new password and signs the account out everywhere but `keep_session` | `routes/users`, `resetpw.main` | v0.1.0 |
| `set_role` | `(conn, user_id, role) -> User` | Changes an account's role; keeps the last active admin | `routes/users.users_role` | v0.1.0 |
| `turn_off_two_factor` | `(conn, user_id) -> User` | Turns two-factor off and forgets the key and backup codes | `routes/users`, `resetpw.main` | v0.1.0 |
| `two_factor_secret` | `(user, secret_key) -> str \| None` | The key in plain text, None if missing or unreadable | `users.check_second_factor`, `routes/users.account_2fa_confirm` | v0.1.0 |

`ROLES` is the three roles, `ROLE_HELP` says what each may do in words, and
`User.can_change` / `User.is_admin` are what the route guards test.
`User.backup_codes_left` is how many unused backup codes an account has.

## `app/switch_accounts.py` — switch accounts for NXray users

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `bring_roles_in_step` | `(client, name, wanted) -> tuple[str, ...]` | Adds the wanted roles the account lacks and takes off the other roles NXray gives people; any other role stays | `routes/switch_accounts.user_switch_roles` | v0.2.0 |
| `check_switch_name` | `(name) -> str` | The NXray username as a switch account name, or `ValueError` naming the switch's rule (format, reserved names) | `routes/users.users_create`, `routes/switch_accounts` | v0.2.0 |
| `check_switch_side_password` | `(password) -> None` | Raises `ValueError` saying it is the switch's rule: letters and digits only, and its strength check | `routes/users.users_create`, `routes/switch_accounts` | v0.2.0 |
| `create_on_switch` | `(client, name, password, roles) -> None` | Makes the account, unless the switch already has one by that name (to be linked instead, never overwritten) | `routes/switch_accounts` | v0.2.0 |
| `get_link` | `(conn, user_id, switch_id) -> AccountLink \| None` | One user's account on one switch, as NXray last left it | `routes/switch_accounts` | v0.2.0 |
| `guard_account` | `(name, connection) -> None` | Refuses NXray's own account on that switch and the names the switch keeps for itself (its admin among them) | every switch account change | v0.2.0 |
| `list_links` | `(conn, *, user_id=None) -> list[AccountLink]` | Every link, or one user's | `routes/users`, `routes/switch_accounts` | v0.2.0 |
| `load_switch_accounts` | `(client) -> list[SwitchAccount]` | The switch's local accounts from `show user-account` | `create_on_switch`, `bring_roles_in_step`, `routes/switch_accounts.read_accounts` | v0.2.0 |
| `remove_from_switch` | `(client, name) -> None` | Removes a local account, or says the switch has none by that name | `routes/switch_accounts.delete_on_switches` | v0.2.0 |
| `lock_password` | `() -> str` | A random password nobody sees, which locks a switch account | `routes/switch_accounts.user_switch_lock` | v0.2.0 |
| `out_of_step` | `(user, link, connection) -> list[str]` | What differs between the NXray user and its switch account (role, password, disabled versus locked), in words | `routes/users`, `routes/switch_accounts` | v0.2.0 |
| `parse_user_accounts` | `(body) -> list[SwitchAccount]` | Every local account and its roles from `show user-account`, by name | `load_switch_accounts` | v0.2.0 |
| `remove_link` | `(conn, user_id, switch_id) -> None` | Forgets a link; the switch is not touched | `routes/switch_accounts` | v0.2.0 |
| `reserved` | `(name) -> bool` | True for a name NX-OS keeps for itself, or the switch's own admin account | `check_switch_name`, `guard_account`, the Users pages | v0.2.0 |
| `run_as_admin` | `(connection, admin_user, admin_password, change, *, secrets=(), transport=None) -> AccountChange` | Signs in with the admin login typed on the form, makes the change, saves the configuration; secrets scrubbed from every message; a failed save is returned, not raised | `routes/switch_accounts` | v0.2.0 |
| `save_link` | `(conn, user_id, switch_id, account_name, roles, *, password_set) -> None` | Records which switch account belongs to the user; refuses one another user has | `routes/switch_accounts` | v0.2.0 |
| `save_words` | `(change, connection) -> str` | What the page says about saving the switch configuration after a change (a restart undoes an unsaved one) | `routes/switch_accounts` | v0.2.0 |
| `switch_roles` | `(role, changes_on) -> tuple[str, ...]` | The switch roles for an NXray role: viewer network-operator, operator network-operator + nxray-ports (where changes are on), admin network-admin | `routes/users`, `routes/switch_accounts`, `out_of_step` | v0.2.0 |
| `update_link` | `(conn, user_id, switch_id, *, roles=None, password_set=False, locked=None) -> None` | Notes what NXray just changed on a linked account | `routes/switch_accounts` | v0.2.0 |

The commands come from `NxapiClient.create_person_account`,
`set_person_password`, `set_person_roles` and `remove_person_account`, kept
apart from `create_user` and `delete_user`, which exist only for NXray's own
account. Each takes only the roles in `PERSON_ROLES`. No switch password is
stored: `switch_accounts.password_set_at` and `users.password_changed_at` are
times, so out of step is worked out without one.

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
| `check_for_updates` | `(conn, *, dev_build=False) -> str` | Compares ghcr.io's digest for this container's tag with what runs, or, with betas on or a beta running, ranks the GitHub releases with `pick_target`; `"available"`, `"current"` or why nothing was compared | `routes/settings_page.settings_update_check`, `settings_update_beta`, `start_background_checker` | v0.1.0 |
| `clear_result` | `(conn) -> None` | Forgets the last update result | `routes/settings_page.settings_update_dismiss` | v0.1.0 |
| `current_state` | `(conn) -> UpdateState` | The update row, with an old success hidden | `routes/settings_page`, `watch_update` | v0.1.0 |
| `deployed_digests` | `(image_id) -> set[str] \| None` | Registry digests of the image the container runs; `None` for an image built locally | `check_for_updates` | v0.1.0 |
| `deployment` | `() -> Deployment \| None` | Asks Docker what this container was made from and which compose project owns it | `check_for_updates`, `start_update` | v0.1.0 |
| `finish_pending_update` | `(conn) -> None` | At start: an update still running means this is its replacement, so record success | `main.lifespan` | v0.1.0 |
| `github_releases` | `() -> list[str] \| None` | The version names of NXray's published releases and betas from api.github.com, drafts left out; `None` on any failure | `check_for_updates` | v0.2.0 |
| `ghcr_digest` | `(tag) -> str \| None` | The digest ghcr.io has for a tag; `None` on any failure | `check_for_updates` | v0.1.0 |
| `is_beta` | `(text) -> bool` | Whether a version names a beta (`0.2.0-beta.1`) | `check_for_updates`, `routes/settings_page` | v0.2.0 |
| `own_container` | `() -> str` | The name Docker knows this container by (its hostname) | `deployment` | v0.1.0 |
| `parse_version` | `(text) -> Version \| None` | A sortable key for `0.2.0`, `v0.2.0` or `0.2.0-beta.3`: numbers first, a release above its betas; `None` for anything else | `pick_target`, `is_beta` | v0.2.0 |
| `pick_target` | `(running, releases, include_beta) -> Target \| None` | The tag to move to (`:beta` while a beta is ahead of the latest release and betas are on, else `:latest`) and its version; `None` unless it is newer than `running` | `check_for_updates` | v0.2.0 |
| `reap_stalled_update` | `(conn) -> None` | Fails an update that never replaced the container | `routes/settings_page` | v0.1.0 |
| `running_version` | `() -> str` | The version of the code in this container (`app.__version__`, which a beta image carries with its beta name) | `check_for_updates`, `routes/settings_page` | v0.2.0 |
| `set_include_beta` | `(conn, include) -> None` | Stores the **Include beta versions** choice; installs nothing | `routes/settings_page.settings_update_beta` | v0.2.0 |
| `start_background_checker` | `(settings) -> None` | Checks once a day on a thread; does nothing with self-update off | `main.lifespan` | v0.1.0 |
| `start_update` | `(conn) -> str \| None` | Refuses an image or container compose did not make, else marks the update running and launches the recreator with the chosen tag as `NXRAY_TAG` | `apply_update` | v0.1.0 |
| `watch_update` | `(db_path) -> None` | Waits for the recreator; records a failure (or a no-op success) if this container is still alive | `apply_update` | v0.1.0 |

## `app/live.py` — figures that refresh themselves

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `health_figures` | `(value) -> (cpu, memory)` | What the trail keeps of a dashboard reading: CPU and memory in use, in percent (None when not given) | `routes/live.live_dashboard` | v0.2.0 |
| `health_trail_chart` | `(trail, *, now, floor) -> ChartView` | The dashboard's CPU and memory chart of the last `TRAIL_SECONDS`, from the trail; says how to fill it when empty | `routes/dashboard`, `routes/live.live_dashboard` | v0.2.0 |
| `measure_rates` | `(previous, ports, now) -> PortReading` | A reading of every port with In and Out also worked out from how far the byte counters moved since `previous`; a port that was down or whose counters were cleared keeps the switch's figure; no rate after a gap of over 120 s | `routes/live.shared_readings` | v0.2.0 |
| `port_figures` | `(reading) -> dict[str, PortFigures]` | What the trail keeps of one port reading: each port's state, the switch's averages and the measured rates (None without an earlier reading) | `routes/live.shared_readings` | v0.2.0 |
| `port_trail_chart` | `(trail, name, *, measured, now, floor) -> ChartView` | One port's In and Out over the last `TRAIL_SECONDS` from the trail, measured (Live) or the switch's averages; a down port or an unmeasured reading leaves a gap | `routes/ports._render_port`, `routes/live.live_port` | v0.2.0 |
| `refreshes_whole_page` | `(method, path) -> bool` | True for a page shown by GET that reads the switch and nothing else changes on (VLANs, Traffic, Routing, Switch ...), which the Refresh box re-reads as a whole; a template global | `base.html`, `dependencies.share_switch_reads` | v0.2.0 |
| `shared_show_reads` | `(cache, floor, text_floor) -> share` | The function `nxapi.shared_reads` holds for one whole-page refresh: each switch, account and command is read at most once per floor (`text_floor` for printed text), a rejected command is remembered as rejected, and each caller gets its own copy | `dependencies.share_switch_reads` | v0.2.0 |
| `pick_interval` | `(choice, floor) -> int` | Seconds between refreshes for a picked choice, never below the floor; 0 for Off or anything unknown | tests; `live.js` repeats the rule in the browser | v0.2.0 |

| `trail_spacing` | `(trail, floor) -> float` | The usual gap between a trail's readings (the median, never below `floor`), so a chart breaks its line only at a real gap | `port_trail_chart`, `health_trail_chart` | v0.2.0 |

`PortReading` (class) is one reading: `ports` (the switch's 30 s averages), `live` (counter-based rates), `window` seconds between the two readings, `at`.

`LiveCache` (class) keeps the newest reading per (switch id, kind):
`get(switch_id, kind, floor, reader)` runs `reader(previous)` only when the
reading is older than `floor`, one read at a time per key, keeps the last good
value and waits longer after each failure; with `figures=`, each fresh reading
also puts `figures(value)` on the entry's trail, the last `TRAIL_SECONDS` kept in
memory only and handed back as `LiveAnswer.trail`. `trail(switch_id, kind)`
returns that trail without reading the switch or counting as someone watching
(for a page opened while another browser's refresh runs). `LIVE_CHOICES` is the
list shown in the top bar. Held in `app.state.live_cache`.

## `app/routes/live.py` — the refresh answers

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `live_neighbors` | `(request, username, q) -> Response` | `GET /live/neighbors`: who announces themselves, the busiest devices and the MAC table narrowed by `q`; ports and tables read at the slower clients pace | router, `live.js` | v0.2.0 |
| `live_port` | `(request, username, name, rates) -> Response` | `GET /live/port`: one port's state, rates, counters and devices; 204 for an unknown port | router, `live.js` | v0.2.0 |
| `live_ports` | `(request, username, show, color, port, rates) -> Response` | `GET /live/ports`: the Ports page's counts, front panel and port rows (no VLAN colouring) | router, `live.js` | v0.2.0 |
| `live_dashboard` | `(request, username) -> Response` | `GET /live/dashboard`: the dashboard's figures alone, read through the cache; 204 with no switch | router, `live.js` | v0.2.0 |
| `live_problem_message` | `(answer) -> str` | The banner for a failed read, saying the figures shown are older and when NXray tries again | `live_dashboard` | v0.2.0 |
| `shared_readings` | `(request, switch_id, target, ports_floor=None) -> (LiveAnswer, NeighborView \| None)` | The newest port reading and neighbour/MAC reading through the cache, shared by every live page; `ports_floor` slows the port read for pages that need it less often | `live_ports`, `live_port`, `live_neighbors` | v0.2.0 |
| `no_cache` | `(response) -> Response` | Marks a response not to be stored by the browser | `live_dashboard` | v0.2.0 |

## `app/history.py` — history

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `bucket_seconds` | `(span: int) -> int` | How wide one chart point is: a minute at least, and at most 500 points | `system_charts`, `port_charts` | v0.1.0 |
| `build_rows` | `(environment, resources, ports, previous_errors) -> (rows, error_totals)` | The rows one sample stores; a port's errors as the increase since the last sample | `Sampler.sample_switch` | v0.1.0 |
| `chart_view` | `(title, lines, *, start, end, bucket, fmt, summarize=None, note="", empty=..., zero_based=True, y_max=None, anchor="") -> ChartView` | One chart's card: the SVG with a legend (now and highest unless `summarize` says otherwise), or the `empty` words when no line has a point | `system_charts`, `port_charts`, `vlan_charts`, `live.port_trail_chart`, `live.health_trail_chart` | v0.2.0 |
| `fill_zeros` | `(points, start, end, bucket) -> list` | Every bucket of a range, 0 where there is no point | `port_charts` | v0.1.0 |
| `last_sample_time` | `(conn, switch_id) -> float \| None` | When a switch's newest row was stored | `routes/history.history_page`, `latest_vlan_traffic` | v0.1.0 |
| `latest_vlan_traffic` | `(conn, switch_id, *, now, max_age) -> dict[int, (in, out)]` | Each VLAN's estimated traffic in a switch's newest sample; empty when that sample is older than `max_age` | `routes/vlans._vlan_traffic` | v0.2.0 |
| `percent_text` | `(value: float) -> str` | An axis value in percent, at most one decimal: `45.56` -> `45.6%` | the charts | v0.2.0 |
| `port_charts` | `(conn, switch_id, port, key, now) -> list[ChartView]` | One port's traffic and errors charts for a range | `routes/ports._render_port` | v0.1.0 |
| `purge` | `(conn, now, keep_days=30) -> int` | Deletes every switch's rows older than the retention; how many went | `start_sampler` | v0.1.0 |
| `rate_text` | `(value: float) -> str` | An axis rate: `500000000` -> `500 Mb/s` | the charts | v0.2.0 |
| `range_key` | `(value) -> str` | A valid `?range=` name; the default for anything else | `routes/history`, `routes/ports` | v0.1.0 |
| `read_series` | `(conn, switch_id, metric, *, start, end, bucket, item=None, total=False) -> dict` | A switch's rows of a metric averaged (or added up) into buckets, by item | `system_charts`, `port_charts` | v0.1.0 |
| `record` | `(conn, switch_id, moment, rows) -> None` | Stores one sample's rows for a switch | `Sampler.sample_switch` | v0.1.0 |
| `start_sampler` | `(settings, transport, alert_transport=lambda: None) -> Event \| None` | Samples on a thread every `NXRAY_HISTORY_INTERVAL` seconds, checking the alerts against each sample and purging hourly; `None` when history is off | `main.lifespan` | v0.1.0 |
| `system_charts` | `(conn, switch_id, key, now) -> list[ChartView]` | The History page's charts of a switch for a range | `routes/history.history_page` | v0.1.0 |
| `vlan_charts` | `(conn, switch_id, key, now) -> list[ChartView]` | Each VLAN's estimated traffic in and out for a range, the busiest `MAX_VLAN_LINES` VLANs in the same colours on both charts | `routes/history.history_page` | v0.2.0 |

`Sampler` (class) samples every switch in turn: `sample_once(now=None)` reads
each one and returns what failed in words (None when all went well), and
`sample_switch(switch_id, now=None)` reads one. It keeps each switch's error
totals and `alerts.AlertMonitor` apart.

## `app/traffic.py` — traffic per device and per VLAN, estimated

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `busiest_devices` | `(traffic, limit=10) -> list[DeviceTraffic]` | The devices with the most traffic, busiest first; idle ones left out | `routes/neighbors._render` | v0.2.0 |
| `device_traffic` | `(ports, neighbors) -> dict[str, DeviceTraffic]` | By MAC address: every device alone on an access port that is up, with that port's rates as its own | `load_device_traffic`, `routes/ports` | v0.2.0 |
| `load_device_traffic` | `(client, neighbors) -> dict[str, DeviceTraffic]` | `device_traffic` with the ports read fresh (`show interface` only); empty when the switch refuses it | `routes/neighbors._read` | v0.2.0 |
| `port_device` | `(port, devices) -> (MacEntry \| None, str)` | The one device a port's traffic belongs to, or why there is none (trunk, port-channel, several addresses) in words | `device_traffic`, `routes/ports._render_port` | v0.2.0 |
| `vlan_traffic` | `(ports) -> dict[int, VlanTraffic]` | By VLAN: the access ports that are up, added up; trunks and routed ports left out | `history.build_rows` | v0.2.0 |

These are estimates from per-port counters; what each leaves out is in
[Traffic per VLAN and per device](traffic.md). `DeviceTraffic` names the rates
from the device's side (it *sends* what comes in on the port).

## `app/sflow.py` — the sFlow collector: traffic per VLAN and per device, measured

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `agent_addresses` | `(connections) -> dict[str, int]` | Which agent address is which switch, from (id, host, stored agent): the stored agent, else the host when it is an IP address | `load_agents` | v0.2.0 |
| `sender_addresses` | `(connections) -> dict[str, int]` | Every address a switch's sFlow datagrams may be sent from: its stored agent and its NX-API host, when they are IP addresses | `load_agents` | v0.3.0 |
| `decode_datagram` | `(data: bytes) -> Datagram` | One sFlow version 5 datagram's flow samples (formats 1 and 3: raw header, Ethernet frame and extended switch records), bounds-checked; raises `SflowError` | `SflowCollector.receive` | v0.2.0 |
| `device_label` | `(item) -> str` | A device item in words (`Other devices` for the left-over) | the Traffic page | v0.2.0 |
| `item_series` | `(conn, switch_id, kind, items, *, start, end, bucket) -> dict` | Each item's traffic in bits per second per bucket, 0 for quiet buckets between its first and last | `sflow_charts`, `vlan_cards` | v0.2.0 |
| `latest_minute` | `(conn, switch_id) -> float \| None` | When a switch's newest stored minute began | `routes/traffic` | v0.2.0 |
| `load_agents` | `(db_path) -> tuple[dict[str, int], dict[str, int]]` | `agent_addresses` and `sender_addresses` for every stored switch | `run_collector`, `routes/traffic` | v0.2.0 |
| `minute_rows` | `(switch_id, minute, totals) -> list[SflowRow]` | One minute's rows: every VLAN, the busiest `MAX_DEVICES_PER_MINUTE` devices each way, the rest as `other` | `SflowCollector.drain` | v0.2.0 |
| `parse_frame_header` | `(header: bytes) -> dict` | MAC addresses, 802.1Q VLAN and IPv4 or IPv6 addresses from the first bytes of an Ethernet frame | `decode_datagram` | v0.2.0 |
| `purge_sflow` | `(conn, now, keep_days) -> int` | Deletes rows older than `NXRAY_SFLOW_KEEP_DAYS` | `run_collector` | v0.2.0 |
| `run_collector` | `(sock, collector, db_path, keep_days, stop, clock=time.time) -> None` | The listener's loop: receive, write the minutes that are over every 10 s, look the switches up again every 30 s, purge hourly; writes what is left when stopped | `start_collector` | v0.2.0 |
| `sflow_charts` | `(conn, switch_id, key, now, mac="") -> list[ChartView]` | One device's sends and receives over a range when `mac` is given, else none | `routes/traffic` | v0.2.0 |
| `start_collector` | `(port, collector, db_path, keep_days) -> Event \| None` | Listens on UDP `port` on a thread; None when the port is 0 or cannot be opened (logged) | `main.lifespan` | v0.2.0 |
| `store_rows` | `(conn, rows) -> None` | Adds rows to `sflow_traffic`; a minute written twice adds up | `run_collector` | v0.2.0 |
| `top_items` | `(conn, switch_id, kind, *, start, end, limit=20) -> list[TopItem]` | The busiest VLANs or devices over a range, with their average in bits per second | `sflow_charts`, `vlan_cards`, `routes/traffic` | v0.2.0 |
| `vlan_cards` | `(conn, switch_id, key, now) -> list[VlanCard]` | A card per busiest VLAN over a range, busiest first: latest, highest and average figures and a filled-area chart | `routes/traffic` | v0.2.0 |
| `vlan_label` | `(item) -> str` | `VLAN 10`, or `VLAN not given` | the Traffic page, `vlan_cards` | v0.2.0 |

`SflowCollector` (class, `app.state.sflow_collector`) adds samples up in memory
per switch and minute: `receive(data, now=None)` counts a datagram only when its
agent address is one of NXray's switches (`set_agents`), else notes the address
(`unknown_agents()`); `drain(now, everything=False)` hands out the minutes that
are over; `status(switch_id)` is what was heard since NXray started. Kinds are
`VLAN` (`vlan`), `MAC_SENDS` (`mac_out`) and `MAC_RECEIVES` (`mac_in`).

## `app/sflow_ports.py` — which VLAN an untagged frame belongs to

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `parse_port_vlans` | `(switchport, ifindex) -> dict[int, int]` | SNMP ifIndex -> the VLAN of an untagged frame on that port (an access port's VLAN, a trunk's native VLAN) from `show interface switchport` and `show interface snmp-ifindex`; routed ports have none | `load_port_vlans` | v0.2.0 |
| `load_port_vlans` | `(client) -> dict[int, int]` | `parse_port_vlans` over what the switch says now, in one request | `history.Sampler` | v0.2.0 |

## `app/sflow_switch.py` — sFlow on the switch

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `load_sflow_config` | `(client) -> SflowConfig` | `show feature` and `show port-channel summary`, then `show sflow` as text while the feature is on | `routes/traffic._read` | v0.2.0 |
| `parse_sflow_text` | `(text, port_channels=()) -> SflowConfig` | `show sflow`'s sampling rate, collector and VRF, port, agent and sampled ports and port-channels (ranges expanded); 0.0.0.0 reads as not set | `load_sflow_config` | v0.2.0 |
| `plan_sflow` | `(current, ports, form) -> SflowPlan` | Checks the setup form (addresses, VRF, port, rate, which ports) and keeps only what changes, with the confirm page's lines and warnings; a port in a port-channel is sampled through its port-channel | `routes/traffic.traffic_sflow_setup` | v0.2.0 |
| `sflow_form` | `(current, *, collector, agent, port, front=()) -> dict` | The setup form filled with what the switch has, else with NXray's guesses; every front port sampled reads as "every front port" | `routes/traffic._render` | v0.2.0 |

## `app/charts.py` — SVG line charts

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `area_chart` | `(points, *, start, end, bucket, fmt, colour=0, label="") -> Markup` | One series as a short filled-area SVG from zero, the value axis on the right, breaking at gaps | `sflow.vlan_cards` | v0.2.0 |
| `line_chart` | `(lines, *, start, end, bucket, fmt, zero_based=True, y_max=None, label="") -> Markup` | Draws lines over a time range as inline SVG, breaking a line where samples are missing | `history._chart` | v0.1.0 |
| `nice_ticks` | `(low, high, target=5) -> list[float]` | Round axis values covering a range | `line_chart` | v0.1.0 |
| `time_label` | `(moment, step) -> str` | An axis label: the clock time, or the date for a midnight or labels a day apart (UTC) | `line_chart` | v0.1.0 |
| `time_ticks` | `(start, end) -> (list[float], int)` | Round UTC times to label an axis (at most seven) and the step between them | `line_chart` | v0.1.0 |

## `app/face.py` — the front-panel picture

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `channel_colours` | `(neighbors) -> dict[str, int]` | A colour number (0-7, repeating) per port-channel, in name order | `draw_face` | v0.1.0 |
| `color_mode` | `(value) -> str` | A valid `?color=` name; `state` for anything else | `draw_face`, `routes/ports.ports_page` | v0.1.0 |
| `detail_link` | `(name) -> str` | A port's own page, `draw_face`'s default link | `draw_face` | v0.1.0 |
| `device_lines` | `(devices: PortDevices) -> list[str]` | The tooltip lines for what is plugged into a port: neighbors, its port-channel, then up to three learned addresses with their makers | `tooltip` | v0.1.0 |
| `draw_face` | `(ports, mode, labels=None, vlan_names=None, neighbors=None, *, model="", link=detail_link, selected="") -> Face` | The front panel as inline SVG, drawn as the switch's metal front: each port a link (`link(name)`) with a tooltip and a light that is lit while up; with `neighbors` the device's name next to each port; the model at the left; the `selected` port outlined; plus a legend with a count per colour | `routes/ports.render_ports_page` | v0.1.0 |
| `panel_layout` | `(ports, left=12) -> tuple[list[Cage], float, float]` | Where each port sits: pairs with the odd port on top, SFP cages in blocks of eight pairs (1-16, 17-32, 33-48), then QSFP cages (40 Gb/s or more, or broken out); plus width and height | `draw_face` | v0.1.0 |
| `port_colour` | `(port, mode, colours, vlan_names=None, channel="") -> tuple[str, str]` | A port's CSS classes and legend words in one colour mode | `draw_face` | v0.1.0 |
| `short_device_name` | `(name) -> str` | A neighbor's name without its domain or CDP serial | `draw_face`, `routes/ports` (the table) | v0.1.0 |
| `speed_class` | `(port) -> tuple[str, str]` | The CSS class and words (1G ... 100G) for the speed a port runs at; `f-none` without a link | `port_colour`, `routes/ports` (the table) | v0.1.0 |
| `tooltip` | `(port, label="", vlan_names=None, devices=None) -> str` | What hovering over a port shows, one fact per line | `draw_face` | v0.1.0 |
| `vlan_colours` | `(ports) -> dict[str, int]` | A colour number (0-7, repeating) per access VLAN in use, lowest first | `draw_face` | v0.1.0 |

The colours are CSS classes (`f-up`, `f-t2`, `f-vlan s3`, ...) in
`static/style.css`; the SVG carries no inline style, so the strict
Content-Security-Policy holds.

## `app/port_bulk.py` — one shared configuration for several ports

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `bulk_kinds` | `(form) -> set[str]` | Which kinds of change the shared form asks for: `port` (on/off, description), `vlans`, `settings`, `discovery`, `macs`; each needs its own switch on the Switch page | `check_bulk_form`, `plan_port`, `routes/ports.ports_bulk_change` | v0.2.0 |
| `change_summary` | `(port, action, description) -> tuple[str, str \| None]` | A change of one port's on/off or description in words, and a warning when turning off an up port | `plan_port`, `routes/ports.port_change` | v0.1.0 |
| `check_bulk_form` | `(form) -> dict[str, str]` | Checks what does not depend on the port (choices offered, description, VLAN numbers and list, storm levels, no VLANs with routed) and returns the form cleaned up; empty means leave as it is | `routes/ports.ports_bulk_change` | v0.2.0 |
| `empty_bulk_form` | `() -> dict[str, str]` | The shared form with every setting at "leave as it is" | `routes/ports.render_ports_page`, `form_from_port` | v0.2.0 |
| `form_from_port` | `(port, settings, vlans, discovery) -> dict[str, str]` | The shared form filled with one port's VLANs, settings and CDP/LLDP ("Start from port"); never on/off, description, address, or the speed of an up port | `routes/ports.ports_bulk_change` | v0.2.0 |
| `group_warnings` | `(plans) -> list[str]` | Each confirm-page warning once, naming the ports it is about | `routes/ports.ports_bulk_change` | v0.2.0 |
| `plan_bulk` | `(ports, names, form, *, view, settings, discovery, neighbors) -> tuple[list[PortPlan], list[str]]` | Plans the shared form for every ticked port, in front-panel order, and the ports already as asked; raises naming every port that cannot take it, so nothing is sent | `routes/ports.ports_bulk_change` | v0.2.0 |
| `plan_port` | `(port, form, *, view, settings, discovery, neighbors, port_names) -> PortPlan` | Plans the shared form for one port with the single-port planners (`plan_port_settings`, `plan_port_vlans`, `plan_port_discovery`, `plan_clear`): its steps (one request each, settings first so a layer change sets what the VLANs start from), lines, warnings and notes | `plan_bulk` | v0.2.0 |

Each `PortPlan.steps` entry is a `BulkStep` that calls one of the existing
`NxapiClient` methods (`configure_port_settings`, `configure_port_vlans`,
`set_port_discovery`, `configure_port`, `clear_learned_macs`), so the bulk
form sends nothing a port's own page could not, and the role NXray's
account is given already allows all of it. Not offered for several ports:
an IPv4 address (two ports cannot share one), the label and breakout.

## `app/port_labels.py` — port labels

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `get_labels` | `(conn, switch_id) -> dict[str, str]` | Every port's label on a switch, by port name | `routes/ports`, `history.Sampler` | v0.1.0 |
| `set_label` | `(conn, switch_id, port, label, username) -> str` | Checks and stores a label (empty removes it); returns what was stored | `routes/ports.port_label` | v0.1.0 |
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

## `app/port_reset.py` — resetting a port or a port-channel to its defaults

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `port_reset_summary` | `(port, settings, vlans) -> tuple[str, list[str]]` | The confirm line for resetting one port: everything it removes (description, VLANs, speed, MTU, FEC, flow control, storm control, layer, IP address), or that it is already a plain access port; a warning when it is up | `routes/ports.port_reset`, `plan_bulk_reset` | v0.2.0 |
| `plan_bulk_reset` | `(ports, names, view, settings) -> tuple[list[Port], list[str], list[str]]` | Every ticked port, in front-panel order, with one confirm line each and every warning once; `ValueError` naming any ticked port the switch does not have | `routes/ports.ports_reset_bulk` | v0.2.0 |
| `channel_reset_summary` | `(channel) -> tuple[str, list[str]]` | The confirm line for resetting a port-channel's own settings (its description); warns which member ports it affects and that they keep their channel-group membership | `routes/port_channels.channel_reset` | v0.2.0 |

`NxapiClient.reset_ports` and `reset_port_channel` (app/nxapi.py) send
`default interface <name>`; the role rule for it is `RESET_RULES`
(app/port_changes.py, `ROLE_VERSION` 16).

## `app/protocols.py` — routing protocols as data: fields, settings, scopes

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `check_value` | `(spec: Field, raw: str) -> str` | One field's value as the switch should get it (address, network, area, AS number, name, secret, interface, VRF, server name or address, domain, VRF to reach a server in, time of day, ...), "" for an empty optional field; ValueError naming the field otherwise | `build_change` | v0.1.0 |
| `render` | `(template: str, values: dict[str, str]) -> str` | Fills a setting's line: `{name}` blanks, `[...]` parts dropped when a value inside is empty | `build_change` | v0.1.0 |
| `blanks` | `(template: str) -> set[str]` | The field names a template uses | `Setting`, `Scope` checks | v0.1.0 |
| `build_change` | `(protocol, scope_key, setting_key, action, ident, values) -> ProtocolChange` | The checked lines for one change (set, remove, create, delete), secrets masked in the labels, with a plain-words description | `routing_protocols.build_protocol_change` | v0.1.0 |
| `route_age` | `(value: str) -> str` | An age as the switch writes it (`P1DT13H30M23S`) in short words (`1d 13h 30m`) | `routing_protocols.parse_routes`, `protocols_bgp` | v0.1.0 |
| `table_rows` | `(body, table: str, row: str) -> list[dict]` | The rows of an NX-OS table, one row or many, also when the table is a list; deliberately not a change to `switch.rows` | `protocols_*` parsers, `routing_protocols.parse_routes` | v0.1.0 |
| `vrf_field` | `(optional=True) -> Field` | The VRF identity field protocol scopes share | `protocols_*` | v0.1.0 |
| `interface_field` | `() -> Field` | The interface identity field of interface scopes | `protocols_*` | v0.1.0 |
| `port_field` | `() -> Field` | The port identity field of spanning-tree port scopes: a switched front port or port-channel (field kind `port`) | `spanning_tree` | v0.1.0 |
| `source_field` | `(name="source", label="Source interface") -> Field` | A field for an interface whose address a protocol uses, loopbacks included (BGP update source, PIM register source, MSDP connect source) | `protocols_bgp`, `protocols_multicast` | v0.1.0 |

## `app/routing_protocols.py` — the Routing protocols pages and the route table

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `protocol` | `(key: str) -> Protocol \| None` | The protocol a page key names | `routes/protocols`, `switch_save` | v0.1.0 |
| `build_protocol_change` | `(key, scope, setting, action, ident, values) -> ProtocolChange` | `build_change` for a protocol named by its key | `NxapiClient.configure_protocol`, `routes/protocols.protocol_change` | v0.1.0 |
| `feature_command` | `(name: str) -> str` | The word typed after `feature` for a `show feature` name (`hsrp_engine` -> `hsrp`) | protocol pages | v0.1.0 |
| `parse_routes` | `(body) -> list[Route]` | Every route of `show ip route vrf all` or `show ipv6 route vrf all`, with its source, next hops, distance, metric and age | `load_overview` | v0.1.0 |
| `load_overview` | `(client) -> ProtocolsOverview` | Which protocols' features are on, and the route table; one request | `routes/protocols` | v0.1.0 |
| `load_protocol_page` | `(client, proto) -> ProtocolPage` | The features, layer 3 interfaces and VRFs in one request, then the protocol's own show commands when it is on | `routes/protocols` | v0.1.0 |

## `app/protocols_ospf.py` — OSPF and OSPFv3 pages

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `parse_ospf` | `(bodies: list[dict]) -> ProtocolView` | The OSPF page from show ip ospf / interface / neighbors / summary-address vrf all: processes, VRF parts, interfaces with prefilled values; neighbor, interface, area and summary tables | `OSPF.parse` (`routing_protocols.load_protocol_page`) | v0.1.0 |
| `parse_ospfv3` | `(bodies: list[dict]) -> ProtocolView` | The OSPFv3 page from show ospfv3 / interface / neighbors vrf all: processes, VRF parts, IPv6 address families, interfaces; neighbor, interface and area tables | `OSPFV3.parse` (`routing_protocols.load_protocol_page`) | v0.1.0 |

## `app/protocols_bgp.py` — BGP: the process, VRF parts, address families and neighbors

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `parse_bgp` | `(bodies: list[dict]) -> ProtocolView` | The BGP page from `show bgp process`, `show bgp all summary vrf all`, `show bgp vrf all all neighbors`, `show bgp sessions vrf all` and `show bgp ipv6 unicast vrf all`: process, VRF parts, address families, neighbors and their address families with the settings the output tells; neighbor, session and IPv6 BGP tables | `BGP.parse` | v0.1.0 |

## `app/protocols_igp.py` — EIGRP, RIP and IS-IS pages

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `parse_eigrp` | `(bodies: list[dict]) -> ProtocolView` | EIGRP processes, interfaces and neighbors from the five EIGRP reads | `EIGRP.parse` | v0.1.0 |
| `parse_rip` | `(bodies: list[dict]) -> ProtocolView` | RIP processes, families, interfaces and neighbors from the five RIP reads | `RIP.parse` | v0.1.0 |
| `parse_isis` | `(bodies: list[dict]) -> ProtocolView` | IS-IS processes, families, interfaces and adjacencies from the three IS-IS reads | `ISIS.parse` | v0.1.0 |

## `app/protocols_fhrp.py` — gateway backup: HSRP, VRRP and VRRPv3 groups

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `parse_hsrp` | `(bodies: list[dict]) -> ProtocolView` | HSRP interfaces and groups, with a groups table, from `show hsrp` | `HSRP.parse` | v0.1.0 |
| `parse_vrrp` | `(bodies: list[dict]) -> ProtocolView` | VRRP groups and a groups table from `show vrrp detail` (falls back to `show vrrp`) | `VRRP.parse` | v0.1.0 |
| `parse_vrrpv3` | `(bodies: list[dict]) -> ProtocolView` | VRRPv3 groups per address family and a groups table from `show vrrpv3 detail` (falls back to `show vrrpv3`) | `VRRPV3.parse` | v0.1.0 |

## `app/protocols_multicast.py` — PIM, PIM6, IGMP, MSDP and BFD pages

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `parse_pim` | `(bodies: list[dict]) -> ProtocolView` | PIM's VRFs (RPs, SSM range, policies) and interfaces, plus tables of interfaces, neighbors, RPs, group ranges, multicast routes | `PIM.parse` | v0.1.0 |
| `parse_pim6` | `(bodies: list[dict]) -> ProtocolView` | PIM6's VRFs (RPs) and interfaces, plus tables of interfaces and RPs | `PIM6.parse` | v0.1.0 |
| `parse_igmp` | `(bodies: list[dict]) -> ProtocolView` | IGMP interfaces with their version and timers, plus a table | `IGMP.parse` | v0.1.0 |
| `parse_msdp` | `(bodies: list[dict]) -> ProtocolView` | MSDP's VRFs and peers with their settings, plus a peer table | `MSDP.parse` | v0.1.0 |
| `parse_bfd` | `(bodies: list[dict]) -> ProtocolView` | The switch-wide BFD place, interfaces with sessions, and a session table (the two-row form is merged) | `BFD.parse` | v0.1.0 |

## `app/protocols_policy.py` — Routing policy: route-maps, prefix-lists, key chains

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `parse_policy` | `(bodies: list[dict]) -> ProtocolView` | Routing policy page from show route-map / ip / ipv6 prefix-list / key chain | `POLICY.parse` | v0.1.0 |
| `check_prefix_entry` | `(prefix: str, ge: str = "", le: str = "") -> tuple[str, str, str]` | Checks a prefix-list entry's length < ge <= le <= 32/128 | the prefix-list entry setting's `check` | v0.1.0 |

## `app/spanning_tree.py` — Spanning tree: the trees, the ports, and every setting

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `expand_vlans` | `(spec: str) -> list[int]` | A VLAN list as the switch writes it (`1-2,10`) as numbers; `[]` for anything else. Deliberately not `nxapi.parse_vlan_list`, which raises on bad input and takes `all`/`none`: here the text is the switch's own and a line it does not match is skipped | `parse_stp_config` | v0.1.0 |
| `parse_stp_config` | `(config: str) -> StpConfig` | `show running-config spanning-tree` text sorted by where each line applies: switch-wide lines, per-VLAN values, VLANs with spanning tree off, the MST region, MST instance priorities, each port's lines | `parse_spanning_tree` | v0.1.0 |
| `parse_spanning_tree` | `(bodies, config_text=None) -> ProtocolView` | The page from the five reads and the configuration text (None when the role may not read it): the switch, each VLAN, the MST region and instances, each port in a tree or with settings, with values prefilled; trees, ports and problem ports tables | `SPANNING_TREE.parse`, `load_spanning_tree_page` | v0.1.0 |
| `switch_port_names` | `(brief) -> list[str]` | The front ports and port-channels in `show interface brief` that are not routed | `parse_spanning_tree`, `load_spanning_tree_page` | v0.1.0 |
| `stp_vlan_numbers` | `(vlan_brief) -> list[int]` | The VLAN numbers in `show vlan brief` up to 3967, lowest first | `parse_spanning_tree`, `load_spanning_tree_page`, `port_security.load_port_security_page` | v0.1.0 |
| `load_spanning_tree_page` | `(client) -> SpanningTreePage` | One request for the reads, then the configuration text (`show_text`); a role that may not read it gives the page without it | `routes/spanning_tree` | v0.1.0 |
| `build_stp_change` | `(scope, setting, action, ident, values) -> ProtocolChange` | `build_change` for the Spanning tree page | `NxapiClient.configure_spanning_tree`, `routes/spanning_tree` | v0.1.0 |

## `app/switch_admin.py` — Switch admin: name, clock and NTP, DNS, logging, SNMP, banner, and the log

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `parse_admin_config` | `(config: str) -> AdminConfig` | `show running-config` text: the hostname, banner (one line or several), time zone, summer time, domain name and lookups, name servers (also those inside a `vrf context`), NTP servers, logging settings and servers, SNMP contact, location, communities and trap receivers | `parse_switch_admin` | v0.1.0 |
| `parse_ntp_status` | `(body) -> list[NtpPeer]` | `show ntp peer-status`: each server with its VRF, stratum, reach, delay and whether the clock follows it | `parse_switch_admin` | v0.1.0 |
| `clock_text` | `(body) -> tuple[str, str]` | `show clock`: the time as the switch writes it and its source | `parse_switch_admin` | v0.1.0 |
| `parse_switch_admin` | `(bodies, ntp_body=None, config_text=None) -> ProtocolView` | The page from the reads, NTP status (None when refused) and the configuration text (None when the role may not read it): the switch's facts and current values, each NTP, DNS and logging server and SNMP trap receiver; SNMP communities masked | `SWITCH_ADMIN.parse`, `load_switch_admin_page` | v0.1.0 |
| `load_switch_admin_page` | `(client) -> SwitchAdminPage` | One request for the reads, one for NTP, one for the configuration text (`show_text`); a role that may not read it gives the page without it | `routes/switch_admin` | v0.1.0 |
| `build_admin_change` | `(scope, setting, action, ident, values) -> ProtocolChange` | `build_change` for the Switch admin page | `NxapiClient.configure_switch_admin`, `routes/switch_admin` | v0.1.0 |
| `vrf_choices` | `(vrf_body) -> tuple[str, ...]` | The VRFs in `show vrf` for a VRF field's list: default, management, then the others | `load_switch_admin_page`, `dhcp_security.load_dhcp_page` | v0.1.0 |
| `log_command` | `(lines: int) -> str` | `show logging last <n>` for 50, 200 or 1000; ValueError otherwise | `load_switch_log` | v0.1.0 |
| `parse_log` | `(output, search="", worst=None) -> list[LogLine]` | The log's lines newest first, each with its severity from `%FACILITY-5-NAME:`, kept to those containing `search` and of `worst` or more urgent | `routes/switch_admin.switch_log_page` | v0.1.0 |
| `load_switch_log` | `(client, lines) -> str` | The last lines of the switch's log as it prints them (`show_text`) | `routes/switch_admin.switch_log_page` | v0.1.0 |

## `app/acls.py` — ACLs: IPv4, IPv6 and MAC access lists, object groups, VLAN access maps, TCAM

Described with the parts of `app/protocols.py`: scopes for each kind of ACL (made
and deleted from the page, entries as settings) and for applying one to a layer
3 interface or a switched port; from role version 14 also MAC ACLs, object
groups, VLAN access maps and filters, and the TCAM regions. New field kinds in
`app/protocols.py`: `aclnet4` and `aclnet6` (any, a network, one address as /32
or /128, or `addrgroup <name>`), `l4port` (22, 1024-65535, >1023, <1024, !=23
as `eq`, `range`, `gt`, `lt`, `neq`, or `portgroup <name>`), `aclmac` (any, an
address, or an address and mask), `ethertype` (0x0600-0xffff), and `arpip` and
`arpmac` (any or `host <address>`, for ARP ACLs).

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `parse_acl_config` | `(config) -> AclConfig` | The IPv4, IPv6 and MAC ACLs, their entry lines and statistics, the object groups, VLAN access maps and filters, the TCAM sizes set, and the interfaces and ports the ACLs apply on, from `show running-config` | `parse_acls` | v0.1.0 |
| `parse_tcam_regions` | `(text) -> list[tuple[str, str, str]]` | `show hardware access-list tcam region` as text: each region's name, what it is for and its size in entries | `parse_acls` | v0.1.0 |
| `parse_acls` | `(bodies, config_text=None, tcam_text=None) -> ProtocolView` | The ACLs page: each IPv4, IPv6 and MAC ACL with its entries and where it applies, each object group, VLAN access map entry and VLAN filter, each interface with its ACLs, a table of every ACL, one of the groups and maps, and one of the TCAM regions; a note when the configuration cannot be read | `ACLS.parse`, `load_acls_page` | v0.1.0 |
| `needs_v14` | `(scope, setting) -> bool` | Whether an ACLs page change needs role version 14 (MAC ACLs, object groups, VLAN access maps and filters, TCAM, MAC port ACLs) | `routes/security.acl_needs` | v0.1.0 |
| `layer3_names` | `(brief) -> tuple[str, ...]` | VLAN interfaces up to Vlan254 and routed ports and port-channels in `show interface brief` | `load_acls_page` | v0.1.0 |
| `load_acls_page` | `(client) -> AclPage` | One request for the interfaces and VLANs, one for the configuration text, one for the TCAM regions (`show_text`; None when refused) | `routes/security` | v0.1.0 |
| `build_acl_change` | `(scope, setting, action, ident, values) -> ProtocolChange` | `build_change` for the ACLs page | `NxapiClient.configure_acl`, `routes/security` | v0.1.0 |

## `app/dhcp_security.py` — DHCP and ARP: DHCP snooping and relay, ARP inspection, IP Source Guard

Described with the parts of `app/protocols.py`: a switch-wide scope, a switched
port scope, a layer 3 interface scope for the DHCP servers, and ARP ACLs (made
and deleted from the page).

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `parse_dhcp_config` | `(config) -> DhcpConfig` | The DHCP snooping, relay, ARP inspection and IP Source Guard lines of `show running-config`, switch-wide and per interface, with NX-OS's defaults for missing lines, and the ARP ACLs | `parse_dhcp` | v0.1.0 |
| `parse_bindings` | `(text) -> list[tuple[str, ...]]` | `show ip dhcp snooping binding` as text: MAC, IP address, lease, type, VLAN and interface per binding | `parse_dhcp` | v0.1.0 |
| `parse_dhcp` | `(bodies, config_text=None, binding_text=None) -> ProtocolView` | The DHCP and ARP page: the switch-wide settings, each port, each relaying interface and ARP ACL, and tables of the ports, the relays and the bindings (learned and fixed); a note when the configuration cannot be read | `DHCP.parse`, `load_dhcp_page` | v0.1.0 |
| `load_dhcp_page` | `(client) -> DhcpPage` | One request for the feature, ports, VLANs and VRFs, one for the configuration text, one for the bindings (while the dhcp feature is on) | `routes/security` | v0.1.0 |
| `build_dhcp_change` | `(scope, setting, action, ident, values) -> ProtocolChange` | `build_change` for the DHCP and ARP page | `NxapiClient.configure_dhcp`, `routes/security` | v0.1.0 |

## `app/port_security.py` — Port security on the switched front ports

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `parse_port_security_config` | `(config) -> dict[str, PortSecurity]` | Every port with a `switchport port-security` line, and its settings and known addresses | `parse_port_security` | v0.1.0 |
| `parse_port_security` | `(bodies, config_text=None) -> ProtocolView` | The Port security page: each port's settings with NX-OS's defaults filled in, and a table | `PORT_SECURITY.parse`, `load_port_security_page` | v0.1.0 |
| `load_port_security_page` | `(client) -> PortSecurityPage` | One request for the feature, ports and VLANs, one for the configuration text; the page names the port-security feature when it is off | `routes/security` | v0.1.0 |
| `build_port_security_change` | `(scope, setting, action, ident, values) -> ProtocolChange` | `build_change` for the Port security page | `NxapiClient.configure_port_security`, `routes/security` | v0.1.0 |

## `app/config_tools.py` — backups, checkpoints, comparing and rolling back

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `clean_config` | `(config) -> list[str]` | A configuration's lines without the `!Time:` and similar lines about when it was printed | `config_diff` | v0.1.0 |
| `config_sections` | `(config) -> list[tuple[str, list[str]]]` | Each top-level line with the indented lines under it, stripped | `acls.parse_acl_config`, `port_security.parse_port_security_config`, `dhcp_security.parse_dhcp_config` | v0.1.0 |
| `config_diff` | `(first, second, context=3) -> list[DiffLine]` | What changes from one configuration to another, with unchanged lines around each change and gaps between | `routes/config_page` | v0.1.0 |
| `diff_counts` | `(diff) -> tuple[int, int]` | Lines removed and added in a comparison | `routes/config_page` | v0.1.0 |
| `parse_checkpoints` | `(output) -> list[str]` | The checkpoint names in `show checkpoint summary` | `load_configs` | v0.1.0 |
| `checkpoint_name` | `(backup_id) -> str` | `nxray-<id>`, the switch checkpoint of a backup | `routes/config_page` | v0.1.0 |
| `validate_note` | `(note) -> str` | A backup's note: one printable line of at most 200 characters | `store_backup`, `routes/config_page` | v0.1.0 |
| `store_backup` | `(conn, switch_id, *, config, created_by, switch, note="", now=None) -> int` | Stores a configuration of a switch; its backup number | `routes/config_page` | v0.1.0 |
| `set_backup_checkpoint` | `(conn, switch_id, backup_id, checkpoint) -> None` | Notes the switch checkpoint made with a backup | `routes/config_page` | v0.1.0 |
| `list_backups` | `(conn, switch_id, limit=200) -> list[Backup]` | A switch's backups, newest first, without their text | `routes/config_page` | v0.1.0 |
| `get_backup` | `(conn, switch_id, backup_id) -> tuple[Backup, str] \| None` | One backup of that switch and its text; None for another switch's, so it is never compared with or rolled back onto the wrong one | `routes/config_page` | v0.1.0 |
| `delete_backup` | `(conn, switch_id, backup_id) -> bool` | Deletes a backup of that switch from NXray | `routes/config_page` | v0.1.0 |
| `load_configs` | `(client) -> SwitchConfigs` | The running and saved configurations and the checkpoints, as text; None for what the role may not read | `routes/config_page` | v0.1.0 |
| `load_running` | `(client) -> str` | `show running-config` as text | `routes/config_page` | v0.1.0 |

## `app/activity.py` — the activity log

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `record_activity` | `(conn, username, area, what, switch="", now=None) -> None` | Records one change and deletes lines older than `KEEP_DAYS` | `dependencies.note_activity` | v0.1.0 |
| `list_activity` | `(conn, *, username="", area="", search="", limit=500) -> list[Activity]` | The changes newest first, filtered by account, area and text (taken literally) | `routes/activity` | v0.1.0 |
| `activity_choices` | `(conn) -> tuple[list[str], list[str]]` | The accounts and areas in the log, for the filters | `routes/activity` | v0.1.0 |
| `utc_time` | `(at) -> str` | A stored time as `2026-11-01 14:30:05 UTC`; the `utc` template filter | `dependencies` (the filter) | v0.1.0 |
| `activity_csv` | `(entries) -> str` | The entries as CSV, with cells that start like a formula made inert | `routes/activity` | v0.1.0 |

## `app/alerts.py` — alerts by e-mail and webhook

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `load_rules` | `(conn) -> AlertRules` | What NXray alerts on; the defaults (unreachable, temperatures, fans, power) until changed | `AlertMonitor`, `notify_change`, `routes/alerts` | v0.1.0 |
| `save_rules` | `(conn, rules) -> None` | Stores the rules, dropping without a "resolved" alert the open problems of a check turned off | `routes/alerts.alerts_rules` | v0.1.0 |
| `parse_rules` | `(form) -> AlertRules` | The rules from the form: ticked boxes, numbers where blank is off; raises `AlertSettingsError` | `routes/alerts.alerts_rules` | v0.1.0 |
| `load_email` | `(conn) -> EmailSettings` | The e-mail settings, with only whether a password is stored | `deliver`, `routes/alerts` | v0.1.0 |
| `split_addresses` | `(text) -> list[str]` | Addresses typed with commas, semicolons, spaces or new lines between them | `load_email`, `validate_email` | v0.1.0 |
| `validate_email` | `(*, host, port, security, username, password, keep_password, sender, recipients) -> EmailSettings` | Checks the e-mail form; refuses a password over an unencrypted connection and CR/LF anywhere | `routes/alerts.alerts_email` | v0.1.0 |
| `save_email` | `(conn, email, password, secret_key) -> None` | Stores checked e-mail settings, the password encrypted; empty keeps or removes the stored one | `routes/alerts.alerts_email` | v0.1.0 |
| `delete_email` | `(conn) -> None` | Forgets the e-mail settings and password | `routes/alerts.alerts_email_delete` | v0.1.0 |
| `shown_url` | `(url) -> str` | A webhook URL cut to scheme and host (`https://hooks.slack.com/…`), never its path or query | `add_webhook`, `post_webhook` | v0.1.0 |
| `validate_webhook` | `(name, url, fmt, secret) -> tuple` | Checks a webhook's name, http(s) URL, format and signing secret (JSON only) | `routes/alerts.alerts_webhook_add` | v0.1.0 |
| `add_webhook` | `(conn, name, url, fmt, secret, secret_key) -> int` | Stores a webhook with its URL and secret encrypted, at most `MAX_WEBHOOKS` | `routes/alerts.alerts_webhook_add` | v0.1.0 |
| `list_webhooks` | `(conn) -> list[Webhook]` | The webhooks without their URLs and secrets | `routes/alerts` | v0.1.0 |
| `delete_webhook` | `(conn, webhook_id) -> Webhook \| None` | Deletes one webhook | `routes/alerts.alerts_webhook_delete` | v0.1.0 |
| `list_open` | `(conn, switch_id=None) -> list[OpenProblem]` | The problems open now on one switch or (None) every switch, oldest first; each names its switch when there are several | `AlertMonitor`, `save_rules`, `routes/alerts` | v0.1.0 |
| `update_open` | `(conn, switch_id, now, found) -> list[AlertEvent]` | Stores the problems found now on a switch: new ones are alerts, open ones not found are resolved | `AlertMonitor` | v0.1.0 |
| `log_alerts` | `(conn, now, events, delivery, switch="") -> list[int]` | Keeps events in the alert log with the switch they name, and deletes lines older than `KEEP_DAYS` | `dispatch`, `send_test` | v0.1.0 |
| `set_delivery` | `(conn, ids, delivery) -> None` | Notes how logged alerts were delivered | `dispatch` | v0.1.0 |
| `list_sent` | `(conn, limit=100) -> list[SentAlert]` | The newest alerts with their delivery | `routes/alerts` | v0.1.0 |
| `find_problems` | `(rules, environment, resources, ports, *, labels, new_errors, was_up, open_keys) -> dict[str, str]` | Every problem the rules ask about in one reading, by key; a watched port only once it went down from up | `AlertMonitor.checked` | v0.1.0 |
| `duration_words` | `(seconds) -> str` | `3 minutes`, `2 hours 5 minutes`, `1 day 3 hours` | `event_line` | v0.1.0 |
| `event_line` | `(event, now) -> str` | One event in words (`Problem: ...`, `Resolved after 5 minutes: ...`) | `compose` | v0.1.0 |
| `compose` | `(events, switch, now) -> tuple[str, str]` | The subject and text of one alert | `deliver`, `webhook_payload` | v0.1.0 |
| `webhook_payload` | `(fmt, events, switch, now) -> dict` | The JSON body: NXray's own (text and events), Slack's `text` or Discord's `content` | `post_webhook` | v0.1.0 |
| `signature` | `(secret, body) -> str` | `sha256=<HMAC-SHA256 of the body>`, the `X-NXray-Signature` header | `post_webhook` | v0.1.0 |
| `send_email` | `(email, password, subject, text, now=None) -> None` | Sends one e-mail over STARTTLS, SSL/TLS or plain, checking the certificate; raises on failure | `deliver` | v0.1.0 |
| `post_webhook` | `(url, fmt, secret, events, switch, now, transport=None) -> None` | POSTs one alert, signed when there is a secret; raises without the URL in the message | `deliver` | v0.1.0 |
| `deliver` | `(conn, secret_key, events, switch, now, transport=None, *, webhook_id=None, email_only=False) -> str` | Sends by e-mail and to every webhook (or one, for a test); how it went, in words | `dispatch`, `send_test` | v0.1.0 |
| `switch_label` | `(connection: SwitchConnection \| None) -> str` | A switch as alerts name it, `leaf1 (192.0.2.10)`; empty for none | `history.Sampler`, `dependencies.note_activity`, `routes/alerts` | v0.1.0 |
| `dispatch` | `(settings, events, switch, transport=None, *, background=True, now=None) -> None` | Logs events about the switch named `switch` and sends them on a thread of their own; never raises | `history.Sampler`, `notify_change` | v0.1.0 |
| `notify_change` | `(settings, username, area, what, switch="", transport=None, *, background=True) -> None` | Sends a change made through NXray to that switch (empty: to NXray itself) when the rules ask for it; never raises | `dependencies.note_activity` | v0.1.0 |
| `send_test` | `(settings, transport=None, *, switch="", webhook_id=None, email_only=False) -> str` | Sends a test alert naming that switch now and waits for it | `routes/alerts` | v0.1.0 |

`AlertMonitor(switch_id)` (class) remembers, for one switch, between samples which ports were up, how long
CPU or memory has been over its limit and how many reads failed in a row:
`checked(conn, now, reading, new_errors, labels)` and `failed(conn, now,
reason)` return the alerts a sample starts or resolves.

## `app/routing.py` — VLAN interfaces, routed ports, their addresses, VRFs and static routes

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `load_routing` | `(client) -> RoutingView` | Whether interface-vlan is on, the VLANs, the VRFs, the static routes, every VLAN interface and routed port with its VRF and addresses; one request, plus one for the VLAN interfaces | `routes/routing` | v0.1.0 |
| `long_name` | `(name: str) -> str` | `Eth1/3` (as `show ip interface` writes it) -> `Ethernet1/3` | `parse_ipv4`, `parse_ipv6` | v0.1.0 |
| `parse_brief` | `(brief_body) -> tuple[list[str], list[dict]]` | VLAN interface names, and the rows of routed front ports and port-channels, from `show interface brief` | `load_routing` | v0.1.0 |
| `parse_ipv4` | `(body) -> dict[str, tuple[str, list[Address], dict]]` | Interface -> (VRF, IPv4 addresses with the main one first, row) from `show ip interface vrf all` | `load_routing`, `port_settings.parse_port_settings` | v0.1.0 |
| `parse_ipv6` | `(body) -> dict[str, tuple[str, list[Address], str]]` | Interface -> (VRF, IPv6 addresses, link-local address) from `show ipv6 interface vrf all` | `load_routing`, `port_settings.parse_port_settings` | v0.1.0 |
| `parse_routed_port` | `(row, ipv4, ipv6, descriptions) -> L3Interface` | One routed front port or port-channel from its `show interface brief` row and the address tables | `load_routing` | v0.1.0 |
| `parse_vlan_interface` | `(name, svi_body, ipv4, ipv6, descriptions) -> L3Interface` | One VLAN interface: on/off, up/down, MTU, description and addresses, from `show interface vlan<n>` and the address tables | `load_routing` | v0.1.0 |
| `parse_ipv4_static` | `(body) -> list[StaticRoute]` | IPv4 static routes per VRF from `show ip static-route vrf all`, with whether the switch uses each | `load_routing` | v0.1.0 |
| `parse_ipv6_static` | `(body) -> list[StaticRoute]` | IPv6 static routes from `show ipv6 static-route vrf all` (a list of tables; the VRF is the next hop's) | `load_routing` | v0.1.0 |
| `parse_vrf_members` | `(body) -> dict[str, str]` | Interface -> its VRF from `show vrf interface`, interfaces without an address too | `load_routing` | v0.1.0 |
| `parse_vrfs` | `(vrf_body, members) -> list[Vrf]` | The VRFs from `show vrf`, up or down, each with its interfaces; default, management, then the others | `load_routing` | v0.1.0 |
| `plan_add_static_route` | `(view, *, vrf, prefix, next_hop) -> tuple[RouteChange, list[str], list[str]]` | A new static route in default or a VRF made on the switch; refuses a duplicate and management; warns for a default route and a next hop no interface in the VRF reaches | `routes/routing.route_add` | v0.1.0 |
| `plan_remove_static_route` | `(view, *, vrf, prefix, next_hop) -> tuple[RouteChange, list[str], list[str]]` | Removing a static route that exists; never one in management | `routes/routing.route_remove` | v0.1.0 |
| `plan_create_vrf` | `(view, *, name) -> tuple[str, list[str], list[str]]` | A new, empty VRF; refuses a name the switch has (any case) or keeps | `routes/routing.vrf_create` | v0.1.0 |
| `plan_delete_vrf` | `(view, *, name) -> tuple[str, list[str], list[str]]` | Deleting a VRF; refuses one interfaces are in or that has static routes, naming them | `routes/routing.vrf_delete` | v0.1.0 |
| `plan_interface_vrf` | `(view, *, name, vrf) -> tuple[VrfMove, list[str], list[str]]` | Moving a VLAN interface or routed port into another VRF, naming the addresses the switch deletes; never into or out of management | `routes/routing.vrf_move` | v0.1.0 |
| `plan_add_address` | `(view, *, name, address) -> tuple[AddressChange, list[str], list[str]]` | One more address on a VLAN interface or routed port: IPv6, or IPv4 (the main one when it has none, else extra); refuses a network another interface in the VRF has | `routes/routing.address_add` | v0.1.0 |
| `plan_create_vlan_interface` | `(view, *, vlan, ipv4, ipv6, description, mtu, enabled, vrf="default") -> tuple[VlanInterfaceChange, list[str], list[str]]` | A new VLAN interface: interface-vlan on, the VLAN exists and has none, the VRF exists, addresses checked against that VRF | `routes/routing.vlan_interface_create` | v0.1.0 |
| `plan_delete_vlan_interface` | `(view, *, vlan) -> tuple[int, list[str], list[str]]` | Deleting a VLAN interface, naming the addresses that go with it; never Vlan1 | `routes/routing.vlan_interface_delete` | v0.1.0 |
| `plan_remove_address` | `(view, *, name, address) -> tuple[AddressChange, list[str], list[str]]` | Taking one address off; the main IPv4 address only once the extra ones are gone | `routes/routing.address_remove` | v0.1.0 |
| `plan_vlan_interface_settings` | `(view, *, vlan, ipv4, description, mtu, enabled) -> tuple[VlanInterfaceChange, list[str], list[str]]` | A VLAN interface's main IPv4 address, description, MTU and on/off; only what differs | `routes/routing.vlan_interface_settings` | v0.1.0 |

VLAN interfaces exist only while the interface-vlan feature is on; turning it
on makes Vlan1 by itself, turned off. NXray changes VLAN interfaces of VLANs 1
to `nxapi.VLAN_INTERFACE_MAX` (254) only, the range its role names. A port becomes routed on its own page;
the Routing page puts extra IPv4 and IPv6 addresses on it. An extra address
may share its main address's network, but not another interface's in the same
VRF. Link-local IPv6 addresses are never typed: the switch makes one on every
IPv6 interface. The switch's own VRFs, default and management (mgmt0), are
never created, deleted or moved into; moving an interface between VRFs makes
the switch delete its addresses, which the confirm page says.

## `app/oui.py` — MAC addresses and their makers

| Function | Signature | Does | Used by | Since |
| --- | --- | --- | --- | --- |
| `format_mac` | `(text: str) -> str` | `0cea.1439.bb3a` -> `0c:ea:14:39:bb:3a`; other text as is | `neighbors.parse_mac_table`, `parse_arp` | v0.1.0 |
| `is_group_mac` | `(text: str) -> bool` | A group (multicast or broadcast) address, which no one device owns or receives | `validate_device_mac`, `protocols._mac`, `sflow` | v0.1.0 |
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
