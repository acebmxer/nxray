# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

NXray is a web interface for Cisco Nexus switches, built on NX-API.

## [Unreleased]

### Added

- **Published image on GitHub Container Registry.** A new workflow,
  `.github/workflows/release.yml`, builds the image and pushes it to
  `ghcr.io/acebmxer/nxray` whenever a version tag is pushed (as `:X.Y.Z`,
  `:X.Y` and `:latest`), and can be run by hand against a branch to publish
  a branch-named tag. `docker-compose.yml.example` now pulls
  `ghcr.io/acebmxer/nxray:latest`, so the compose file and `nxray.env` are a
  whole install with no clone and no build; updating is `docker compose pull`
  then `docker compose up -d`, and a version can be pinned in the `image:`
  line. To build from a clone, the new `docker-compose.dev.yml` is added to
  every command (`docker compose -f docker-compose.yml -f
  docker-compose.dev.yml up -d --build`). A `docker-compose.yml` copied from
  the older sample keeps building from its folder until it is replaced. No
  image exists on GHCR until the first version tag is pushed.
- **Built-in HTTPS, off by default.** Set `NXRAY_ENABLE_HTTPS=true` in
  `nxray.env` (and keep the new `8443:8443` line in `docker-compose.yml`)
  and NXray serves its pages over HTTPS on port 8443 with an nginx inside
  the container, no reverse proxy of your own needed; plain-HTTP visits to
  port 8080 are sent there. On the first start it makes a self-signed
  certificate, so browsers warn until an admin uploads a certificate they
  trust on the new Settings page; it is checked (matching key, in date, no
  passphrase) and used at once, with no restart. nginx runs as the same
  non-root user, allows TLS 1.2 and 1.3 only, and passes on the visitor's
  address so failed sign-ins are still counted per address. The session
  cookie is marked Secure by itself. `NXRAY_HTTPS_PORT` tells NXray the
  port if you publish HTTPS on another one. With the setting off, nothing
  changes. A `docker-compose.yml` copied before this has no `8443` line;
  add it before turning HTTPS on.
- **Two-factor sign-in, optional, per account.** On the Account page, Set up
  two-factor sign-in shows a QR code to scan with an authenticator app
  (Google Authenticator, Microsoft Authenticator, Authy, 1Password and
  others), or a key to type in by hand; it turns on once you type a right
  code from the app, and then shows ten one-time backup codes, once. After
  that, signing in asks for the app's six-digit code after the password,
  or a backup code if the phone is lost. A code works only once, wrong codes
  count towards the sign-in lockout, and turning it on signs your other
  sessions out. Turning it off or making new backup codes needs your
  password. Admins see who has it on, on the Users page, and can turn it off
  for someone who lost their phone and their backup codes; the only admin
  can do that for themselves from the Docker host with
  `docker compose exec nxray python -m app.resetpw --2fa-off <username>`.
  The key is stored encrypted and the backup codes only as hashes. Off for
  everyone until they turn it on, so nothing changes when you upgrade. The
  codes depend on the clock of the machine NXray runs on being right.
- **More NXray accounts, with roles.** Admins add sign-in accounts on a new
  Users page and give each a role: admin (everything, including the Switch
  page and the Users page), operator (turn ports on or off, edit
  descriptions, change VLANs, Save config) or viewer (look only). Pages
  hide the buttons a role can't use, and NXray refuses those forms if they
  are sent anyway. Admins can change roles, disable an account (it is signed
  out at once) and set a new password (it is signed out everywhere);
  NXray always keeps at least one active admin. Everyone changes their own
  password on the new Account page (click your name at the top). The
  account in `nxray.env` becomes the first admin at the first start after
  upgrading, so you keep signing in as before; after that, changing
  `NXRAY_ADMIN_USER` or `NXRAY_ADMIN_PASSWORD_HASH` no longer changes who
  can sign in. A forgotten password can be reset from the Docker host with
  `docker compose exec nxray python -m app.resetpw <username>`.
- **Switch settings on the Switch page.** Change the switch address lets
  NXray follow a switch whose management address or NX-API port changed: it
  signs in at the new address with its own account first and keeps the old
  address if that fails, with no admin login needed. Run setup again repairs
  NXray's switch login with the admin login when it stopped working (the
  account's password was changed or the account was removed on the switch,
  or NXray can no longer read its stored copy after a secret key change): it
  gives the same account a new password, or makes it again under the same
  name, and keeps its port and VLAN permissions; the address can be changed
  in the same step. Before, the only way out was to forget the switch and
  set it up again under a new account name. If the account had lost the
  nxray-ports role, it gets it back (an account that was still there means
  the usual 11-minute wait, once); if the role is gone from the switch,
  port changes are turned off with a note to turn them on again. The
  messages for a refused NXray login and a changed secret key now point to
  Run setup again.
- **VLANs.** A new VLANs page lists every VLAN with the ports that use it,
  and creates, renames and deletes VLANs; deleting asks to confirm, and a
  VLAN a port still uses is not deleted (the page names the ports to move
  first). Each port's own page now shows its mode and VLANs and can set
  them: access or trunk, the access or native VLAN, and the VLANs a trunk
  carries, with a confirm step that warns when a port switches between
  access and trunk, moves to another VLAN or stops carrying VLANs. VLAN
  names are checked before they reach the switch, which silently ignores
  names longer than 32 characters. Turning on port changes now also allows
  these VLAN changes: on a new install, one button (Turn on port and VLAN
  changes) turns on both, with a single wait of about 11 minutes, and the
  Switch page says so. An install that turned port changes on before this
  shows a Turn on VLAN changes button on the Switch page: it asks for the
  admin login once more to add the VLAN rules to NXray's role, with no wait
  this time. The unsaved-changes reminder now says NXray changed the
  switch, as it also covers VLAN changes.
- **Port changes.** Each port's own page can now turn the port on or off and
  change or remove its description, with a confirm step that warns when a
  port that is up is about to be turned off. A Save config button keeps the
  changes over a restart of the switch, and the pages remind you while
  changes are unsaved. Port changes are off until you turn them on on the
  Switch page with the switch's admin login: NXray then signs in to the
  switch over SSH once to create a role (`nxray-ports`) that lets its
  account do only that, on the front-panel ports only, and gives it to the
  account; the switch keeps refusing it everything else, including mgmt0,
  speeds and accounts. The admin password is never stored. Because
  the switch applies a new role only to an account it has not heard from
  for a while, NXray then waits about 11 minutes before contacting the
  switch again and says so on every page. Needs SSH reachable from the
  machine running NXray.

  Save config pressed on a port's page (or on the VLANs page) used to jump
  to the Switch page after saving; it now stays on that page and shows
  that the configuration was saved, or why saving failed.

  Pressing Save config twice in quick succession used to show "another
  request for config change is already in progress" although the switch
  had saved; NXray now runs one save at a time, so both presses save.
- **Ports page.** A new Ports page lists every front-panel port with its
  description, state (with the switch's reason when it is down), speed,
  VLAN, transceiver, traffic in and out over the last 30 seconds, and its
  error count, with filters for up, down and ports with errors. Each port
  has its own page with its MAC address, MTU, last link change, the
  transceiver's vendor, part and serial number, totals sent and received,
  and every error and discard counter. Read-only.
- **Switch setup.** The new Switch page connects NXray to a switch. It signs
  in to NX-API once with the switch's admin login, creates NXray's own
  read-only account (role `network-operator`) with a long random password,
  checks that account can sign in, and saves the switch configuration so
  the account survives a restart; the page warns that this also saves any
  other unsaved changes. The admin password is never stored. Each install
  picks its own account name, and setup stops if the name already exists on
  the switch. The new account's password is stored encrypted. The dashboard
  and the Test connection button say plainly when the switch can't be
  reached or refuses the login, and Forget this switch removes the stored
  login. Forms that change anything are protected against cross-site
  forgery.

  When setup fails after the new account has signed in (for example,
  storing its login fails), the switch refuses to remove the account again
  for about 10 minutes. The page used to say it was removed anyway; it now
  says the account is still on the switch, and how to remove it or set up
  again with another name.
- **Sign in.** NXray runs as a Docker container and asks for a username and
  password before showing anything. The password is stored only as an
  Argon2id hash in `nxray.env`, made with `python -m app.hashpw`; NXray
  refuses to start without one and has no default password. Sessions are
  kept on the server, so logging out ends them at once, and repeated wrong
  passwords from one address are blocked for a while.
- **Dashboard.** After signing in you see the dashboard. With no switch set
  up it points to the Switch page; once one is, it reads the switch live
  and shows its hostname, model, NX-OS version, uptime and last restart
  reason; every temperature sensor against the switch's own minor and
  major limits; each fan and the fan speed; each power supply with its
  input, output and capacity, the total draw and the power mode; CPU and
  memory use; and how many Ethernet ports are up, down or empty. Anything
  the switch reports as too hot or failed is listed at the top under
  "Needs attention". If the switch can't be reached or refuses NXray's
  login, the page says so instead.
- **Protection for the pages.** Every page except sign-in and the health check
  needs a session, other sites cannot frame NXray, and the pages run no
  inline scripts.
- **Health check.** `GET /healthz` answers without a session, for Docker's
  health check.
