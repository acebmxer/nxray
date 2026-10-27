# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

NXray is a web interface for Cisco Nexus switches, built on NX-API.

## [Unreleased]

### Added

- **VLANs.** A new VLANs page lists every VLAN with the ports that use it,
  and creates, renames and deletes VLANs; deleting asks to confirm, and a
  VLAN a port still uses is not deleted (the page names the ports to move
  first). Each port's own page now shows its mode and VLANs and can set
  them: access or trunk, the access or native VLAN, and the VLANs a trunk
  carries, with a confirm step that warns when a port switches between
  access and trunk, moves to another VLAN or stops carrying VLANs. VLAN
  names are checked before they reach the switch, which silently ignores
  names longer than 32 characters. Turning on port changes now also allows
  these VLAN changes. An install that turned port changes on before this
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
