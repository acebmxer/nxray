# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

NXray is a web interface for Cisco Nexus switches, built on NX-API.

## [Unreleased]

### Added

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
