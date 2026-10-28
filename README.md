# NXray

[![CI](https://github.com/acebmxer/nxray/actions/workflows/ci.yml/badge.svg)](https://github.com/acebmxer/nxray/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![Docker](https://img.shields.io/badge/docker-compose-2496ED?logo=docker&logoColor=white)](docker-compose.yml.example)
[![Tests](https://img.shields.io/badge/tests-645%20unit-informational)](https://github.com/acebmxer/nxray/actions/workflows/ci.yml)
[![Ruff](https://img.shields.io/badge/ruff-clean-brightgreen)](https://github.com/acebmxer/nxray/actions/workflows/ci.yml)
[![Trivy](https://img.shields.io/badge/trivy-scanned-brightgreen)](https://github.com/acebmxer/nxray/actions/workflows/ci.yml)

A web interface for monitoring and managing Cisco Nexus switches through
NX-API, so everyday checks and changes don't need an SSH session.

Built and tested against a Nexus 9000 (N9K-C92160YC-X) on NX-OS 9.3.

**Status:** early. Stages 1 to 9 of the [roadmap](#roadmap) are built, and
stages 10 to 22 (the advanced switch features) are planned. Today you can
install NXray, sign in, connect it to a switch,
see the switch's health on the dashboard, look at every port, turn ports on
or off, edit their descriptions, create, rename and delete VLANs, set the
VLANs on ports, change the switch's address or repair NXray's switch login
from the web interface, and give other people their own NXray accounts as
admin, operator or viewer, each with optional two-factor sign-in, turn on
built-in HTTPS, update from the Settings page, and see 30 days of temperatures,
power, CPU, memory and port traffic as graphs.

## Read next

| Page | What it covers |
| --- | --- |
| [Installation](docs/installation.md) | Getting the container running |
| [Configuration](docs/configuration.md) | Every setting, its default and what it does |
| [Switch setup](docs/switch-setup.md) | What setup does on the switch, and how to undo it |
| [Function index](docs/functions.md) | Every function in the codebase, in one place |
| [Contributing](CONTRIBUTING.md) | Development setup and conventions |
| [Security](SECURITY.md) | Threat model and reporting a vulnerability |
| [Changelog](CHANGELOG.md) | What changed in each version |

## Quick start

On a Linux machine with Docker and Compose 2.30 or newer:

```bash
mkdir nxray && cd nxray
curl -o docker-compose.yml https://raw.githubusercontent.com/acebmxer/nxray/main/docker-compose.yml.example
curl -o nxray.env https://raw.githubusercontent.com/acebmxer/nxray/main/nxray.env.example
docker compose run --rm nxray python -m app.hashpw   # paste the printed line into nxray.env
docker compose up -d
```

Then open `http://<that machine>:8080` and sign in. The full steps are in
[Installation](docs/installation.md).

## Requirements

- Linux with Docker Engine and the Compose plugin, 2.30 or newer.
- A Cisco Nexus switch with NX-API turned on (`feature nxapi`), reachable from
  the Docker host on port 443. Turning on port changes also needs the
  switch's SSH (port 22) reachable from the Docker host, once.

## How it talks to the switch

Through NX-API, the switch's own HTTPS interface: the same commands you
type over SSH, answered as structured data. NXray uses its own read-only
account on the switch, never `admin`: the Switch page signs in with the admin
login once, creates that account with a long random password, saves the
switch configuration, and keeps only that account's login. The admin
password is never stored. See [Switch setup](docs/switch-setup.md).

Once a switch is set up, NXray also reads it every minute (three read-only
commands) to record history; see [Installation](docs/installation.md#history).

Turning on port changes is the one step that uses SSH: NX-API cannot create
the role that lets NXray's account change the front ports and the VLANs (and
nothing else), so NXray types it in over SSH with the admin login, once.

The switch's self-signed HTTPS certificate is accepted without checking; see
[SECURITY.md](SECURITY.md) for what that means.

## Roadmap

1. **Groundwork**: install, sign in, empty dashboard. *(built)*
2. **Switch setup**: a setup page that connects to the switch and creates
   NXray's own read-only account on it; clear messages when the switch can't
   be reached or refuses the login; a "Test connection" button. *(built)*
3. **Dashboard**: hostname, model, NX-OS version, uptime, temperatures against
   their limits, fans, power supplies and power draw, CPU and memory, port
   counts. *(built)*
4. **Ports page**: every port's state, speed, VLAN, description, transceiver,
   traffic and error counters. Read-only. *(built)*
5. **Port changes**: turn a port on or off and edit its description, with a
   confirm step, plus "Save config". *(built)*
6. **VLANs**: create, delete and rename VLANs; set the VLANs on ports.
   *(built)*
7. **Switch settings in the web interface**: change the switch address or run
   setup again. *(built)*
8. **HTTPS, more users, two-factor sign-in, self-update, published images.**
   More users with admin, operator and viewer roles: *(built)*. Optional
   two-factor sign-in per account: *(built)*. Built-in HTTPS, off by
   default: *(built)*. Published images on GHCR: *(built)*. Self-update, off by
default: *(built)*.
9. **History**: temperatures, power, fans, CPU, memory and port traffic and
   errors over time, as graphs. *(built)*
10. **Switch face**: a picture of the front panel with every port colored by
    state, traffic or VLAN; hover for details, click to open the port; your
    own labels on ports. *(planned)*
11. **Port settings**: speed, duplex, MTU and jumbo frames, FEC, breakout,
    storm control, flow control, layer 2 or layer 3 per port. *(planned)*
12. **Neighbors and tables**: LLDP and CDP neighbors, MAC address table, ARP,
    which device is on a port. *(planned)*
13. **Features**: turn switch features on and off. *(planned)*
14. **Link aggregation**: port-channels and LACP. *(planned)*
15. **Layer 3**: VLAN interfaces, routed ports, VRFs, static routes, routing
    protocols. *(planned)*
16. **Spanning tree.** *(planned)*
17. **Switch admin**: hostname, clock and NTP, DNS, logging, SNMP, banner.
    *(planned)*
18. **Security and config tools**: ACLs, port security, config diff, backup
    and rollback. *(planned)*
19. **Alerts** by e-mail and webhook. *(planned)*
20. **Activity log** and a viewer for the switch's own log. *(planned)*
21. **Several switches** in one NXray. *(planned)*
22. **Everything else** the switch offers over NX-API. *(planned)*

## Contributing

Pull requests go to the `dev` branch. Read [CONTRIBUTING.md](CONTRIBUTING.md)
for the setup and conventions, use the issue templates for
[bug reports and feature requests](https://github.com/acebmxer/nxray/issues/new/choose),
report vulnerabilities privately as described in [SECURITY.md](SECURITY.md),
and follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

[MIT](LICENSE)
