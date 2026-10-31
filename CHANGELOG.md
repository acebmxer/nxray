# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

NXray is a web interface for Cisco Nexus switches, built on NX-API.

## [Unreleased]

### Added

- **Routing page: VRFs.** The Routing page lists the VRFs (separate routing
  tables), each with its state and the interfaces in it; default and
  management (mgmt0) are marked as the switch's own and never changed.
  Operators and admins can, after a confirm page, make a VRF, delete one
  (refused while interfaces are in it, naming them), move a VLAN interface
  or routed port into another VRF or back to default, and make a new VLAN
  interface straight into a VRF. The switch deletes an interface's addresses
  when its VRF changes, so the confirm page lists the ones that will go.
  NXray's `nxray-ports` role gets rules 51 to 54 (`vrf context * ;
  description *`, so the account may make a VRF, `no vrf context *`, `vrf
  member *`, `no vrf member *`; role version 8); an older role gets a **Turn
  on VRF changes** button, with no wait. The rules were tried on an
  N9K-C92160YC-X with NX-OS 9.3(16) with a throwaway account on an unused
  port.
- **Routing page: VLAN interfaces.** A new **Routing** page lists the VLAN
  interfaces (which give the switch its own address in a VLAN, so devices
  there can use it as their gateway) and the routed ports, each with its
  state, VRF and IPv4 and IPv6 addresses. Every role can look, and each VLAN
  on the VLANs page links to its VLAN interface. Operators and admins can,
  after a confirm page, make a VLAN interface for a VLAN (with an IPv4 and an
  IPv6 address, a description, an MTU, on or off), change it, delete it
  (never Vlan1), and add and remove IPv4 (main or extra) and IPv6 addresses
  on VLAN interfaces and routed ports. NXray refuses an address in a network
  another interface in the same VRF has and link-local IPv6 addresses, which
  the switch makes by itself. The VLANs page refuses to delete a VLAN that
  has a VLAN interface. VLAN interfaces need the interface-vlan feature; with
  it off the page says so and points to the Features page. A routed port's
  page now shows its extra IPv4 and IPv6 addresses and takes them off when
  the port goes back to switched. NXray's `nxray-ports` role gets rules 48
  to 50 (`ipv6 address *`, `no ipv6 address *`, `no interface Vlan *`) and
  `permit interface Vlan1-254` in its port list (role version 7), so NXray
  makes and changes VLAN interfaces of VLANs 1 to 254 only: the switch stores
  the range as one line per VLAN interface, and all 4094 took it minutes and
  stopped NX-API answering (#11); an older
  role gets a **Turn on VLAN interface and VRF changes** button, with no wait,
  checked and saved over SSH. The switch takes the VLAN interfaces into the
  port list only while interface-vlan is on, so with it off NXray leaves
  that line out and says so; once an admin turns interface-vlan on, **Update
  the port list** adds it (#10). The rules were tried on an N9K-C92160YC-X with
  NX-OS 9.3(16) with a throwaway account on an unused port and VLAN.
- **Port-channels page.** A new **Port-channels** page lists every
  port-channel with its ports, each port's state and how it joined (LACP
  active, LACP passive or static) and, while LACP is on, each port's LACP
  rate and port priority, the device at the other end with its maker, and
  the switch's own LACP priority. Every role can look; the Ports page and a
  port's page link a port to its port-channel. Operators and admins can,
  after a confirm page, make a port-channel from free front ports (with an
  optional fast LACP rate and description), add and take out ports, delete
  an empty one (NXray refuses while it still has ports and names them, where
  the switch would quietly pull them out), set its description and LACP
  minimum links, set one port's LACP rate and priority, and set the switch's
  LACP priority, which warns that every LACP port-channel agrees on its ports
  again. The switch changes a member's LACP rate only while the port is off,
  so NXray says so instead of sending it. LACP active and passive need LACP
  on; with it off the page offers static port-channels only. Changes wait for
  **Save config**, which the page has too. NXray's `nxray-ports` role gets
  rules 41 to 47 (`channel-group *`, `no channel-group`, `lacp rate *`, `lacp
  port-priority *`, `lacp min-links *`, `no interface port-channel *`, `lacp
  system-priority *`) and `permit interface port-channel1-4096` in its port
  list, which also lets its port rules act on port-channels (role version
  6). A new install turns everything on with **Turn on port, VLAN, port
  settings, feature, neighbor and port-channel changes**; an older role gets
  a button such as **Turn on port-channel changes**, with no wait. Adding the
  port-channels to the role is checked and saved over SSH rather than NX-API,
  which once stopped answering for about 15 minutes right after such a
  change on NX-OS 9.3(16). These rules were tried on an N9K-C92160YC-X with
  NX-OS 9.3(16) with a throwaway account on two unused ports, except `lacp
  system-priority`, which touches every port-channel on the switch.
- **Neighbor changes.** Operators and admins can now change CDP, LLDP and
  the MAC address table. On a port's page, a **CDP and LLDP** card shows whether the port
  speaks CDP and, while LLDP is on for the switch, whether it sends and
  listens for LLDP, each with its own tick box; only what changes is sent,
  after a confirm page that warns a device stops showing as a neighbor once
  its hold time runs out. With LLDP off for the switch, the LLDP boxes are
  left out and the card says to turn LLDP on on the Features page. The
  port's **Connected devices** card gets a button that clears the addresses
  learned on that port. The Neighbors page gets a **Static addresses** card
  listing the entries fixed by hand, each with **Remove**, and a form that
  adds one: a MAC address in any common form, a VLAN that exists on the
  switch, and the front port its traffic always goes to, or dropped to block
  the address. Multicast, broadcast and all-zero addresses are refused, and
  the confirm page warns when the address was learned on another port. A
  **Change the MAC address table** card sets how long learned addresses are
  kept (120 to 918000 seconds in steps of 5, or 0 for never; the switch
  quietly rounds other values down, so NXray refuses them) and clears
  learned addresses: all of them, one port's, one VLAN's, or one address.
  Clearing changes no configuration, so it leaves nothing to save; the other
  changes wait for **Save config**, which the Neighbors page now has too.
  NXray's `nxray-ports` role gets rules 30 to 40 (`cdp enable`, `lldp
  transmit`, `lldp receive` and their `no` forms on the front ports, `mac
  address-table aging-time *`, `mac address-table static *` and its `no`
  form, `clear mac address-table dynamic`; role version 5). A new install
  turns everything on with **Turn on port, VLAN, port settings, feature and
  neighbor changes** (one wait, as before); an install whose role is older
  gets a button named for what it lacks, such as **Turn on neighbor
  changes**, with no wait. The CDP, aging-time, static-address and clearing
  rules were tried on an N9K-C92160YC-X with NX-OS 9.3(16) with a throwaway
  account on an unused port; the LLDP lines need LLDP on and have not been
  tried on a switch yet, nor has the shape of `show lldp interface`, which
  NXray reads from the field names in Cisco's guides.
- **Features page.** A new **Features** page lists every feature the switch
  reports (130 on an N9K-C92160YC-X with NX-OS 9.3), grouped into routing,
  gateway redundancy, multicast, layer 2, VXLAN and MPLS, management,
  security, monitoring, programmability and other, each with a one-line
  description and whether it is on. It shows the command you would type
  (`ssh`, `hsrp`, `nv overlay`) rather than the switch's internal name. Every
  role can look; an admin turns a feature on or off after a confirm page, and
  the change waits for **Save config** like any other. NXray refuses to turn
  off a feature it can see in use (LACP while an LACP port-channel exists,
  naming it and its ports; VLAN interfaces while one exists), never turns
  off NX-API or SSH, which it needs itself, and leaves alone the features
  that have no `feature` command on the switch (services NX-OS runs itself,
  and the NX-SDK app slots, shown as one line). Turning one off warns that
  its settings are deleted. The Neighbors page's "LLDP is off" note now
  points to the Features page.
- **Feature changes on the Switch page.** NXray's `nxray-ports` role gets
  rules 28 and 29 (`conf t ; feature *` and `conf t ; no feature *`, role
  version 4). A new install turns everything on with one button (one wait,
  as before; now **Turn on port, VLAN, port settings, feature and neighbor
  changes**, see neighbor changes above); an install whose role is older
  gets a button named for what it lacks, with no wait. The Save config button on the Features
  page answers on that page.

- **Neighbors page.** A new **Neighbors** page, open to every role, lists
  what the switch knows about the devices around it, read live: the devices
  that announce themselves over CDP or LLDP (port, name, their port, model,
  management address, what they can act as, VLAN); the MAC address table
  (every device address the switch has learned, its VLAN, the port it came in
  on, its IPv4 address when the ARP table has one, and how long an address is
  kept without traffic), with a search box for part of a MAC address in any
  form, a maker, a port or a VLAN; and the ARP table of every VRF. The page
  says whether CDP and LLDP are on. With LLDP off, only CDP devices can
  appear, and the page says so; LLDP neighbors appear by themselves once LLDP
  is turned on.
- **What is plugged into a port.** Each port's page has a **Connected
  devices** card with the neighbors on that port and the addresses learned on
  it, and the front panel's tooltips name the CDP or LLDP neighbor and up to
  three learned addresses. For a port in a port-channel these are the
  port-channel's addresses, because the switch learns them on the bundle; the
  card says so and names the other ports in it. The Ports page and a port's
  page ask the switch for these in two more requests; if the switch refuses
  them, the rest of the page still shows.
- **Device makers from the MAC address.** Every learned address shows the
  company its block was assigned to, from the IEEE's public MA-L, MA-M and
  MA-S lists (the smallest matching block wins), downloaded each time the
  image is built. An address a VM, a container or a phone made up for itself
  (locally administered) is labelled as such instead. When the build cannot
  reach the IEEE, the copy in the repository is used.
- **Port settings.** Each port's page has a **Port settings** card showing
  the port's layer (switched, or routed with its IPv4 address), speed,
  duplex, MTU, FEC, flow control and storm control, and **Change settings**
  sets them after a confirm page that sends only what changed: switched or
  routed (`no switchport`, with an address typed as `192.0.2.1/24`), the
  speed (Auto or one the port can run at), the MTU (1500 or 9216 jumbo frames
  on a switched port, 576 to 9216 on a routed one), the FEC mode, flow control
  in each direction, and storm-control levels for broadcast, multicast and
  unknown unicast with the action above them (drop, SNMP trap or turn the port
  off). Duplex is shown only: the switch offers full duplex alone. The
  confirm page warns when the link goes down for a moment, when a layer change
  removes the VLANs or the address, when a smaller MTU drops large frames and
  when the shutdown action is picked. NXray's account may not read the
  running configuration, so the settings come from show commands; for a port
  that is up the switch reports the speed it runs at.
- **Splitting a 100G port.** Ethernet1/50 and 1/52 can be split into four
  ports (4 x 10G or 4 x 25G) from their page, and one of the four ports joins
  them again. The confirm page says the port's settings are removed and the
  new ports start with the switch's defaults.
- **Port settings changes on the Switch page.** NXray's `nxray-ports` role
  gets rules 12 to 27 for those settings and for splitting ports (role
  version 3), turned on from the Switch page with the other changes (see
  Feature changes on the Switch page for the button names). **Update the
  port list** adds the ports a split or join made to the role, which names
  every port it covers;
  until then the switch refuses NXray's changes to them and the page says
  where to go.
- **Front panel picture on the Ports page.** A drawing of the switch's front
  panel sits above the port table, with every port in its place: in pairs with
  the odd number on top, the 48 small SFP cages in blocks of six pairs and the
  six wide QSFP cages after them. Which cages are wide comes from what the
  switch reports for each port (40 Gb/s or more), and a QSFP port split into
  four (breakout) is drawn as one cage cut into four. Buttons above it colour
  the ports by **State** (up; down with something plugged in; empty; turned
  off), **Traffic** (the busier direction as a share of the link's speed: under
  1 %, 1 to 10 %, 10 to 50 %, 50 % or more), **Errors** (errors or discards
  counted since the counters were cleared) or **VLAN** (one colour per access
  VLAN, trunks hatched, routed ports grey, ports without a link faded; colours
  repeat after eight VLANs). A legend under the picture counts the ports in
  each colour. Hovering over a port shows its name, label, state, speed, VLAN,
  description, transceiver, traffic and errors; clicking it opens the port's
  page. The picture is inline SVG drawn on the server with no script, like the
  History charts. State, Traffic and Errors use the same single request to the
  switch as before; VLAN adds `show vlan brief` and `show interface
  switchport` to that request for the VLAN names.
- **Port labels.** Each port's page has a **Label** card for your own note on
  the port, such as "Proxmox node 2, NIC 1" (up to 64 characters, one line).
  Labels are kept in NXray's database only and never sent to the switch, so
  they can hold any text, need no confirm step and work while port changes are
  off. They show on the port's page, under the port's name in the Ports table,
  in the front panel's tooltip, and as a dot on the picture. Operators and
  admins can set them; viewers see them. Schema version 9 adds the
  `port_labels` table.
- **History: graphs of the switch over time.** NXray now reads the switch
  once a minute (`NXRAY_HISTORY_INTERVAL`, 10 to 3600 seconds, `0` for off) and
  keeps 30 days. A background thread runs `show environment`, `show system
  resources` and `show interface` in one NX-API request, the same three
  commands the dashboard runs when it opens, and stores temperatures per
  sensor, total power draw, fan speed, CPU and memory use, the traffic of all
  ports together, and for each port that is up its in and out rate, plus each
  port's new errors and discards. A new **History** page draws them as line
  charts for the last hour, 6 hours, 24 hours, 7 days or 30 days, and every
  port's page gets its own traffic and error charts under the same range
  links. The charts are drawn on the server as inline SVG with no script and
  no chart library, so the strict Content-Security-Policy stays as it is; the
  colours come from CSS classes. Times are UTC. Longer ranges average the
  stored samples into at most 500 points per line. A line breaks where
  samples are missing, which is how a stretch when the switch could not be
  reached shows. A port's errors are stored as the increase since the
  previous sample (the switch's counters only ever grow until cleared), so the
  first sample after NXray starts stores none and a counter that went down
  stores none. The sampler leaves the switch alone while NXray waits for a new
  role to apply (the pause after **Turn on port, VLAN, port settings, feature and neighbor changes**), logs a failure
  when it starts and when it ends rather than every minute, and deletes rows
  older than 30 days once an hour. Opening the pages reads only the database
  and never contacts the switch. About 7 MB a day is stored with a dozen
  ports up. Schema version 8 adds the `history` table.
- **Self-update, off by default.** Set `NXRAY_ENABLE_SELF_UPDATE=true` in
  `nxray.env` and uncomment the `docker.sock` mount and `group_add` lines in
  `docker-compose.yml`, and the Settings page gets an Updates card: NXray
  checks ghcr.io once a day (and on **Check now**) for a newer image under the
  tag the container runs, and an admin presses **Update now** to have Docker
  replace the container with it. Without the setting NXray never contacts
  ghcr.io or Docker, and the card only explains how to turn it on. What runs
  is read from Docker (`docker inspect`) and compared by image digest, so a
  manual `docker compose pull && up -d` cannot leave the page wrong; the pull
  and restart are done by a short-lived `nxray_updater` container started from
  the same image, because a container cannot replace itself, and it learns the
  compose project, folder and files from the labels compose puts on the
  container, so no path has to be configured. The replacement container
  records the success when it starts. The update is admin-only and
  CSRF-protected like the other Settings actions. An image built from a clone
  (`docker-compose.dev.yml`, which now passes `NXRAY_DEV_BUILD`) is never
  reported out of date, since its digest differs from the published one
  whether it is behind or ahead. The image now includes the Docker CLI and
  Compose plugin from Docker's own apt repository (client only, no daemon;
  Debian's Compose is too old to read the sample's `env_file` with
  `format: raw`). Its buttons use the same row layout as the Switch page's, so the quiet and
  primary buttons line up (the second form was being pushed 20px down by the
  rule that spaces stacked forms apart). Schema version 7 adds the `update_state` table. The CI image
  job gained a step checking that the update controls are absent with the
  setting off and that the Docker client is in the image; Trivy flags one
  HIGH in the Compose plugin's bundled `golang.org/x/net` (CVE-2026-78669,
  HTTP/2 denial of service, fixed upstream but not yet in a Compose release),
  accepted in `.trivyignore` with the reasoning, since the plugin serves
  nothing.

  The sample's `getent group docker` hint sat on its own commented line
  directly above `group_add`, so uncommenting the block took the shell command
  with it and Compose refused the file (`did not find expected '-'
  indicator`). The command is now part of the comment's sentence, and the two
  `group_add` lines are the only ones below it to uncomment.
- **Published image on GitHub Container Registry.** A new workflow,
  `.github/workflows/release.yml`, builds the image and pushes it to
  `ghcr.io/acebmxer/nxray` whenever a version tag is pushed (as `:X.Y.Z`,
  `:X.Y` and `:latest`). A second workflow, `.github/workflows/beta.yml`, is
  run by hand from the Actions tab on the `dev` branch and publishes a beta
  as `:beta` (the beta channel, which moves with every beta),
  `:X.Y.Z-beta.N` and `:dev-<short sha>`, never touching `:latest`, and
  creates a GitHub pre-release `vX.Y.Z-beta.N` with the `[Unreleased]` notes.
  A container started from `ghcr.io/acebmxer/nxray:beta` follows the beta
  channel, and Settings > Updates there compares against `:beta`.
  `docker-compose.yml.example` now pulls
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
  these VLAN changes: on a new install, one button turns on both (and the
  port settings, feature and neighbor changes above), with a single wait of
  about 11 minutes, and the Switch page says so. An install that turned port
  changes on before this shows a Turn on VLAN, port settings, feature and
  neighbor changes button on the Switch page: it asks for the admin login once more to add the rules to NXray's role,
  with no wait this time. The unsaved-changes reminder now says NXray changed the
  switch, as it also covers VLAN changes.
- **Port changes.** Each port's own page can now turn the port on or off and
  change or remove its description, with a confirm step that warns when a
  port that is up is about to be turned off. A Save config button keeps the
  changes over a restart of the switch, and the pages remind you while
  changes are unsaved. Port changes are off until you turn them on on the
  Switch page with the switch's admin login: NXray then signs in to the
  switch over SSH once to create a role (`nxray-ports`) that lets its
  account do only that, on the front-panel ports only, and gives it to the
  account; the switch keeps refusing it everything else, including mgmt0
  and accounts. The admin password is never stored. Because
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
