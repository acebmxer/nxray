# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

NXray is a web interface for Cisco Nexus switches, built on NX-API.

## [Unreleased]

### Added

- **Manage IP SLA from the web interface (#71).** The new **IP SLA** page (under Configure)
  makes IP SLA entries that measure from the switch: ping, UDP echo, UDP jitter (with an
  optional voice codec), TCP connect, DNS lookup and HTTP get, each with its frequency,
  threshold, timeout, VRF, type of service, packet size, tag, owner and history settings. It
  schedules an entry (start now, at a time, after a wait or when triggered; for a time or
  forever; every day if wanted), adds reactions to its results (round-trip time, timeout,
  jitter, packet loss and more, with thresholds and an SNMP trap or a trigger) and lets one
  entry start another. It lists every entry with what it measures, its state, its latest
  result, how many runs passed and failed, and its schedule and reactions. A scheduled entry
  cannot be changed: the page says to remove its schedule first. It needs the sla sender
  feature (Features page). Each change shows its lines and asks first. It works with the
  broad role or a stored admin login. The lines and show output were tried on a switch.
- **Manage 802.1X port authentication from the web interface (#68).** The new **802.1X**
  page (under Configure) sets the RADIUS server groups that check sign-ins and get
  accounting, turns 802.1X on or off for the switch, and per port sets port control (auto,
  force-authorized, force-unauthorized), the host mode (single-host, multi-host,
  multi-auth), MAC authentication bypass, regular sign-in, the timers and the retries. It
  lists the ports set up for 802.1X and every device signed in, with its port, MAC address,
  method, who checked it and the VLAN it was given. NX-OS has no guest VLAN and no
  auth-fail VLAN, so the page has neither; the RADIUS servers themselves are still made on
  the switch. It needs the dot1x feature (Features page). Each change shows its lines and
  asks first. It works with the broad role or a stored admin login. Written from Cisco's
  guide; not tried on a switch.
- **Manage VTP from the web interface (#67).** The new **VTP** page (under Configure) shows
  the switch's VTP status, the ports taking part and the message counters, and sets the VTP
  mode (transparent or off), domain, version (1 or 2) and password, and VTP on or off per
  port. A Nexus 9000 runs VTP in transparent mode only, so it never takes its VLAN list
  from another switch; the password that is set is never shown. It needs the vtp feature
  (Features page). Each change shows its lines and asks first. It works with the broad role
  or a stored admin login. Written from Cisco's guide; not tried on a switch.
- **Manage UDLD from the web interface (#66).** The new **UDLD** page (under Configure)
  turns UDLD on or off per port, sets aggressive mode per port or for every fibre port, and
  sets the message interval. It lists each port's setting, state and whether its link
  passes traffic both ways, and the neighbour each port hears. It needs the udld feature
  (Features page), which starts UDLD on every fibre port at once. Each change shows its
  lines and asks first. It works with the broad role or a stored admin login. Written from
  Cisco's guide; not tried on a switch.
- **Set up private VLANs from the web interface (#65).** The new **Private VLANs** page
  (under Configure) makes a VLAN a primary, isolated or community VLAN, gives a primary
  VLAN its secondary VLANs, sets a port's private VLAN mode (host, promiscuous, trunk
  promiscuous or trunk secondary) with its host association, mapping or trunk lines, and
  maps secondary VLANs to the primary VLAN's VLAN interface. It lists each primary and
  secondary VLAN with its host and promiscuous ports, and every port in a private VLAN
  mode. It needs the private-vlan feature (Features page). Each change shows its lines and
  asks first. It works with the broad role or a stored admin login; the limited role has
  no room left for it. The lines and show output were tried on a switch.
- **See control-plane policing (CoPP) from the web interface (#64).** The new
  **Control-plane policing** page (under Configure) names the CoPP policy applied to the
  control plane and lists its classes, with what each matches, its CoS, rate limit and
  burst, the traffic it passed and dropped, and its 5-minute offered and drop rates. The
  page only shows; every role can look. Read from a switch. Its table uses the whole
  width of the page, as does any page whose only card is a table, and only the matches
  wrap onto more lines.
- **See and set priority flow control (PFC) from the web interface (#63).** The new
  **Priority flow control** page (under Configure) lists every port's PFC mode and
  whether it is working, with the pause frames received and sent, and the pause counts
  per priority (CoS) for ports that have any. It sets a port's mode (on, off or auto) and
  watchdog, and the switch-wide watchdog and "force PFC off" setting. Each change shows
  its lines and asks first. It works with the broad role or a stored admin login; the
  limited role has no room left for it. The pause counters were read from a switch; the
  configuration lines are written from Cisco's NX-OS 9.3 guide and were not tried on one.
- **Manage QoS from the web interface (#62).** The new **QoS** page (under Configure)
  shows the class-maps and policy-maps that were made, what is applied to each port and
  to the whole switch, the switch's own default policies and the output queue counters
  (packets sent and dropped per port and QoS group). It makes class-maps that match
  DSCP, CoS, IP precedence, an ACL or RTP ports; makes policy-maps and adds classes that
  set a QoS group, DSCP, CoS or precedence or limit the rate; applies a policy to a
  port's incoming traffic; and makes network-qos policies (MTU, pause) and queuing
  policies (bandwidth, priority, shaping, queue limit) and applies them to the system.
  Each change shows its lines and asks first. It works with the broad role or a stored
  admin login; the limited role has no room left for it. The class-map, policy-map and
  port lines were tried on a switch with throwaway objects; applying a network-qos or
  queuing policy to the system changes the whole switch and was not tried.
- **Set up and monitor port mirroring (SPAN and ERSPAN) from the web interface (#61).**
  The new **Monitor sessions** page (under Configure) lists every monitor session with
  its state, sources and destination. It makes local (SPAN) and ERSPAN source sessions
  and ERSPAN destination sessions and sets their source ports and VLANs with a direction,
  the VLAN filter, the destination port or address, ERSPAN ID, VRF, time to live, DSCP,
  the largest packet copied, a description and on/off; marks a port as a monitor destination; and sets the
  ERSPAN source address. Each change shows its lines and asks first. It works with the
  broad role or a stored admin login; the limited role has no room left for it. The
  lines were tried on a switch with throwaway sessions, except ERSPAN destination
  sessions, which the switch refuses while the nve (VXLAN) feature is on; a session
  coming up was not seen, because the test ports were down.
- **Set up and monitor VXLAN and EVPN from the web interface (#60).** The new
  **VXLAN** page (under Configure) shows the NVE interface (state, source
  address, host reachability), its peers, and every VNI with its type, mode and
  state. It makes the NVE interface and sets its source interface, host
  reachability through BGP, on/off state and the flooding of every VNI; ties a
  VLAN to a VNI; adds layer 2 and layer 3 VNIs to the NVE interface with
  suppress-ARP, multicast group and ingress replication; sets a VNI's EVPN route
  distinguisher and route-targets; gives a VRF its layer 3 VNI and EVPN
  route-targets; and turns the EVPN control plane and the anycast gateway MAC
  on. Each change shows its lines and asks first. It needs the nve and
  vnseg_vlan features (Features page) and NXray's role at version 20: admins
  turn the features on, then press **Update the port list** on the Switch page,
  which now also names the NVE interface in the role's port list. The lines
  it sends were tried on a switch with throwaway objects; the role rules and EVPN with
  a real BGP neighbor were not. The EVPN settings need the bgp feature and EVPN turned
  on first.
- **Set up and monitor vPC from the web interface (#59).** The new **vPC** page
  (under Configure) shows the vPC domain (peer status, peer keepalive, which
  switch is primary, whether the two agree), the peer-link and every vPC with
  its state and consistency. It makes the vPC domain and sets its peer
  keepalive, role and system priority, peer switch, peer gateway, layer 3 peer
  router, ARP and IPv6 neighbor synchronization, auto-recovery and delay
  restore; marks a port-channel as the peer-link; and gives a port-channel a
  vPC number. Each change shows its lines and asks first. It needs the vpc and
  lacp features (Features page) and NXray's role at version 19: admins press
  **Update the port list** on the Switch page. Written from Cisco's NX-OS 9.3
  guides and not yet tried on a switch.

### Changed

- **The Ports page switch picture shows each port's speed in its normal view
  (#58).** A port that is up is now coloured by the speed it runs at (1G, 10G,
  25G, 40G, 100G), the same colours as the Speed view (40G is now pink, no longer
  orange, so it cannot be mistaken for amber), and the small light in
  its top right corner shows that it is up. Amber (down with something plugged
  in), grey (turned off) and empty ports are unchanged. The
  legends of the State, Speed, Traffic and Errors views always list every
  colour, with a count of 0 when no port has it. VLAN and Port-channel keep
  listing only the colours in use.

### Fixed

- **The Ports page keeps its room for the side panel again (#91).** On a screen 1700px
  or wider, the front panel picture and the port table stretched to the right edge, so
  a port's side panel covered their right end. They again stop short of the panel's
  place, open or shut.
- **The broad role now also denies EEM applets.** An EEM applet's commands run as the
  switch's admin, not as the account that made it, so NXray's account with the broad
  role could get past its own deny list (accounts, roles, AAA, boot) through an applet.
  The role now denies `event manager` configuration too. A broad role written by an
  older NXray is flagged on the Switch page and in a banner for admins: press **Update
  the port list** there to add the deny.
- **A page shows an update's new look without a forced reload (#90).** Browsers kept
  the old stylesheet and scripts for a while after NXray was updated, so a changed
  layout showed only after Ctrl+Shift+R. NXray now tells the browser to check them on
  every load; an unchanged file costs a short answer.
- **Table columns are no longer squeezed (#89).** In tables whose text wraps (the
  protocol, QoS, PFC, Monitor sessions, Activity, Alerts, Routing, Neighbors and
  Port-channels pages, among others) the first column took almost the whole width and
  every cell had extra space above and below. Columns now size to their content, so long
  text such as matches, messages and addresses gets the room.
- **The Spanning tree page needs far less scrolling (#57).** Its tables (Trees,
  Ports in the trees, Port settings) no longer stretch across the whole page.
  They sit in the page's columns like the other cards, and a long table keeps
  a fixed height and scrolls inside its card with the column names kept in
  view. On a 1920px-wide screen the page is about 40% shorter.

- **Neighbors no longer shows the text "null" for LLDP fields a neighbor did not
  send (#56).** A name, port, model, address or VLAN that the switch prints as
  `null` is now treated like "not advertised": the cell is empty, or the
  chassis ID or port ID is shown, as it already was for a missing name.

- **The container health check reads `NXRAY_ENABLE_HTTPS` the way the app does
  (#54).** It had its own looser copy, so a value the app refuses to start with
  (such as `maybe`) was read as "HTTPS off". It now uses `env_bool` from
  `app/config.py` and reports unhealthy for such a value.

- **A MAC address is read, and tested for being a group address, in one place
  (#53).** The static-entry check, the gateway-MAC check and the sFlow
  collector each had their own spelling rules and group-bit test. They all use
  `normalize_mac` and `is_group_mac` in `app/oui.py` now.

- **Which roles may change the switch is now decided in one place (#52).**
  Four pages each had their own copy of the operator/admin check, and three
  more wrote the role list out again. They all ask `may_change`, which asks
  `User.can_change`, so a new role only has to be added there.

- **A duration on the OSPF and multicast pages is now read one way (#51).**
  The two pages each had their own formatter; the multicast one kept a zero
  part such as `0d` and left a fractional-seconds time unchanged. Both use
  `duration_text` in `app/switch.py` now.

- **The small helpers that read a value from the switch's JSON now exist once
  (#50).** `text`, whole-number, true/yes and VRF-name readers were copied
  across a dozen modules and disagreed on what they accept. They now live in
  `app/switch.py`, with the stricter variants named for what they do
  (`digits_int`, `is_enabled`, `row_vrf`), so the same value reads the same way
  on every page.

- **Hiding a password or key in a message is now done one way (#49).** Seven
  places each had their own copy of the code; they all use `scrub_secrets`
  now, so an empty secret is handled the same everywhere.

- **Signing in now returns you to the page you asked for, query string
  included (#48).** A signed-out request to `/config?a=1&b=2` used to come back
  to `/config` only, and the address was put in `?next=` unencoded, so a `&` or
  `#` in it would have cut it short. The whole path and query are now kept and
  URL-encoded; only a local address is still accepted.

- **HTTPS responses now carry `Strict-Transport-Security` (#47).** With
  `NXRAY_ENABLE_HTTPS` or `NXRAY_HTTPS` on, the browser is told to keep to
  https:// for a year after its first visit, so a later typed `http://` address
  can no longer be intercepted before the redirect. Browsers ignore the
  header on a certificate they do not trust (the built-in self-signed one), but
  for a trusted certificate that later expires they offer no click-through.

- **Sign-ins are now logged (#45).** The container log records a wrong
  password or code, a lockout, a refused disabled account, a successful
  sign-in and a sign-out, each with the address and the account name, so an
  admin or a log watcher such as fail2ban can see who is guessing. The name is
  quoted and cut short, and no password or code is ever written.

- **The data folder and the database are now private to NXray's user (#44).**
  The folder is set to mode 700 and the database files (with the stored switch
  configurations) to 600 from the moment they exist, and the session key is
  created 600 instead of being restricted after it is written. Existing
  installs are tightened at the next start; a bind-mounted folder NXray does
  not own is left as it is, so set its mode on the host.

- **The sFlow collector no longer trusts the agent address written inside a
  datagram (#43).** A datagram now counts only when it was also sent from an
  address of that same switch, so a packet from another host that names a
  switch as its agent is ignored and its sender is listed on the Traffic page.

- **A trailing line break is no longer accepted in a switch password, account
  name, port name or switch host (#42).** The checks now refuse a value that
  ends in a line break, like any other character outside the allowed set.

## [0.2.1] - 2026-11-08

**A small release: choose how much access NXray's switch account gets, a Restart button that needs no admin login, and two fixes.** Run **Update the port list** on the Switch page once per switch to pick up the new role rules (role version 18). No `docker-compose.yml` change is needed.

### Added

- **Choose how much access NXray's switch account gets, per switch (#40).**
  Pick it in the setup form or later on the Switch page: the **limited role**
  (default, as before), a **broad role with a deny list** (any configuration
  and show command on the listed ports except accounts, roles, AAA, TACACS+,
  RADIUS and the boot image, so new features need no role update), or the
  limited role with the **switch admin login stored** (encrypted), so NXray
  adds new rules itself when it starts. Changing the choice asks for the admin
  login and removes the rules the new choice does not have; **Delete the
  stored admin login** returns to the limited role. The broad role's denies for
  `role`, `aaa`, `tacacs-server`, `radius-server` and `boot` are not yet tried
  on a real switch.

- **A "Restart" button in the top bar and at the foot of the menu** (admins
  only), so restarting the switch no longer needs a trip to the Config page.
  Both open the same confirm page (#38). That page now asks "Do you want to
  save the changes first?" when something is unsaved, and "Are you sure you
  want to restart the switch?" (without the Save first box) when nothing is.

- **Restart needs no admin login any more, and goes straight ahead when
  nothing is unsaved (#39).** NXray's role gets the restart rules (role
  version 18): run Update the port list on the Switch page once to pick them
  up. Until then the restart page asks for the admin login as before. With
  unsaved changes it still asks whether to save first. Not yet tried on a
  real switch.

### Changed

- **The Light / Dark / System choice is now in the top bar**, to the right of
  the Refresh control, instead of at the bottom of the menu. It also shows
  when the menu is narrowed (#37).

### Fixed

- **Selected text on a self-refreshing page is kept (#41).** On the Config page
  and the other pages that refresh whole, text selected with the mouse was
  cleared within a second or two, so it could not be copied. A refresh now waits
  while text in the page is selected.

- **Switching a port from trunk to access now clears its trunk settings.** The
  port kept its trunk native VLAN and trunk allowed VLANs in the running
  config, and the VLAN form kept showing them. NXray now sets them back to the
  defaults (native VLAN 1, every VLAN carried), which the switch leaves out of
  the configuration. The confirm page lists it, and the bulk port change does
  the same. An access port that still carries such leftovers gets them cleared
  the next time its VLANs are changed (#35).

## [0.2.0] - 2026-11-05

**A feature release: traffic per VLAN and per device with sFlow, live figures
on every page, NXray users with their own switch accounts, and Include beta
versions for self-update.** Coming from 0.1.1 on `:latest`, run
`docker compose pull` and `docker compose up -d`; on `:0.1.1`, put `:0.2.0`
in the compose file's `image:` line first. Coming from a beta, replace
`:beta` with `:latest` or `:0.2.0`. The data volume carries over and the
database upgrades itself on first start. On each switch, open the Switch page
and press **Update the port list** so NXray's role gains the new rules (the
banner on every page says when a switch is behind).

### Added

- **Refresh, last-updated time and Pause on every page.** The top bar's
  **Refresh** choice, the *Updated* time and **Pause** were only on the
  dashboard, Ports, a port's page and Neighbors. They are now on every page.
  VLANs, Port-channels, Traffic, Spanning tree, Routing, Protocols, Security,
  Features, Switch admin, Alerts, History, Activity, Config and Switch
  refresh by reading the page again, with sections that were open and wide
  tables scrolled staying as they were, and pausing while a field is changed
  and not yet sent. Pages with nothing to refresh (Settings, Users, Account)
  show the control and say so, so the top bar no longer changes from page to
  page. The switch is read through the shared cache, so many open pages still
  cost it one read per interval, and refreshing still does not keep a sign-in
  alive. See [Live figures](docs/live.md) (#33).

- **Make or delete an NXray user and a switch account separately.** The Users
  page can now make a switch account on its own (**Add a switch account
  only**: a local account for someone who uses SSH or the console, with the
  role you pick, on the switches you tick), and delete either side. **Delete**
  beside a user opens a page naming their switch accounts: tick none to delete
  the NXray user only (their switch accounts stay, linked to no one), or tick
  some to delete those too. **Delete** beside an account in *Local accounts
  on …* deletes it from the switches you tick, whether or not an NXray user is
  linked to it (the user stays, only the link goes). Each asks to confirm, uses
  the switch admin login once and never stores it, and saves the switch
  configuration. If a switch refuses, the NXray user is kept so you can try
  again. NXray's own account, the switch's `admin` and the other reserved
  names, your own account and the last active admin are never deleted (#31).
- **A banner on every page when the switch's permissions are behind.** After
  an NXray update adds a kind of change, an admin sees a notice at the top of
  every page (not only the Switch page) naming the switch and what it can't
  yet do, with a link to the Switch page where **Turn on …** brings it up to
  date. It shows only for admins, only for a switch that already had changes
  turned on, and one banner per switch that is behind. NXray still does not
  keep the switch's admin login.
- **Setting up a switch turns changes on in the same step.** The Switch
  page's setup form (and Add another switch) has a new **Also turn on
  changes** box, ticked by default, and an **SSH port** field. With it
  ticked, once NXray's account is made, setup gives it the `nxray-ports`
  role over SSH with the same admin login, so a new switch no longer needs
  the admin login typed a second time under **Turn on … changes**. The
  usual wait of about 11 minutes follows. If that step fails (SSH off or
  unreachable, a refused line), the switch stays set up with a read-only
  account, the page says why, and the Turn on button tries again. Untick
  the box to keep the account read-only. An already connected switch still
  needs the Turn on button after an update that adds rules. See
  [What setup does on the switch](docs/switch-setup.md#what-setup-does-on-the-switch)
  (#22).

- **Reset a port, several ticked ports or a port-channel to its defaults.**
  A port's own page and its side panel now have a **Reset to defaults**
  button, the Ports page's **Change several ports** card a **Reset the
  ticked ports to their defaults** button, and the Port-channels page a
  **Reset `<name>` to defaults** button for each port-channel. Each sends
  `default interface <name>` after a confirm page listing everything it
  removes (description, VLANs, speed, MTU, FEC, flow control, storm control,
  layer, any IP address) — or says there is nothing to remove when it is
  already a plain, unconfigured access port; a port-channel's reset names
  its member ports and says they keep their channel-group membership, which
  is set on the member, not the port-channel. Warns when a port or
  port-channel is up, since whatever is plugged in may lose its connection
  while it resets. This adds rule 232 to role version 16. See
  [Reset to defaults](docs/switch-setup.md#port-changes) (#21).

- **Traffic per VLAN and per device, measured with sFlow.** NXray can now be
  the switch's sFlow collector, which gives real traffic per VLAN and per
  device, trunks and ports with several devices behind them included, on a
  new **Traffic** page under Monitor: the busiest VLANs with their share, a
  chart of them over time, and the busiest devices by MAC address (sends and
  receives, with maker, IP addresses and port) with each one's traffic over
  time. Off by default: set `NXRAY_SFLOW_PORT=6343` in nxray.env and publish
  `"6343:6343/udp"` in docker-compose.yml (an older compose file needs the
  line added). Then, with traffic measuring changes on, the page's **Send
  sFlow to NXray** form sets the switch up (the sflow feature, the collector
  and its VRF, the agent address, the sampling rate and the ports), asks
  first and sends only what changes; **Turn sFlow off on the switch** undoes
  it. A port in a port-channel is sampled through its port-channel (the
  switch refuses the port itself), and a refusal part-way marks the switch as
  having unsaved changes, since the lines before it took effect. This adds
  rules 230 and 231 to role version 15. NXray counts only
  datagrams whose agent address is one of its switches and names any other
  sender. Minutes are kept `NXRAY_SFLOW_KEEP_DAYS` days (7), each with every
  VLAN and the 100 busiest devices each way. The switch-side lines follow
  Cisco's NX-OS 9.3 guide; the front-port lines have been tried on an
  N9K-C92160YC-X, the port-channel line not yet. See
  [Traffic per VLAN and per device](docs/traffic.md#measured-with-sflow) (#18, #23).

- **The last few minutes, drawn live.** While a refresh is on, a port's page
  has a **Last 10 minutes** chart of its In and Out (measured from the byte
  counters on **Live**, the switch's averages otherwise) and the dashboard a
  **CPU and memory, last 10 minutes** chart, both moving with the figures.
  The readings are kept in memory only, never written to the history, for as
  long as someone has a refreshing page open, and a page opened meanwhile
  draws what is already kept. See [Live figures](docs/live.md) (#19).

- **How long a port averages its rates.** The switch's In and Out are its own
  average over 30 seconds. A port's page and its side panel now show that
  average and, with the new **traffic measuring changes** on, have a **Rate
  average** card to set it to 5, 10 or 15 seconds, 1, 2 or 5 minutes, or back
  to the default (`load-interval counter 1`). It asks first, changes only the
  figures (never the traffic), and is not saved until Save config. The rate
  notes now name the real average instead of always saying 30 seconds. Turning
  it on adds rules 228 and 229 to NXray's role (role version 15) with no wait:
  an admin presses **Turn on traffic measuring changes** on the Switch page.
  The values follow Cisco's NX-OS 9.3 guide and have not yet been tried on a
  switch; a value the switch refuses is shown with its own words (#19).

- **Live figures.** The dashboard, the Ports page, a port's page and the
  Neighbors page can refresh their figures by themselves: pick **Live, 3 s, 5 s,
  10 s, 15 s, 30 s, 60 s** or **Off** (the default) in the top bar, kept per
  browser. Only the numbers, bars, front panel and table rows change, so an
  open side panel, scroll position and what you are typing stay; it pauses in a
  background tab, while a field has the cursor or unsent input, and on
  **Pause**, and shows when it last updated. NXray reads each switch once per
  floor however many browsers watch (`NXRAY_LIVE_MIN_INTERVAL`, 2 s;
  `NXRAY_LIVE_CLIENTS_MIN_INTERVAL`, 10 s for the MAC, ARP and neighbour
  tables), only with `show` commands, and backs off and says so when the switch
  does not answer. **Live** works In and Out out from the byte counters
  between two readings instead of the switch's 30-second average, and labels
  it. Refreshing does not keep a sign-in alive. See
  [Live figures](docs/live.md) (#19).

- **Traffic per VLAN and per device, estimated.** The switch counts traffic
  per port only, so NXray now works out two estimates from the port figures
  it already reads, and labels them as such. A device alone on an access
  port gets that port's traffic as its own (sends and receives): on the new
  **Busiest devices** card and a **Traffic now** column of the MAC address
  table on the Neighbors page, on a port's Connected devices card and in its
  side panel. Each VLAN's access ports that are up are added up: a **Traffic
  now** column on the VLANs page, from history's newest sample, and two
  **Traffic per VLAN** charts on the History page. Trunks, port-channels and
  ports with several devices behind them are left out, and the pages say so;
  [Traffic per VLAN and per device](docs/traffic.md) explains each figure and
  lists the read-only checks for measuring it instead (VLAN interface and
  VLAN counters, sFlow). History now reads `show interface status` as well,
  four read-only commands a sample instead of three, and the Neighbors page
  reads `show interface` once more (#18).

- **Switch accounts for NXray users.** An NXray user still exists only in
  NXray by default, but an admin can now also give them a local account on a
  switch with the same name and password, so people who use the command line
  can sign in over SSH too: tick the switches when adding someone, or use the
  new **Switch accounts** page of an existing user to make one, link an
  account already on the switch, set one new password for NXray and the
  switch, change its role, lock it or remove it. The role follows the NXray
  role (viewer `network-operator`, operator `network-operator` +
  `nxray-ports`, admin `network-admin`) and is shown to confirm before
  anything is sent. The switch admin login is typed on each form and never
  stored; the switch's password rules are checked first; each change saves
  the switch configuration so a restart does not undo it. The Users page
  lists the switch's local accounts and shows when a switch account is out
  of step (role, password, disabled), and the Account page says when your
  own switch password no longer matches. NXray's own switch account and the
  switch's `admin` are never touched. The docs say when TACACS+ or RADIUS
  suits better (#17).

- **Change several ports: one whole configuration for every ticked port.**
  Ticking a port on the Ports page now opens a **Change several ports** side
  panel on the right, laid out like a port's own panel: one section per kind
  of change, all in view. Its top lists the ticked ports; press one there, or
  its box in the table, to untick it, and the panel stays open while you tick
  more. It sets everything a
  port's own page can share, on any set of ticked ports, next to each other
  or not: on or off and a description, VLANs (access or trunk, access VLAN,
  native VLAN, VLANs carried), port settings (switched or routed, speed,
  MTU, FEC, flow control, storm-control levels and action), CDP and LLDP,
  and clearing the learned MAC addresses. Every setting starts at "Leave as
  it is" and only what you fill in is sent, so changing the MTU leaves the
  VLANs alone. Each port is checked as on its own page, including the
  trunk-carries-its-native-VLAN rule; if one cannot take it, nothing is sent
  and NXray names it and why. The confirm page lists each port's old → new
  values, leaves out ports already set as asked and warns about anything that
  cuts traffic; the result names what changed, what was refused and what was
  not tried. **Start from port** fills the form from an existing port, to copy
  a known-good one. An IPv4 address, the label and breakout stay per port.
  The form's fields changed: `action` is now `power` and `set_description`
  (#16).

- **Include beta versions, from the Settings page.** With self-update on,
  **Settings → Updates** has an **Include beta versions** switch (admin
  only) that moves NXray onto the beta channel and back without editing
  `docker-compose.yml` on the host. Saving it installs nothing: it checks
  again, and **Update now** does the move. With betas on, NXray goes to
  `:beta` while the newest beta is ahead of the latest release and back to
  `:latest` once a release has caught up; with betas off it follows
  `:latest` as before. Versions are ranked from the GitHub releases list, a
  release above every beta of its version, and only a newer version is ever
  offered: an older beta is never offered after its release, and turning
  betas off on a beta that is newer than the latest release stays on it
  until a newer release is out. A beta image now reports its own name
  (`0.2.0-beta.1`) in the page footer and `/healthz`. If the compose file
  names a fixed tag and so ignores the choice, the Updates card says so and
  shows the line to change instead of reporting success (#15).

  **Upgrading from 0.1.x: edit `docker-compose.yml` once.** Your compose file
  is your own and no update changes it. For the switch to work, change its
  `image:` line from `ghcr.io/acebmxer/nxray:latest` (or `:beta`, or a pinned
  `:0.1.0`) to `ghcr.io/acebmxer/nxray:${NXRAY_TAG:-latest}`, then run
  `docker compose pull` and `docker compose up -d`. Without the edit NXray
  still updates and runs as before; only the beta switch cannot move it. New
  installs copy `docker-compose.yml.example`, which already has the line.
  `nxray.env` and the data volume carry over either way.

### Changed

- **Traffic per VLAN is drawn as a small card for each VLAN, with a filled
  chart.** On the Traffic page each of the busiest VLANs now has a card of its
  own: the VLAN's name, its latest figure in large type with the highest and
  the average beneath, and beside them a short, wide chart of the traffic as a
  filled area with the scale on the right, instead of one chart with a thin
  line per VLAN. The cards sit two or three across on a wide screen. sFlow
  counts each frame once, so there is one figure per VLAN, not an in and an
  out (#29).
- **The Switch page keeps "Update the port list" in view while new functions
  wait to be turned on.** The two jobs used to share one card: when an update
  added rules the card read **Turn on …**, and once they were on it turned
  into **Update the port list** in the same place, which looked as if nothing
  had happened. Now **Turn on …** is a card of its own, shown only while the
  switch's permissions lack rules this version knows, and **Update the port
  list** stays below it, with its own explanation (#27).
- **Cards sit two or three across on a wide screen, on every page.** Each
  card used to take a full-width row of its own, so a wide screen showed mostly
  empty space and the page ran far down. From 1300 pixels wide a page's cards
  flow down two columns, and three from 2350 pixels, like newspaper columns, so
  a short card does not leave a gap beside a tall one; narrower screens stack
  them. The front panel, long tables (as many columns as the column fits, or
  over 20 rows), code blocks, messages and notes still take the whole row, and
  the places on a protocol or spanning tree card (one per VLAN, port or
  instance) fill the card in columns. On the Alerts page **Open now** now comes
  after **What to alert on** and **E-mail**, beside them on a wide screen. No
  table scrolls sideways any more: cells wrap, the VLAN grid squeezes its
  columns, and the Ports table drops its Transceiver and Activity columns under
  1500 pixels wide, and Description and Connected under 1200 (#28).

### Fixed

- **The Ports page no longer shifts when a port's panel opens, and the panel
  no longer covers the top bar.** The front panel picture and the port list
  used to shrink to make room when a port (or the ticked ports) opened its
  side panel, and grow back when it closed. On a screen 1700 pixels wide or
  more the page now keeps that room on the right all the time, empty while the
  panel is shut, so nothing moves. On a narrower screen the panel is laid over
  the page and nothing moves either. The panel now starts below the top bar,
  so the Refresh choice and the switch picker stay in reach (#32).
- **The buttons at the foot of a port's panel line up.** **Reset to defaults**
  sat lower than **Turn off** because its form carried a top margin of its own;
  both now share one line (#32).
- **Busiest VLANs no longer lumps untagged traffic under "VLAN not given".**
  A frame that comes in without a VLAN tag (on an access port, or on a trunk's
  native VLAN) has no VLAN in the sample the switch sends, so all of it was
  counted together and VLAN 2's own row came out far too low. NXray now reads
  each port's access or native VLAN from the switch (about once a minute, with
  the history sample) and counts such frames in that VLAN. "VLAN not given" is
  left for a port NXray has not read, such as in the first minute after it
  starts, or a routed port (#30).
- **Charts are no longer huge on a wide screen.** A chart stretched to the
  full page width, so on a wide screen it was taller than the screen and its
  labels were oversized. A chart is now at most 960 pixels wide. On the
  History and port pages the charts sit two to a row, and on the Traffic page
  the Busiest VLANs table sits beside its chart, whenever the screen leaves
  each at least 680 pixels, and the Send sFlow to NXray form there is no wider
  than 680 pixels. Narrower screens stack them as before (#26).

- **The Traffic page's sFlow card can read the switch's sFlow status.** It
  showed "The switch refused a command: 'show sflow': % Permission denied for
  the role", because the `nxray-ports` role permitted configuring sFlow but
  never `show sflow`. The role now has rule 233 for it (role version 17); an
  install already connected gets a **Turn on sFlow status changes** card on the
  Switch page, which adds the rule with no wait (#25).

- **A ticked port stays ticked while the page refreshes by itself.** With
  Refresh on anything but Off, a refresh that was already on its way when a
  tick box was pressed could land afterwards and redraw the rows without
  the tick, so it took two or three clicks. The page now checks again when
  the answer arrives and drops it if a box was changed meanwhile (#24).

- **A port's side panel no longer covers the right of the Ports page.**
  Opening a port from the front panel or the table used to lay its panel over
  the page, hiding the right-hand ports of the front panel. The page now moves
  aside for it, as it does for the **Change several ports** panel, so every
  port stays in view and can be clicked.

## [0.1.1] - 2026-11-01

**A fix release: every port change can now be made from the port's side
panel on the Ports page.** Coming from 0.1.0 on `:latest`, run
`docker compose pull` and `docker compose up -d`; on `:0.1.0`, put `:0.1.1`
in the compose file's `image:` line first. Coming from a beta, replace
`:beta` with `:latest` or `:0.1.1`. The data volume carries over.

### Fixed

- **The bar at the bottom of the Ports page points to the settings.** Its
  **Change the ticked ports** button looked like the whole form; the settings
  (VLANs, port settings, CDP and LLDP) are in the **Change several ports** card
  further down. The bar now has a **Choose what to change** link to it.

- **Ticked ports stay ticked when you switch the front-panel colour, change
  the filter or press Read again** on the Ports page. They were cleared
  before, so ticking two ports and then looking at the VLAN colours lost them.

- **The port side panel makes every change to the port.** On the Ports page,
  a port's side panel used to change only its description and turn it off or
  on; everything else needed **All of this port →**, which left the Ports
  page, and even a description change ended on the port's own page. The panel
  now has the same forms as the port's own page: VLANs, speed, MTU, FEC, flow
  control, storm control, layer and address, splitting or joining a 100G
  port, CDP and LLDP, the label, and clearing the addresses learned on the
  port. After the confirm page, a refusal or the result, the Ports page comes
  back with the same filter, colour mode and panel open, and the message and a
  Save config button are shown in the panel. Cancel on the confirm page goes
  back to the panel too. What each change sends to the switch, the confirm
  steps and the role checks are unchanged; **All of this port →** stays for
  the charts, counters and full device tables (#14).

## [0.1.0] - 2026-11-01

**The first stable release of NXray: all 20 stages of the roadmap, from the
dashboard and the ports to VLANs, layer 3, spanning tree, security, alerts and
several switches in one NXray.** A new install needs only
`docker-compose.yml` and `nxray.env` (see `docs/installation.md`). Coming from
a beta: put `ghcr.io/acebmxer/nxray:latest` (or `:0.1.0`) in the compose
file's `image:` line in place of `:beta`, then `docker compose pull` and
`docker compose up -d`; the data volume carries over.

### Added

- **VLAN grid.** The VLANs page shows every VLAN against every port and
  port-channel: **U** where the port carries it untagged (its access VLAN, or
  a trunk's native VLAN) and **T** where a trunk carries it tagged.

- **Change several ports at once.** With port changes on, the Ports page has
  a tick box on each row for operators and admins, a **Tick every port
  shown** link (which follows the Up, Down and With errors filters), and a
  **Change several ports** card that turns the ticked ports off or on or gives
  them all one description. The confirm page lists every port and what
  happens to it, warns for each up port about to be turned off, and leaves
  out ports already as asked. NXray changes the ports one request at a time;
  if the switch refuses one, it stops there and the page names the ports that
  changed, the one refused and the ones not tried, with the ticks kept. Each
  change is in the Activity log. The Ports page now shows the unsaved-changes
  reminder with a Save config button that stays on the Ports page (#3).

- **Several switches in one NXray.** Once a switch is set up, the Switch page
  (admins only) has **Add another switch**, the same setup as the first, and
  lists every switch NXray has. With two or more, the top bar has a switch
  picker, for every role: every page shows the switch picked there, and every
  change goes to that switch only. The choice is kept per browser. A page left
  open for one switch refuses its forms once another switch was picked in
  another tab (reload it and try again), so a change never lands on a switch
  the page did not show. Each switch has its own NXray account, port changes,
  history, port labels, config backups (a backup is never compared with or
  rolled back onto another switch) and open alerts; history reads every
  switch each minute, one after the other, and every alert names its switch
  (also in the alert log on the Alerts page). NXray refuses a second switch
  at an address it already has, and moving one onto another's address.
  **Forget this switch** now also deletes the history, port labels, config
  backups and open alerts NXray kept for that switch. An existing install
  keeps its switch and everything recorded for it.

- **Restart the switch.** The Config page (admins only) has **Restart the
  switch**: a confirm page warns that every port goes down for several
  minutes, says how much of the running configuration is unsaved, offers
  **Save first** (on by default), and asks for the switch admin login and
  SSH port. NXray saves with its own account when asked, then types
  `terminal dont-ask` and `reload` over SSH with the admin login, once; the
  password is never stored, and NXray's own role has no rule to restart the
  switch. A restart is in the Activity log. It is also how new TCAM region
  sizes take effect.

- **ACLs page: MAC ACLs, object groups, VLAN access maps and TCAM regions.**
  Operators and admins can now also make MAC ACLs (entries matching a source
  and destination MAC address, an EtherType, a CoS and a VLAN) and apply them
  in on a switched port (`mac port access-group`); make IPv4 and IPv6
  address groups and port groups, which an IPv4 or IPv6 entry names as
  `addrgroup <name>` or `portgroup <name>`; make VLAN access maps whose
  entries match an IPv4, IPv6 or MAC ACL and then forward or drop, and apply
  a map to VLANs with a VLAN filter; and size the TCAM regions. The page
  lists the TCAM regions with their size now and the size set, and which wait
  for a restart: on a Nexus 9000 port ACLs and VLAN ACLs have no space until
  their region is given some. These need NXray's role version 14.

- **DHCP and ARP.** A new **DHCP and ARP** page, linked from ACLs and Port
  security, shows and changes, after a confirm page that shows the lines and
  warns when devices can be cut off: DHCP snooping (on or off, its VLANs,
  option 82, checking client MAC addresses), each switched port's trust and
  DHCP rate limit, the DHCP relay (on or off, option 82, across VRFs) and the
  DHCP and DHCPv6 servers of each VLAN interface or routed port, dynamic ARP
  inspection (its VLANs, extra checks, log buffer, trusted ports) and ARP
  ACLs for hosts with fixed addresses, and IP Source Guard per port with
  fixed bindings. A table lists the addresses DHCP snooping learned (`show
  ip dhcp snooping binding`) and the fixed ones. It needs the dhcp feature.
  NXray's `nxray-ports` role gets rules 191 to 227 (role version 14); an older
  role gets a **Turn on layer 2 security changes** button, with no wait. The
  lines and rules follow Cisco's NX-OS 9.3 Security Configuration Guide and
  have not yet been tried on a switch.

- **Alerts by e-mail and webhook.** A new **Alerts** page (admins only, in
  the menu) sends an e-mail, a webhook or both when the switch needs
  attention, and again when the problem is over: NXray cannot reach the
  switch (two reads in a row), a temperature at its minor or major limit, a
  fan or power supply that is not OK, and, when turned on, CPU or memory at
  a limit for three checks in a row, a port that goes down from up while it
  is turned on (every port, or only those with a description or a label), a
  number of new errors on a port, and every change made through NXray. Each
  problem is sent once when it starts and once when it ends, also across a
  restart, and what one check finds goes out together. It is checked
  against each history sample, so it asks nothing more of the switch; with
  history off only changes are sent. E-mail goes through your mail server
  (STARTTLS, SSL/TLS, or none for a trusted relay, with the certificate
  checked and a password never sent unencrypted) to up to ten addresses;
  up to ten webhooks get NXray's own JSON (optionally signed with
  `X-NXray-Signature`), Slack's or Discord's format. The SMTP password and
  the webhook URLs and secrets are stored encrypted and never shown again.
  The page lists the problems open now and the alerts sent in the last 90
  days with how each delivery went, and has test buttons.

- **Activity log.** A new **Activity** page (admins only, in the menu) lists
  every change made through NXray, newest first: who made it, on which page,
  the change in plain words (passwords and SNMP communities masked) and the
  switch's address. It covers port, VLAN, port-channel, routing, protocol,
  spanning tree, switch admin, ACL, port security, neighbor and feature
  changes, Save config, backups and rollbacks, the Switch page's actions, and
  changes to NXray's own accounts and settings. Filter it by account, page or
  text, or download it as CSV. Lines are kept for a year.

- **Config: backups, comparing and rollback.** A new **Config** page (admins
  only) shows whether the running configuration differs from the saved one,
  line by line, with a Save config button. **Take a backup now** keeps the
  running configuration in NXray with a note, and the switch keeps a
  checkpoint of the same moment (`nxray-<number>`). Backups can be downloaded,
  compared with the running or saved configuration or with each other, and
  deleted with their checkpoint. **Roll back to this** shows what changes and
  asks for the switch admin login, used once and never stored: NXray's own
  account may not roll the switch back. NXray first backs up the
  configuration it replaces, so a rollback can be undone; NX-OS rolls back all
  or nothing.

- **ACLs and port security.** A new **Security** menu opens the **ACLs** page:
  every IPv4 and IPv6 ACL with its entries and where it applies. Operators and
  admins can, after a confirm page that shows the lines, make and delete ACLs,
  add and remove entries (permit or deny, protocol, source and destination as
  any, a network or one address, TCP, UDP and SCTP ports, logging) and
  remarks, count matches, and apply an ACL in or out on a VLAN interface or
  routed port, or in on a switched port or port-channel. The **Port
  security** page sets, for each switched front port, port security on or off,
  the most addresses, what happens on a violation, sticky learning, known
  addresses and aging; it needs the port-security feature. NXray's
  `nxray-ports` role gets rules 171 to 190 (role version 13); an older role
  gets a **Turn on security and config changes** button, with no wait. The
  lines follow Cisco's NX-OS 9.3 guides and have not yet been tried on a
  switch.

- **Switch admin.** A new **Switch admin** page (in the menu) shows the
  switch's hostname, its time and where it comes from, and the NTP servers it
  talks to; once switch admin changes are on, also its time zone and summer
  time, DNS domain, lookups and servers, logging settings and servers, SNMP
  contact, location, trap receivers and communities (never shown, only
  whether each is read-only) and login banner. Operators and admins can,
  after a confirm page that shows the lines, change the hostname (NXray
  stores the new name too), set a one-line login banner, the time zone,
  summer time and the time now (`clock set`, which leaves nothing to save),
  add and delete NTP servers (by address or name, in any VRF, preferred or
  not), set the DNS domain, turn lookups on and off, add and delete DNS
  servers (also delete those typed inside a VRF), set the log file's level
  and size, console and terminal logging and timestamps, add and delete
  syslog servers, and set the SNMP contact and location, add and remove
  read-only SNMP communities and SNMP v2c trap receivers. A new **Switch
  log** page shows the newest 50, 200 or 1000 lines of the switch's own log,
  newest first, with a search and a severity filter, for every role.
  NXray's `nxray-ports` role gets rules 135 to 170 (role version 12), which
  also let it read the running configuration; they allow only read-only SNMP
  communities and no SNMP users, so NXray's account cannot give itself
  more. An older role gets a **Turn on switch admin changes** button, with
  no wait. The lines and the shapes of `show clock` and `show ntp
  peer-status` follow Cisco's NX-OS 9.3 documentation and have not yet been
  tried on a switch.

- **Spanning tree.** A new **Spanning tree** page shows the switch's mode,
  every tree (per VLAN, or per MST instance) with its root bridge, root
  port, cost, topology changes and timers, every port in each tree with its
  role, state, cost and priority, the spanning tree settings of every front
  port and port-channel, and the ports that are blocked, inconsistent or in
  a dispute. Operators and admins can, after a confirm
  page that shows the lines and warns when traffic can stop, change the
  mode, the path cost method, Bridge Assurance, the defaults for ports
  (edge, network, BPDU guard and filter, loop guard), PVST simulation and
  the MST timers; each VLAN's priority, root primary or secondary and
  timers, or turn spanning tree off for it; the MST region's name, revision
  and VLAN mapping and each instance's priority; and on a front port or
  port-channel its port type (edge, edge trunk, network, normal), BPDU guard
  and filter, root or loop guard, cost, port priority (also per VLAN or MST
  instance) and link type. NXray's `nxray-ports` role gets rules 129 to 134
  (role version 11), which also let it read the spanning tree lines of the
  running configuration, the only place a down port's settings show; an
  older role gets a **Turn on spanning tree changes** button, with no wait.
  The per-VLAN, MST region and port lines were tried on an N9K-C92160YC-X
  with NX-OS 9.3(16) with a throwaway account on an unused port and VLAN.
  Spanning tree is in the menu, which now wraps between names on a narrower
  window instead of splitting them.

- **Routing protocols.** A new **Routing protocols** page (Protocols in the
  menu) lists every routing protocol the switch has with whether its feature
  is on, and the switch's whole route table per VRF. Each protocol has its
  own page: OSPF, OSPFv3, BGP, EIGRP, RIP, IS-IS, HSRP, VRRP, VRRPv3, PIM,
  PIM6, IGMP, MSDP and BFD, plus **Routing policy** for route-maps, IPv4 and
  IPv6 prefix-lists and key chains. Each page shows the processes,
  neighbors, interfaces or groups the switch reports, and operators and
  admins can, after a confirm page that shows the exact lines sent, make and
  delete processes, VRF parts, address families, neighbors and groups and
  set or remove each of their settings (router ID, areas, redistribution,
  summaries, timers, authentication, BFD, interface costs and more).
  Passwords and keys are never shown back. A protocol whose feature is off
  links to the Features page. NXray's `nxray-ports` role gets rules 63 to
  128 (role version 10); an older role gets a **Turn on routing protocol
  changes** button, with no wait. The rules were tried on an N9K-C92160YC-X
  with NX-OS 9.3(16) with a throwaway account on an unused port.

- **Routing page: static routes.** The Routing page lists the IPv4 and IPv6
  static routes of every VRF, with whether the switch uses each IPv4 one.
  Operators and admins can, after a confirm page, add a static route (a VRF,
  a destination network and a next-hop address; `0.0.0.0/0` or `::/0` for a
  default route) and remove one. The confirm page warns for a default route
  and when no interface in the VRF reaches the next hop. Routes in management
  are shown but never changed, and a VRF that has static routes cannot be
  deleted until they are removed. NXray's `nxray-ports` role gets rules 55
  to 62 (`ip route *`, `ipv6 route *` and their `no` forms, in default and
  inside `vrf context *`; role version 9); an older role gets a **Turn on
  static route changes** button, with no wait. The rules were tried on an
  N9K-C92160YC-X with NX-OS 9.3(16) with a throwaway account.
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
  access and trunk, moves to another VLAN or stops carrying VLANs. A trunk
  always carries its native VLAN: NXray adds it to the VLANs carried when
  the form leaves it out, and the confirm page says so, since NX-OS drops a
  trunk's untagged traffic when its native VLAN is not carried (native VLAN 2
  with only 253-254 carried gave the device on the port no DHCP address). A
  port page flags a trunk already set up that way on the switch (#12). VLAN
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

### Changed

- **A new look for every page.** A menu down the left side, grouped as
  Monitor, Configure, Switch and Admin, with the current page lit; **Narrow
  the menu** shrinks it to icons. A strip across the top names the switch
  shown, its address, model and NX-OS version (stored when the dashboard or
  Test connection reads them), whether the last connection test worked, and
  **Unsaved changes** when NXray changed the switch since the last Save
  config; the switch picker moved into it. Square corners, thin borders,
  denser tables, and port names, addresses and numbers in a fixed-width
  font. The colours follow the computer's light or dark setting, or the
  **Light** or **Dark** button at the foot of the menu; the choice is kept per
  browser. Still no script and no inline style on any page.
- **The Ports page is built around the front panel.** The panel is drawn as
  the switch's metal front across the page, with the model at the left, a
  light on each port that is lit while it has a link, and the name of the
  device plugged in (from CDP or LLDP) above or below each port. The small
  ports are drawn in three blocks of sixteen (1-16, 17-32, 33-48), as on the
  Nexus 92160YC-X; they were drawn in four blocks of twelve. Two new colour
  views: **Speed** (1G, 10G, 25G, 40G, 100G) and **Port-channel**. Above the
  table: the port count, how many are up, down, turned off and with errors,
  and the traffic now; quick filters for turned-off ports, each speed,
  trunks and ports in a port-channel, each with its count. The table adds
  the connected device and small bars showing in and out traffic as a share
  of the link's speed. Clicking a port, on the panel or in the table, opens
  a side panel with its traffic graph, what is connected, its settings and
  transceiver, the description and on/off buttons (operators and admins),
  arrows to the next and previous port, and a link to the port's own page.
  **Change several ports** is now a bar under the table.
- **Pages use the full width of the browser window.** Every page used to sit
  in a centred column at most 1100 px wide, and intro lines wrapped at about
  65 characters, so a PC screen had empty space on both sides and tables
  wrapped. The column now fills the window (with its side padding), and
  intro lines run the width of their card. The sign-in box and form fields
  keep their own widths (#9).
