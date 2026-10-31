# Switch setup

[← back to the README](../README.md)

NXray never uses the switch's admin account for its day-to-day work. On the
**Switch** page it signs in once with the admin login, creates its own
account, and from then on uses only that.

## Before you start

- NX-API must be on. In an SSH session on the switch:

      configure terminal
      feature nxapi
      end
      copy running-config startup-config

  `show nxapi` then says `nxapi enabled` and `HTTPS Listen on port 443`.
- The machine running NXray must reach the switch's management address on
  that port.

## What setup does on the switch

When you press **Create the account and connect**, NXray:

1. Signs in with the admin username and password you typed and reads
   `show version` and `show user-account`.
2. Stops if an account with the name you chose already exists. Each NXray
   install needs its own name (for example `nxray` for production and
   `nxray-dev` for a test machine), because setting one up gives the account
   a new password.
3. Runs `username <name> password <random> role network-operator`. The
   password is 32 random letters and digits that nobody sees.
   `network-operator` is NX-OS's built-in read-only role.
4. Signs in with the new account to check it works. If that, or storing the
   login, fails, it runs `no username <name>` so a retry is not blocked.
   The switch refuses that for an account that signed in during the last
   10 minutes; the page then says the account is still there, and that you
   can remove it with `no username <name>` after 10 minutes or set up again
   with another name.
5. Runs `copy running-config startup-config`, so the account survives a
   restart of the switch. **This also saves any other changes on the switch
   that were not saved yet**, which is why the page asks you to tick a box
   first. If saving fails, NXray still connects and tells you to run the
   command yourself.

The admin password is used only during these steps. NXray does not store
it, log it or show it. The new account's password is stored encrypted in
NXray's database.

## Test connection and Forget this switch

- **Test connection** signs in with NXray's account and reads the switch's
  hostname and version. The dashboard also signs in with that account every
  time it opens, and reads the switch's health.
- **Forget this switch** deletes NXray's stored login only. The account stays
  on the switch. To remove it, in an SSH session on the switch as admin:

      configure terminal
      no username nxray
      end
      copy running-config startup-config

  (with your account name in place of `nxray`).

## Changing the address, and Run setup again

Both are on the **Switch** page once a switch is set up.

**Change the switch address** is for when the switch's management address or
NX-API port changed. Type the new address and port and press **Change
address**. NXray signs in there with its own account (`show version`) and
stores the new address only if that works; otherwise it keeps the old one
and says why. If the switch at the new address has another hostname, the
page says so. No admin login is needed.

**Run setup again** is for when NXray's login stopped working: someone
changed the account's password or removed the account on the switch, or
NXray can no longer read its stored copy because `NXRAY_SECRET_KEY` (or the
data volume's `secret_key` file) changed. Type the admin username and
password, tick the box and press **Run setup again**. NXray then:

1. Signs in with the admin login and reads `show version`, `show
   user-account`, `show role` and `show nxapi`.
2. Runs `username <name> password <random> role network-operator` for
   NXray's own account name. If the account is still there, this only gives
   it a new password: it keeps every role it had, and the switch accepts the
   new password at once. If the account is gone, this makes it again under
   the same name.
3. If port changes were on: when the account no longer has the
   `nxray-ports` role but the switch still has the role, runs `username
   <name> role nxray-ports`. An account that was made again gets it before
   it first signs in, so there is no wait; an account that was still there
   may hold its old permissions in its NX-API session, so NXray waits about
   11 minutes, as after turning port changes on. When the role itself is no
   longer on the switch, port changes are turned off in NXray; turn them on
   again on the same page.
4. Signs in with the new password to check it, stores it encrypted, and
   runs `copy running-config startup-config` (which also saves any other
   unsaved changes on the switch).

The address and NX-API port fields of Run setup again start with the stored
address; change them too if the switch moved. The account keeps its name:
to use another name, press **Forget this switch** and set it up again.
Neither button can be used while NXray is waiting for the switch to apply a
new role, because signing in would make the wait start over.

## Port changes

Port changes are off after setup: NXray's account can only read. To turn
them on, open the **Switch** page, type the admin username and password
under **Port, VLAN, port settings, feature, neighbor, port-channel, VLAN
interface, VRF and static route changes**, tick the box and press **Turn on
port, VLAN, port settings, feature, neighbor, port-channel, VLAN interface,
VRF and static route changes**. One press turns on all nine, with a single
wait.
NXray then:

1. Reads `show interface brief`, `show user-account` and `show nxapi` over
   NX-API with the admin login.
2. Signs in to the switch over **SSH** with the same admin login (password
   only) and types:

       configure terminal
       role name nxray-ports
         rule 1 permit command conf t ; interface * ; shutdown
         rule 2 permit command conf t ; interface * ; no shutdown
         rule 3 permit command conf t ; interface * ; description *
         rule 4 permit command conf t ; interface * ; no description
         rule 5 permit command copy running-config startup-config
         rule 6 permit command conf t ; vlan * ; name *
         rule 7 permit command conf t ; no vlan *
         rule 8 permit command conf t ; interface * ; switchport mode *
         rule 9 permit command conf t ; interface * ; switchport access vlan *
         rule 10 permit command conf t ; interface * ; switchport trunk allowed vlan *
         rule 11 permit command conf t ; interface * ; switchport trunk native vlan *
         rule 12 permit command conf t ; interface * ; speed *
         rule 13 permit command conf t ; interface * ; mtu *
         rule 14 permit command conf t ; interface * ; fec *
         rule 15 permit command conf t ; interface * ; flowcontrol receive *
         rule 16 permit command conf t ; interface * ; flowcontrol send *
         rule 17 permit command conf t ; interface * ; storm-control broadcast level *
         rule 18 permit command conf t ; interface * ; storm-control multicast level *
         rule 19 permit command conf t ; interface * ; storm-control unicast level *
         rule 20 permit command conf t ; interface * ; storm-control action *
         rule 21 permit command conf t ; interface * ; no storm-control action *
         rule 22 permit command conf t ; interface * ; switchport
         rule 23 permit command conf t ; interface * ; no switchport
         rule 24 permit command conf t ; interface * ; ip address *
         rule 25 permit command conf t ; interface * ; no ip address *
         rule 26 permit command conf t ; interface breakout module * port * map *
         rule 27 permit command conf t ; no interface breakout module * port * map *
         rule 28 permit command conf t ; feature *
         rule 29 permit command conf t ; no feature *
         rule 30 permit command conf t ; interface * ; cdp enable
         rule 31 permit command conf t ; interface * ; no cdp enable
         rule 32 permit command conf t ; interface * ; lldp transmit
         rule 33 permit command conf t ; interface * ; no lldp transmit
         rule 34 permit command conf t ; interface * ; lldp receive
         rule 35 permit command conf t ; interface * ; no lldp receive
         rule 36 permit command conf t ; mac address-table aging-time *
         rule 37 permit command conf t ; mac address-table static *
         rule 38 permit command conf t ; no mac address-table static *
         rule 39 permit command clear mac address-table dynamic
         rule 40 permit command clear mac address-table dynamic *
         rule 41 permit command conf t ; interface * ; channel-group *
         rule 42 permit command conf t ; interface * ; no channel-group
         rule 43 permit command conf t ; interface * ; lacp rate *
         rule 44 permit command conf t ; interface * ; lacp port-priority *
         rule 45 permit command conf t ; interface * ; lacp min-links *
         rule 46 permit command conf t ; no interface port-channel *
         rule 47 permit command conf t ; lacp system-priority *
         rule 48 permit command conf t ; interface * ; ipv6 address *
         rule 49 permit command conf t ; interface * ; no ipv6 address *
         rule 50 permit command conf t ; no interface Vlan *
         rule 51 permit command conf t ; vrf context * ; description *
         rule 52 permit command conf t ; no vrf context *
         rule 53 permit command conf t ; interface * ; vrf member *
         rule 54 permit command conf t ; interface * ; no vrf member *
         rule 55 permit command conf t ; ip route *
         rule 56 permit command conf t ; no ip route *
         rule 57 permit command conf t ; ipv6 route *
         rule 58 permit command conf t ; no ipv6 route *
         rule 59 permit command conf t ; vrf context * ; ip route *
         rule 60 permit command conf t ; vrf context * ; no ip route *
         rule 61 permit command conf t ; vrf context * ; ipv6 route *
         rule 62 permit command conf t ; vrf context * ; no ipv6 route *
         interface policy deny
           permit interface Ethernet1/1
           ... (one line per front-panel port)
           permit interface port-channel1-4096
           permit interface Vlan1-254
       username <name> role nxray-ports
       end

   NX-API refuses the `;` in these rules, which is why this one step uses
   SSH. The SSH port is 22 unless you change it on the page.
3. Checks over NX-API that the account now has the role, and runs
   `copy running-config startup-config` (again saving any other unsaved
   changes on the switch).

The role lets NXray's account turn front-panel ports on or off, set or
remove their descriptions, set their mode (access or trunk) and VLANs, and
set their speed, MTU, FEC, flow control, storm control and layer (switched,
or routed with IPv4 and IPv6 addresses), and turn CDP and LLDP sending and
listening on or off on them; split a 100G port into four and join it again;
create, name and delete VLANs; turn switch features on and off; set how
long the switch keeps learned MAC addresses, add and remove static MAC
addresses (on a front port, or dropped) and clear learned ones; put front
ports into port-channels and take them out, with their LACP rate and port
priority; on the port-channels, the same port settings, their LACP minimum
links, and deleting them; set the switch's LACP priority; make, turn on or
off, describe, set the MTU of and delete VLAN interfaces and put IPv4 and
IPv6 addresses on them; make and delete VRFs and move VLAN interfaces and
routed ports between them; add and remove IPv4 and IPv6 static routes; and
save the configuration. The switch
refuses it everything else: mgmt0, shutting a VLAN down or suspending it,
accounts and other switch-wide settings. Every NXray install
on a switch uses the same `nxray-ports` role.

**The wait.** The switch keeps an account's permissions in its NX-API
session and only reloads them once that session has been idle for NX-API's
timeout (10 minutes unless changed). So after turning port changes on,
NXray does not contact the switch for that long plus a minute, about 11
minutes, and every page says so. This happens once: after it, port, VLAN,
port settings, feature, neighbor, port-channel, VLAN interface, VRF and
static route changes take effect straight away. When the role gains the port-channels or the VLAN
interfaces, NXray checks it and
saves the configuration over SSH rather than NX-API: on an N9K-C92160YC-X
with NX-OS 9.3(16), NX-API once stopped answering every account for about 15
minutes right after such a change (SSH kept working), though a later change
went through without it.

**Installs that turned port changes on before VLANs, port settings,
features, neighbor, port-channel, VLAN interface, VRF or static route
changes existed.** Their role has rules 1 to 5, 1 to 11, 1 to 27, 1 to 29,
1 to 40, 1 to 47, 1 to 50 or 1 to 54. The Switch page then shows a card
named for what is missing (for example **VRF and static route changes** or
**Static route changes**): type the admin login,
tick the box and press its **Turn on** button. NXray types the same lines as above (adding the missing
rules) and saves the configuration. There is no wait this time: the switch
applies new rules in a role the account already has at once.

**Update the port list.** The role names each front port it covers. A port
split into four (Ethernet1/50 becomes Ethernet1/50/1 to Ethernet1/50/4), or
four joined back into one, is not in that list yet, and the switch refuses
NXray's changes to it. Once port settings changes are on, the Switch page
has an **Update the port list** card: the admin login and the same lines
again, with the ports the switch has now. No wait.

**Changing a port.** On a port's own page (Ports, then the port's name),
**Change description** and **Turn off this port** / **Turn on this port**
each show what will happen and ask you to confirm. Turning off a port that is
up warns that whatever is plugged in loses its connection. A change takes
effect at once but is not saved: press **Save config** (on the port's page or
the Switch page) to keep it over a restart of the switch. Descriptions are
up to 254 plain characters; NX-API refuses `?` and `;`.

**A port's VLANs.** The same page shows the port's mode and VLANs. **Change
VLANs** sets the mode (access: one untagged VLAN; trunk: several tagged
VLANs plus one native, untagged VLAN), the access or native VLAN (picked
from the VLANs on the switch) and the VLANs a trunk carries (typed as
`10,20-30`, `all` or `none`; this replaces the whole list). Only the
settings of the chosen mode are sent, and only those that change. The
confirm page warns when the port switches between access and trunk (the
device on it may lose its connection for a moment), when an access port
moves to another VLAN, and when a trunk stops carrying VLANs.

**A port's settings.** The **Port settings** card on the same page shows the
port's layer (switched or routed, with its IPv4 address), speed, duplex,
MTU, FEC, flow control and storm control. **Change settings** sends only the
settings that change, after a confirm page:

- **Layer.** Switched (layer 2) carries VLANs; routed (layer 3,
  `no switchport`) has its own IPv4 address, typed with its prefix length
  (`192.0.2.1/24`), and no VLANs; extra IPv4 and IPv6 addresses go on it on
  the **Routing** page. Going back to switched removes the addresses first.
  Both warn that the device on the port loses its connection.
- **Speed.** Auto or a speed the port can run at (`show interface
  capabilities`). NXray's account may not read the running configuration,
  so for a port that is up the page shows the speed it runs at, which may
  come from Auto; leaving the box alone sends nothing.
- **MTU.** A switched port takes 1500 (standard) or 9216 (jumbo frames, the
  switch's `system jumbomtu`); a routed port 576 to 9216.
- **FEC.** Auto, off, FC-FEC, RS-FEC, RS-IEEE or RS-CONS16. The switch
  refuses a mode the port's speed or transceiver cannot use, and the page
  shows its words.
- **Flow control.** Receive and send, each on or off.
- **Storm control** (switched ports). A limit for broadcast, multicast and
  unknown unicast traffic as a percentage of the link (empty: no limit,
  which the switch writes as 100.00), and what happens above it: drop the
  extra traffic only, also send an SNMP trap, or turn the port off.
- **Duplex** is shown only: the switch offers full duplex on every port.

Changing the speed, FEC or layer of a port that is up warns that its link
goes down for a moment.

**Splitting a 100G port.** Ethernet1/50 and Ethernet1/52 can be split into
four ports (4 x 10G or 4 x 25G) for a breakout cable, with
`interface breakout module 1 port 50 map 25g-4x`. The confirm page says
that the port's settings are removed, the four new ports start with the
switch's defaults, and whatever is plugged in loses its connection. The page
of one of the four ports joins them again (`no interface breakout ...`),
with the split preselected when the ports' speeds show it. Either way an
NXray admin then presses **Update the port list** on the Switch page before
NXray can change the new ports.

**VLANs.** The **VLANs** page lists every VLAN with the ports using it, and
creates (number and optional name), renames and deletes VLANs. Names are up
to 32 letters, digits, dots, dashes or underscores, without spaces: the
switch refuses spaces and silently ignores a longer name. VLAN 1 cannot be
renamed or deleted, and the switch keeps 3968 to 4094 for itself. A VLAN
that a port still uses cannot be deleted: an access port in it, a trunk
using it as native VLAN, or a trunk that names it in its list (a trunk
carrying every VLAN does not count). Move those ports first; the page lists
them. Deleting asks you to confirm.

**Features.** The **Features** page lists every feature the switch reports
(`show feature`), grouped (routing, layer 2, management, security and so
on), each with what it does and whether it is on; every NXray role can look.
An NXray admin turns one on or off (`feature lldp`, `no feature lldp`) after
a confirm page; operators and viewers cannot. The page uses the command you
would type, which is not always the switch's internal name (`ssh` for
`sshServer`, `hsrp` for `hsrp_engine`, `nv overlay` for `nve`). NXray will
not:

- turn off NX-API or SSH, which it needs itself;
- turn off a feature it can see in use: LACP while an LACP port-channel
  exists (the page names it and its ports), or VLAN interfaces while one
  exists. Remove that first;
- change a feature that has no `feature` command on this switch (services
  NX-OS runs itself, such as `icam`, or ones this model does not offer).
  These are listed under their internal name; the 32 NX-SDK app slots are
  one line under **Other**.

Turning a feature off deletes all of its settings from the running
configuration, and NXray's account cannot read the running configuration to
list them, so the confirm page says so. Like other changes, a feature
change is not saved until you press **Save config**.

**CDP and LLDP on a port.** The **CDP and LLDP** card on a port's page shows
whether the port speaks CDP (Cisco's own way for devices to say who they
are) and, while LLDP is on for the switch, whether it sends and listens for
LLDP (the standard way most servers and other makers' switches use). Tick or
untick **CDP**, **LLDP: send** and **LLDP: listen** and press **Change CDP and
LLDP**; NXray sends only what changes (`cdp enable` / `no cdp enable`,
`lldp transmit`, `lldp receive` and their `no` forms) after a confirm page,
which warns that a device stops showing as a neighbor once its hold time
runs out. With LLDP off for the whole switch the LLDP boxes are not shown;
an NXray admin turns LLDP on on the **Features** page first.

**The MAC address table.** The **Neighbors** page has, for operators and
admins:

- **Static addresses**: the entries fixed by hand, with **Remove**, and a
  form that adds one: a MAC address in any common form, a VLAN that exists,
  and the front port its traffic always goes to, or **Drop it** to block the
  address (`mac address-table static <mac> vlan <n> interface <port>` or
  `... drop`). Static entries never age out. The confirm page warns when the
  address was learned on another port, because its device loses its
  connection if it is really there. NXray removes only entries on a front
  port or dropped; others (on a port-channel) say so and are removed on the
  switch.
- **Aging time**: how long the switch keeps a learned address without
  traffic, 120 to 918000 seconds in steps of 5 (the switch's default is
  1800), or 0 to keep them until the switch restarts. The switch would
  quietly round other values down, so NXray refuses them.
- **Clear learned addresses**: all of them, those on one port, those in one
  VLAN, or one address (optionally in one VLAN), with `clear mac
  address-table dynamic`. Static entries stay. Devices that are still
  connected are learned again from their next traffic; until then the switch
  sends their traffic out of every port in their VLAN. A port's own page has
  a button for its own addresses. Clearing changes no configuration, so
  there is nothing to save; the other changes wait for **Save config**.

**Port-channels.** The **Port-channels** page lists every port-channel with
its ports, each port's state and how it joined (LACP active, LACP passive,
or static), and while LACP is on each port's LACP rate and port priority,
the device at the other end (its address and maker) and the switch's own
LACP priority. The Ports page and a port's page link a port to its
port-channel. Operators and admins can, each after a confirm page:

- **Make a port-channel** from front ports that are in none: a number from
  1 to 4096, the ports, how they join, optionally the fast LACP rate (a
  message every second instead of every 30) and a description. NXray sends
  `lacp rate fast` (when asked) and `channel-group <n> mode active|passive`,
  or `channel-group <n>` for static, on each port; the switch makes the
  port-channel from the first one. The ports must have the same settings
  (mode, VLANs, speed, MTU, flow control), or the switch refuses them, and a
  port that is up drops its link for a moment. LACP active and passive need
  LACP on (the **Features** page).
- **Add a port** to a port-channel, joining the way its ports did, and
  **Take out** a port (`no channel-group`); the port keeps its own settings.
- **Delete** a port-channel (`no interface port-channel<n>`). NXray refuses
  while it still has ports and names them: take them out first.
- **Change settings**: the description and, for LACP, how many ports must be
  up for the port-channel to stay up (`lacp min-links`, 1 to 32). The switch
  does not show NXray the current minimum, so the box starts empty; empty
  keeps it.
- **LACP settings of one port**: its rate and port priority (1 to 65535,
  lower is used first). The switch changes the rate of a port in a
  port-channel only while that port is off, so NXray says so; turn the port
  off on its page first.
- **Change LACP priority**: the switch's own LACP priority (1 to 65535,
  default 32768), for every port-channel at once; the confirm page warns
  that every LACP port-channel agrees on its ports again with the device at
  the other end, and its traffic can stop for a moment.

The rules for joining, leaving, the rate, the port priority, the minimum and
deleting were tried on an N9K-C92160YC-X with NX-OS 9.3(16) with a throwaway
account on two unused ports; `lacp system-priority` was not, because it
touches every port-channel on the switch.

**VLAN interfaces and addresses.** The **Routing** page (and a link from
each VLAN on the **VLANs** page) lists the VLAN interfaces, which give the
switch its own address in a VLAN so devices there can reach it and use it as
their gateway, and the routed ports, each with its state, VRF and IPv4 and
IPv6 addresses. Every role can look. VLAN interfaces need the interface-vlan
feature, which an admin turns on on the **Features** page; turning it on
makes Vlan1 by itself, turned off. Operators and admins can, each after a
confirm page:

- **Make a VLAN interface** for a VLAN that has none, optionally with an
  IPv4 and an IPv6 address, a description and an MTU, on or off
  (`interface vlan<n>`, then `ip address`, `ipv6 address`, `description`,
  `mtu` and `no shutdown`). Once it is on and has an address, the switch
  routes between it and its other VLAN interfaces and routed ports.
- **Change** a VLAN interface's main IPv4 address, description, MTU (576 to
  9216) and on/off; only what changes is sent.
- **Add an address** to a VLAN interface or a routed port: IPv6, or IPv4,
  which becomes an extra (secondary) address when there is a main one
  already, and **Remove** one. The main IPv4 address comes off only once
  the extra ones are gone. NXray refuses an address in a network another
  interface in the same VRF has, and link-local IPv6 addresses (`fe80::`),
  which the switch makes by itself on every IPv6 interface.
- **Delete** a VLAN interface (`no interface vlan<n>`); its addresses go with
  it and the VLAN stays. Vlan1 is never deleted, and the VLANs page refuses
  to delete a VLAN that has a VLAN interface.

The role names the VLAN interfaces of VLANs 1 to 254 only: the switch
stores that range as one line per VLAN interface, and all 4094 took it
minutes and stopped NX-API answering. A VLAN above 254 gets no VLAN
interface from NXray. The switch takes `permit interface Vlan1-254` into the
role only while interface-vlan is on; with it off it answers "Invalid interface format". So
when changes are turned on with interface-vlan off, NXray leaves that line
out and says so, the Routing page offers no VLAN interface forms, and the
Switch page asks for **Update the port list** once interface-vlan is on.

A port becomes routed on its own page (**Port settings**, Layer). That page
shows its extra IPv4 and IPv6 addresses and takes them off when the port
goes back to switched. These rules were tried on an N9K-C92160YC-X with
NX-OS 9.3(16) with a throwaway account on an unused port and VLAN.

**VRFs.** A VRF is a routing table of its own: the switch routes between the
interfaces in one VRF, never from one VRF to another. The Routing page lists
the VRFs with their state and the interfaces in each. Every interface starts
in `default`, and mgmt0 is in `management`; NXray never changes those two.
Operators and admins can, each after a confirm page:

- **Make a VRF** (`vrf context <name>`): up to 32 letters, digits, `-` or
  `_`.
- **Move** a VLAN interface or routed port into another VRF, or back to
  default (`no vrf member <old>`, `vrf member <new>`). The switch deletes
  every address on the interface when its VRF changes; the confirm page lists
  them, and they are added again afterwards with **Add an address**.
- Make a new VLAN interface straight into a VRF (the **VRF** box of **Make a
  VLAN interface**).
- **Delete** a VRF (`no vrf context <name>`). NXray refuses while interfaces
  are in it and names them: the switch itself would take them out and delete
  their addresses.

An install whose role predates VRFs gets a **Turn on VRF changes** card on the
Switch page; it adds rules 51 to 54 with no wait. These commands were tried
on an N9K-C92160YC-X with NX-OS 9.3(16) with a throwaway account on an unused
port.

**Static routes.** A static route sends the traffic for a network to a
router (the next hop) that the switch reaches through one of its interfaces
in the same VRF. The Routing page lists the IPv4 and IPv6 static routes of
every VRF, with whether the switch uses each IPv4 one (it keeps a route but
does not use it while no interface in the VRF reaches the next hop).
Operators and admins can, each after a confirm page:

- **Add a static route**: a VRF, a destination network with its prefix length
  (`0.0.0.0/0` or `::/0` for a default route) and a next-hop address of the
  same family (`ip route <network> <next hop>` or `ipv6 route ...`, inside
  `vrf context <name>` for a VRF other than default). The confirm page warns
  for a default route and when no interface in the VRF reaches the next hop.
  Link-local IPv6 next hops are refused, as they would also need an
  interface.
- **Remove** a static route (the same command with `no`).

Routes in management (such as mgmt0's default route) are shown but never
changed. A VRF that has static routes cannot be deleted until they are
removed. An install whose role predates static routes gets a **Turn on
static route changes** card on the Switch page; it adds rules 55 to 62 with
no wait. These commands were tried on an N9K-C92160YC-X with NX-OS 9.3(16)
with a throwaway account.

**Taking port changes away.** In an SSH session on the switch as admin:

    configure terminal
    no username nxray role nxray-ports
    end
    copy running-config startup-config

(with your account name in place of `nxray`). Remove the role itself with
`no role name nxray-ports` only when no NXray install on the switch uses it.

## When it stops working

| The page says | What it means |
| --- | --- |
| could not reach the switch | Wrong address or port, a firewall, or NX-API is off. If the switch moved, use **Change the switch address** |
| the switch refused the admin username or password | The admin login typed during setup is wrong |
| the switch refused the NXray account | NXray's account was removed, or its password changed, on the switch. Press **Run setup again** on the Switch page |
| NXray cannot read the stored switch login | `NXRAY_SECRET_KEY` (or the data volume's `secret_key` file) changed. Press **Run setup again** on the Switch page |
| NXray is leaving the switch alone for about N more minutes | Port changes were just turned on; the switch is applying the new role. Wait, then reload |
| could not reach the switch over SSH | Turning on port changes needs SSH from the NXray machine to the switch; check SSH is on and the port |
| may not make this change yet | The switch has not applied the port-changes role, or it was removed. Leave NXray's pages closed for 10 minutes and try again, or turn port changes on again |
| NXray kept the address | Change the switch address could not sign in at the new address with NXray's account; the message after it says why |
| Port changes are now off: the nxray-ports role is no longer on the switch | Run setup again found the role gone. Press **Turn on port, VLAN, port settings, feature, neighbor and port-channel changes** to make it again |
| VLAN changes are off | Port changes were turned on before NXray could change VLANs. Press **Turn on VLAN, port settings, feature, neighbor and port-channel changes** on the Switch page |
| Port settings changes are off | Port changes were turned on before NXray could change port settings. Press **Turn on port settings, feature, neighbor and port-channel changes** on the Switch page |
| Feature changes are off | Port changes were turned on before NXray could turn features on and off. Press **Turn on feature, neighbor and port-channel changes** on the Switch page |
| Neighbor changes are off | Port changes were turned on before NXray could change CDP, LLDP and the MAC address table. Press **Turn on neighbor and port-channel changes** on the Switch page |
| Port-channel changes are off | Port changes were turned on before NXray could change port-channels. Press **Turn on port-channel changes** on the Switch page |
| changes the LACP rate of a port in a port-channel only while the port is off | Turn the port off on its page, change the rate, turn it on again |
| still has ...; take them out first | NXray deletes only an empty port-channel. Take its ports out first |
| Not turned off: ... still uses ... | The feature is in use (an LACP port-channel, a VLAN interface). Remove that first |
| NXray's role on the switch does not name this port | The port came from a split or a join. Press **Update the port list** on the Switch page |

## The certificate and the SSH host key

The switch's NX-API uses a self-signed certificate. NXray accepts it without
checking, and does the same with the switch's SSH host key when turning on
port changes; see [SECURITY.md](../SECURITY.md).
