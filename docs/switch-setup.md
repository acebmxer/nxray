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
6. With **Also turn on changes** ticked (it is, unless you untick it), turns
   on every kind of change straight away, with the same admin login and the
   **SSH port** on the form: exactly the steps under
   [Port changes](#port-changes) below, including the wait of about 11
   minutes. If this step fails (SSH off or unreachable, a refused line), the
   switch stays set up with a read-only account, the page says why, and the
   **Turn on** button on the Switch page tries again. Untick the box to keep
   the account read-only.

The admin password is used only during these steps. NXray does not store
it, log it or show it. The new account's password is stored encrypted in
NXray's database.

## What NXray users get on the switch

Nothing, unless an admin asks for it. An account on NXray's Users page exists
only in NXray: everything it changes reaches the switch through NXray's own
account, and it cannot sign in over SSH. An admin can also give a person a
local account on the switch with the same name and password (see
[Switch accounts](installation.md#switch-accounts-the-same-person-on-the-switchs-command-line)).
NXray then signs in with the switch admin login typed on that form, used for
that one request and never stored, and runs only these, built from checked
values:

- `username <name> password <password> role <role>`, then `username <name>
  role <role>` for a second role, to make an account (after `show
  user-account`, so an existing account is never overwritten);
- `username <name> password <password>` for a new password, or a random one
  nobody knows to lock the account;
- `username <name> role <role>` and `no username <name> role <role>` to bring
  its role in step, for the roles `network-operator`, `network-admin` and
  `nxray-ports` only;
- `no username <name>` to remove it;
- then `copy running-config startup-config`, so a restart keeps the change.

NXray's own account and the names NX-OS keeps for itself (`admin` among
them) are never changed this way. NXray's own role (`nxray-ports`) gains no
rule for any of this.

## Test connection and Forget this switch

- **Test connection** signs in with NXray's account and reads the switch's
  hostname and version. The dashboard also signs in with that account every
  time it opens, and reads the switch's health.
- **Forget this switch** deletes NXray's stored login, and what NXray kept
  about that switch: its history, port labels, config backups and open
  alerts. The activity log and the alert log keep their lines, and NXray's
  other switches stay as they are. The account stays on the switch. To
  remove it, in an SSH session on the switch as admin:

      configure terminal
      no username nxray
      end
      copy running-config startup-config

  (with your account name in place of `nxray`).

## Several switches

One NXray can look after several switches. Once one is set up, the
**Switch** page has **Add another switch**: the same form as the first setup,
for the next switch's address and admin login. Each switch gets its own
account made the same way (the name can be the same on every switch), its
own port changes, its own history, port labels, config backups and open
alerts. NXray refuses a second switch at an address and NX-API port it
already has.

Once there are two or more, the top bar has a switch picker. Every page
(the dashboard, ports, VLANs, routing, history, the Switch and Config pages,
and the rest) shows the switch picked there, and every change goes to that
switch only. The choice is kept per browser in a cookie, for a year. Any
account may pick a switch, whatever its role. When a page was left open for
one switch and another switch was picked since, in another tab, its forms are
refused like an expired form: reload the page, which then shows the switch
picked, and try again. This way a change can never land on a switch other
than the one the page showed.

History reads every switch each minute, one after the other, and alerts name
the switch they are about. The alert rules, the e-mail settings and the
webhooks are the same for every switch.

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
to use another name, press **Forget this switch** and set it up again (which
also deletes the history, port labels and config backups NXray kept for it).
Neither button can be used while NXray is waiting for the switch to apply a
new role, because signing in would make the wait start over.

## Port changes

Setup turns changes on unless **Also turn on changes** was unticked. With it
unticked, or if that step failed, NXray's account can only read. To turn
them on later, open the **Switch** page, type the admin username and password
under **Port, VLAN, port settings, feature, neighbor, port-channel, VLAN
interface, VRF, static route, routing protocol, spanning tree, switch admin,
security and config, layer 2 security, traffic measuring and reset to defaults changes**, tick the box and press
**Turn on port, VLAN, port settings, feature, neighbor, port-channel, VLAN
interface, VRF, static route, routing protocol, spanning tree, switch admin,
security and config, layer 2 security, traffic measuring and reset to defaults changes**. One press turns on all
sixteen, with a single wait.
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
         rule 63 permit command conf t ; router ospf *
         rule 64 permit command conf t ; no router ospf *
         rule 65 permit command conf t ; router ospfv3 *
         rule 66 permit command conf t ; no router ospfv3 *
         rule 67 permit command conf t ; router bgp *
         rule 68 permit command conf t ; no router bgp *
         rule 69 permit command conf t ; router eigrp *
         rule 70 permit command conf t ; no router eigrp *
         rule 71 permit command conf t ; router rip *
         rule 72 permit command conf t ; no router rip *
         rule 73 permit command conf t ; router isis *
         rule 74 permit command conf t ; no router isis *
         rule 75 permit command conf t ; route-map *
         rule 76 permit command conf t ; no route-map *
         rule 77 permit command conf t ; ip prefix-list *
         rule 78 permit command conf t ; no ip prefix-list *
         rule 79 permit command conf t ; ipv6 prefix-list *
         rule 80 permit command conf t ; no ipv6 prefix-list *
         rule 81 permit command conf t ; key chain *
         rule 82 permit command conf t ; no key chain *
         rule 83 permit command conf t ; ip pim *
         rule 84 permit command conf t ; no ip pim *
         rule 85 permit command conf t ; ipv6 pim *
         rule 86 permit command conf t ; no ipv6 pim *
         rule 87 permit command conf t ; ip msdp *
         rule 88 permit command conf t ; no ip msdp *
         rule 89 permit command conf t ; bfd *
         rule 90 permit command conf t ; no bfd *
         rule 91 permit command conf t ; interface * ; ip router *
         rule 92 permit command conf t ; interface * ; no ip router *
         rule 93 permit command conf t ; interface * ; ipv6 router *
         rule 94 permit command conf t ; interface * ; no ipv6 router *
         rule 95 permit command conf t ; interface * ; ip ospf *
         rule 96 permit command conf t ; interface * ; no ip ospf *
         rule 97 permit command conf t ; interface * ; ospfv3 *
         rule 98 permit command conf t ; interface * ; no ospfv3 *
         rule 99 permit command conf t ; interface * ; ipv6 * eigrp *
         rule 100 permit command conf t ; interface * ; no ipv6 * eigrp *
         rule 101 permit command conf t ; interface * ; ip * eigrp *
         rule 102 permit command conf t ; interface * ; no ip * eigrp *
         rule 103 permit command conf t ; interface * ; ip rip *
         rule 104 permit command conf t ; interface * ; no ip rip *
         rule 105 permit command conf t ; vrf context * ; ip pim *
         rule 106 permit command conf t ; vrf context * ; no ip pim *
         rule 107 permit command conf t ; vrf context * ; ipv6 pim *
         rule 108 permit command conf t ; vrf context * ; no ipv6 pim *
         rule 109 permit command conf t ; vrf context * ; ip msdp *
         rule 110 permit command conf t ; vrf context * ; no ip msdp *
         rule 111 permit command conf t ; interface * ; ipv6 rip *
         rule 112 permit command conf t ; interface * ; no ipv6 rip *
         rule 113 permit command conf t ; interface * ; isis *
         rule 114 permit command conf t ; interface * ; no isis *
         rule 115 permit command conf t ; interface * ; hsrp *
         rule 116 permit command conf t ; interface * ; no hsrp *
         rule 117 permit command conf t ; interface * ; vrrp *
         rule 118 permit command conf t ; interface * ; no vrrp *
         rule 119 permit command conf t ; interface * ; vrrpv3 *
         rule 120 permit command conf t ; interface * ; no vrrpv3 *
         rule 121 permit command conf t ; interface * ; ip pim *
         rule 122 permit command conf t ; interface * ; no ip pim *
         rule 123 permit command conf t ; interface * ; ipv6 pim *
         rule 124 permit command conf t ; interface * ; no ipv6 pim *
         rule 125 permit command conf t ; interface * ; ip igmp *
         rule 126 permit command conf t ; interface * ; no ip igmp *
         rule 127 permit command conf t ; interface * ; bfd *
         rule 128 permit command conf t ; interface * ; no bfd *
         rule 129 permit command conf t ; spanning-tree *
         rule 130 permit command conf t ; no spanning-tree *
         rule 131 permit command conf t ; interface * ; spanning-tree *
         rule 132 permit command conf t ; interface * ; no spanning-tree *
         rule 133 permit command show running-config spanning-tree
         rule 134 permit command show running-config spanning-tree *
         rule 135 permit command conf t ; hostname *
         rule 136 permit command conf t ; banner motd *
         rule 137 permit command conf t ; no banner motd
         rule 138 permit command conf t ; clock timezone *
         rule 139 permit command conf t ; no clock timezone
         rule 140 permit command conf t ; clock summer-time *
         rule 141 permit command conf t ; no clock summer-time
         rule 142 permit command clock set *
         rule 143 permit command conf t ; ntp server *
         rule 144 permit command conf t ; no ntp server *
         rule 145 permit command conf t ; ip domain-name *
         rule 146 permit command conf t ; no ip domain-name *
         rule 147 permit command conf t ; ip domain-lookup
         rule 148 permit command conf t ; no ip domain-lookup
         rule 149 permit command conf t ; ip name-server *
         rule 150 permit command conf t ; no ip name-server *
         rule 151 permit command conf t ; vrf context * ; no ip name-server *
         rule 152 permit command conf t ; logging server *
         rule 153 permit command conf t ; no logging server *
         rule 154 permit command conf t ; logging logfile messages *
         rule 155 permit command conf t ; logging console *
         rule 156 permit command conf t ; no logging console
         rule 157 permit command conf t ; logging monitor *
         rule 158 permit command conf t ; no logging monitor
         rule 159 permit command conf t ; logging timestamp *
         rule 160 permit command conf t ; snmp-server contact *
         rule 161 permit command conf t ; no snmp-server contact
         rule 162 permit command conf t ; snmp-server location *
         rule 163 permit command conf t ; no snmp-server location
         rule 164 permit command conf t ; snmp-server community * group network-operator
         rule 165 permit command conf t ; no snmp-server community *
         rule 166 permit command conf t ; snmp-server host * traps version 2c *
         rule 167 permit command conf t ; no snmp-server host * traps version 2c *
         rule 168 permit command conf t ; snmp-server host * use-vrf *
         rule 169 permit command conf t ; no snmp-server host * use-vrf *
         rule 170 permit command show running-config
         rule 171 permit command conf t ; ip access-list *
         rule 172 permit command conf t ; no ip access-list *
         rule 173 permit command conf t ; ipv6 access-list *
         rule 174 permit command conf t ; no ipv6 access-list *
         rule 175 permit command conf t ; interface * ; ip access-group *
         rule 176 permit command conf t ; interface * ; no ip access-group *
         rule 177 permit command conf t ; interface * ; ip port access-group *
         rule 178 permit command conf t ; interface * ; no ip port access-group *
         rule 179 permit command conf t ; interface * ; ipv6 traffic-filter *
         rule 180 permit command conf t ; interface * ; no ipv6 traffic-filter *
         rule 181 permit command conf t ; interface * ; ipv6 port traffic-filter *
         rule 182 permit command conf t ; interface * ; no ipv6 port traffic-filter *
         rule 183 permit command conf t ; interface * ; switchport port-security
         rule 184 permit command conf t ; interface * ; switchport port-security *
         rule 185 permit command conf t ; interface * ; no switchport port-security
         rule 186 permit command conf t ; interface * ; no switchport port-security *
         rule 187 permit command show startup-config
         rule 188 permit command checkpoint *
         rule 189 permit command no checkpoint *
         rule 190 permit command show checkpoint *
         rule 191 permit command conf t ; ip dhcp snooping
         rule 192 permit command conf t ; ip dhcp snooping *
         rule 193 permit command conf t ; no ip dhcp snooping
         rule 194 permit command conf t ; no ip dhcp snooping *
         rule 195 permit command conf t ; ip dhcp relay
         rule 196 permit command conf t ; ip dhcp relay *
         rule 197 permit command conf t ; no ip dhcp relay
         rule 198 permit command conf t ; no ip dhcp relay *
         rule 199 permit command conf t ; ipv6 dhcp relay
         rule 200 permit command conf t ; no ipv6 dhcp relay
         rule 201 permit command conf t ; interface * ; ip dhcp snooping *
         rule 202 permit command conf t ; interface * ; no ip dhcp snooping *
         rule 203 permit command conf t ; interface * ; ip dhcp relay address *
         rule 204 permit command conf t ; interface * ; no ip dhcp relay address *
         rule 205 permit command conf t ; interface * ; ipv6 dhcp relay address *
         rule 206 permit command conf t ; interface * ; no ipv6 dhcp relay address *
         rule 207 permit command conf t ; ip arp inspection *
         rule 208 permit command conf t ; no ip arp inspection *
         rule 209 permit command conf t ; interface * ; ip arp inspection trust
         rule 210 permit command conf t ; interface * ; no ip arp inspection trust
         rule 211 permit command conf t ; arp access-list *
         rule 212 permit command conf t ; no arp access-list *
         rule 213 permit command conf t ; ip source binding *
         rule 214 permit command conf t ; no ip source binding *
         rule 215 permit command conf t ; interface * ; ip verify source *
         rule 216 permit command conf t ; interface * ; no ip verify source *
         rule 217 permit command conf t ; mac access-list *
         rule 218 permit command conf t ; no mac access-list *
         rule 219 permit command conf t ; interface * ; mac port access-group *
         rule 220 permit command conf t ; interface * ; no mac port access-group *
         rule 221 permit command conf t ; object-group *
         rule 222 permit command conf t ; no object-group *
         rule 223 permit command conf t ; vlan access-map *
         rule 224 permit command conf t ; no vlan access-map *
         rule 225 permit command conf t ; vlan filter *
         rule 226 permit command conf t ; no vlan filter *
         rule 227 permit command conf t ; hardware access-list tcam region *
         rule 228 permit command conf t ; interface * ; load-interval *
         rule 229 permit command conf t ; interface * ; no load-interval *
         rule 230 permit command conf t ; sflow *
         rule 231 permit command conf t ; no sflow *
         rule 232 permit command conf t ; default interface *
         rule 233 permit command show sflow
         rule 234 permit command terminal dont-ask
         rule 235 permit command reload
         rule 236 permit command conf t ; vpc domain *
         rule 237 permit command conf t ; no vpc domain *
         rule 238 permit command conf t ; interface * ; vpc *
         rule 239 permit command conf t ; interface * ; no vpc *
         rule 240 permit command show running-config vpc
         rule 241 permit command show running-config vpc *
         rule 242 permit command conf t ; nv overlay evpn
         rule 243 permit command conf t ; no nv overlay evpn
         rule 244 permit command conf t ; fabric forwarding *
         rule 245 permit command conf t ; no fabric forwarding *
         rule 246 permit command conf t ; vlan * ; vn-segment *
         rule 247 permit command conf t ; vlan * ; no vn-segment *
         rule 248 permit command conf t ; interface nve*
         rule 249 permit command conf t ; no interface nve*
         rule 250 permit command conf t ; evpn*
         rule 251 permit command conf t ; vrf context * ; vni *
         rule 252 permit command conf t ; vrf context * ; no vni *
         rule 253 permit command conf t ; vrf context * ; address-family * ; route-target *
         rule 254 permit command conf t ; vrf context * ; address-family * ; no route-target *
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
routed ports between them; add and remove IPv4 and IPv6 static routes; run
the routing protocols and change their settings, on those interfaces too,
and the route-maps, prefix-lists and key chains they use; change spanning
tree for the whole switch, each VLAN, the MST region and the front ports and
port-channels, and read the spanning tree lines of the running configuration;
change the switch's hostname, login banner, time zone, summer time and clock,
NTP servers, DNS domain, lookups and servers, logging (servers, log file,
console, terminal, timestamps), SNMP contact and location, read-only SNMP
communities and trap receivers, and read the running configuration; make,
change and delete IPv4 and IPv6 ACLs and apply them to those interfaces and
ports; set port security on the front ports; read the saved configuration and
make, list and delete checkpoints; set DHCP snooping, the DHCP relay, ARP
inspection and IP Source Guard, MAC ACLs, object groups, VLAN access maps and
the TCAM regions' sizes; set how long the front ports average their In and Out
rates over, and set up sFlow (where the samples go, how often, from which front
ports); put a front port or a port-channel back to how it came out of the box
(`default interface`); and save the configuration. The switch
refuses it everything else: mgmt0, shutting a VLAN down or suspending it,
accounts, SNMP users and read-write SNMP communities, rolling the switch back
(the Config page asks for the admin login each time for that), and other
switch-wide settings. Every NXray install
on a switch uses the same `nxray-ports` role.

**The wait.** The switch keeps an account's permissions in its NX-API
session and only reloads them once that session has been idle for NX-API's
timeout (10 minutes unless changed). So after turning port changes on,
NXray does not contact the switch for that long plus a minute, about 11
minutes, and every page says so. This happens once: after it, port, VLAN,
port settings, feature, neighbor, port-channel, VLAN interface, VRF, static
route, routing protocol, spanning tree, switch admin, security and config, layer 2 security, traffic measuring and reset to defaults changes take effect straight away. When the role gains the port-channels or the VLAN
interfaces, NXray checks it and
saves the configuration over SSH rather than NX-API: on an N9K-C92160YC-X
with NX-OS 9.3(16), NX-API once stopped answering every account for about 15
minutes right after such a change (SSH kept working), though a later change
went through without it.

**Installs that turned port changes on before VLANs, port settings,
features, neighbor, port-channel, VLAN interface, VRF, static route,
routing protocol, spanning tree, switch admin, security and config, layer 2
security, traffic measuring, reset to defaults or sFlow status changes existed.** Their role has rules 1 to 5, 1 to 11, 1 to 27, 1 to 29, 1 to 40, 1
to 47, 1 to 50, 1 to 54, 1 to 62, 1 to 128, 1 to 134, 1 to 170, 1 to 190, 1 to
227, 1 to 231 or 1 to 232. The Switch
page then shows a card named for what is missing (for example **Switch admin
and security and config changes** or **Security and config changes**): type the
admin login,
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

**Changing several ports at once.** With port changes on, the Ports page has
a tick box on each row for operators and admins (**Tick every port shown**
ticks the ports the filter shows, so Down then Tick every port shown picks
every port without a link). The ticked ports do not need to be next to each
other: `Ethernet1/3`, `Ethernet1/7`, `Ethernet1/12` and `Ethernet1/40` work
as well as a row of four. The **Change several ports** card under the table
is one configuration that every ticked port gets:

- **On or off and description**: turn them on or off; tick **Change the
  description to** to give them one description (left empty, it removes
  theirs); **Clear the addresses learned on them** (with neighbor changes on).
- **VLANs** (with VLAN changes on): access or trunk, the access VLAN, the
  native VLAN and the VLANs a trunk carries. The native VLAN is always added
  to the VLANs carried, as on a port's own page.
- **Port settings** (with port settings changes on): switched or routed,
  speed, MTU, FEC, flow control (receive and send), the storm-control levels
  (broadcast, multicast, unknown unicast; `none` for no limit) and the
  storm-control action.
- **CDP and LLDP** (with neighbor changes on): CDP, LLDP sending, LLDP
  listening. LLDP needs the lldp feature on for the whole switch.

Every setting starts at **Leave as it is**, and only what you fill in is
sent: changing the MTU of six ports leaves their VLANs alone. A setting that
only applies to one mode is left alone on the other (a native VLAN on an
access port, storm control on a routed port), and the confirm page says so.
Not offered for several ports, because each port needs its own: an IPv4
address on a routed port (a port made routed here has none; set it on the
port's page), the label, and splitting a 100G port, which the switch allows
only on some ports.

Every value is checked for each ticked port exactly as on that port's own
page (the speeds the port can run at, the MTU for its layer, VLANs that
exist), and if any ticked port cannot take the configuration, nothing is
sent and the page names each such port and why. The confirm page lists
every port that changes with each setting's old and new value, and leaves
out the ports already set as asked. It warns about anything that cuts
traffic: turning off a port that is up, moving a port to another VLAN,
switching between access and trunk, changing the layer, a speed or FEC
change on an up port, a smaller MTU, and the storm-control shutdown action;
each warning names the ports it is about.

NXray then changes the ports one at a time, in front-panel order, each kind
of change (settings, VLANs, CDP and LLDP, description and on/off, clearing
addresses) in its own request, with the same commands as a port's own page,
so the role NXray's account was given already allows them all. If the switch
refuses one, NXray stops there, and the page names the ports that changed,
what was already made on the port it stopped at, what was refused and why,
and the ports not tried; the ticks and the form are kept to try again. The
Ports page has a **Save config** button too.

**Start from port** fills the form with one port's VLANs, settings and CDP
and LLDP, to copy a known-good port onto others. It changes nothing on the
switch; you check the form, tick the ports and press **Change the ticked
ports**. It never copies on or off, the description or an address, nor the
speed of a port that is up (the switch then reports the speed it runs at,
which may come from auto).

**A port's VLANs.** The same page shows the port's mode and VLANs. **Change
VLANs** sets the mode (access: one untagged VLAN; trunk: several tagged
VLANs plus one native, untagged VLAN), the access or native VLAN (picked
from the VLANs on the switch) and the VLANs a trunk carries (typed as
`10,20-30`, `all` or `none`; this replaces the whole list). NXray always
adds the native VLAN to that list, and the confirm page says so when it
does: NX-OS forwards untagged traffic only in a native VLAN the trunk
carries, so with native VLAN 2 and `253-254` the device on the port would
get nothing, not even DHCP. The port page flags a trunk set up that way on
the switch. Only the settings of the chosen mode are sent, and only those
that change. The
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

**Routing protocols.** The **Routing protocols** page (Protocols in the menu)
lists every routing protocol the switch has, whether its feature is on, and
the switch's whole route table per VRF (connected networks, static routes and
what each protocol learned). Each protocol has its own page: OSPF, OSPFv3,
BGP, EIGRP, RIP, IS-IS, HSRP, VRRP, VRRPv3, PIM, PIM6, IGMP, MSDP and BFD,
plus **Routing policy** for the route-maps, IPv4 and IPv6 prefix-lists and
key chains the protocols point at (redistribution needs a route-map on
NX-OS; authentication uses key chains). A protocol whose feature is off says
so and links to the Features page, where an admin turns it on. Each page
shows what the switch reports (processes, neighbors, interfaces, groups) and,
for operators and admins, a form for every setting: making and deleting a
process, VRF part, address family, neighbor or group, and setting or removing
each of its lines. The confirm page shows the exact lines the switch gets;
passwords and keys are shown as `***` and never read back. Interfaces are the
VLAN interfaces (up to Vlan254), routed ports and routed port-channels, never
mgmt0; VRFs never include management. An install whose role predates this
gets a **Turn on routing protocol changes** card on the Switch page; it adds
rules 63 to 128 with no wait. The rules were tried on an N9K-C92160YC-X with
NX-OS 9.3(16) with a throwaway account on an unused port: a rule naming a
protocol's mode (`router ospf *`) covers every line inside it. Rules 99, 100
and 105 to 110 (IPv6 EIGRP lines, and PIM and MSDP inside a VRF) are the same
shapes as tried ones but were not tried on their own.

**Spanning tree.** The **Spanning tree** page shows the switch's mode, which
VLANs it is the root bridge for, every tree (one per VLAN in rapid-pvst mode,
one per instance in mst mode) with its root bridge, root port, cost,
topology changes and timers, every port in each tree with its role, state,
cost and priority, the spanning tree settings of every front port and
port-channel that carries VLANs, and any port that is blocked, inconsistent
or in a dispute. A port's settings are changed under **Port**: **Change any
port** at the top of that card offers every port, including ones that are
down. Operators and admins can, each after a confirm page that shows the
lines and warns when traffic can stop:

- **For the whole switch**: the mode (`spanning-tree mode rapid-pvst|mst`),
  the path cost method (short or long), Bridge Assurance, the defaults for
  ports (edge ports, network ports, BPDU guard and BPDU filter on edge ports,
  loop guard), PVST simulation and the MST timers and hop count.
- **For one VLAN**: its bridge priority (0 to 61440 in steps of 4096), making
  the switch the primary or secondary root (the switch stores the priority it
  picks), hello time, forward delay and maximum age, and turning spanning
  tree off or on for it.
- **The MST region**: name, revision and which VLANs map to which instance;
  and each MST instance's priority or root. They are used in mst mode only.
- **For one front port or port-channel** (not a routed port, never mgmt0):
  port type (edge, edge trunk, network or normal), BPDU guard, BPDU filter,
  root or loop guard, cost and port priority (for all VLANs, some VLANs, or an
  MST instance) and link type.

Each setting can also be removed, which goes back to the switch's default.
The settings of a port that is down only show in the running configuration,
which NX-API gives only as text: NXray reads `show running-config
spanning-tree` once its role allows it. An install whose role predates this
gets a **Turn on spanning tree changes** card on the Switch page; it adds
rules 129 to 134 with no wait. The per-VLAN, MST region and port lines were
tried on an N9K-C92160YC-X with NX-OS 9.3(16) with a throwaway account on an
unused port and VLAN; the switch-wide lines (mode, path cost method, the
defaults, Bridge Assurance) use the same rule but were not typed there, since
each changes every VLAN or port of the switch.

**Switch admin.** The **Switch admin** page (in the menu) shows the switch's
hostname, the time and where it comes from, and the NTP servers it is talking
to, for every role. Once switch admin changes are on, NXray also reads `show
running-config` (as text: NX-API gives it no other way) and shows the time
zone and summer time, the DNS domain, whether lookups are on and the DNS
servers (also those typed inside a VRF, such as `vrf context management`),
the log file, console and terminal logging levels and timestamps, the logging
servers, the SNMP contact, location and trap receivers, how many SNMP
communities there are and whether each is read-only (the communities
themselves are never shown) and the login banner. Operators and admins can,
each after a confirm page that shows the lines:

- **Name and banner**: the hostname (NXray stores the new name too) and a
  one-line login banner (`banner motd #...#`, so the text may not contain
  `#`), or put back the switch's own banner.
- **Clock**: the time zone (`clock timezone`), summer time (`clock
  summer-time`) and setting the time now (`clock set`, which changes no
  configuration; NTP moves it back when servers are set).
- **NTP servers**: add one (an address or a name, preferred or not, in the
  default VRF, management or another) and delete one.
- **DNS**: the domain name, lookups on or off, and the name servers.
- **Logging**: the log file's level and size, console and terminal logging,
  timestamps, and the syslog servers with their level and VRF.
- **SNMP**: contact, location, read-only communities (typed like a password,
  and typed again to remove one) and SNMP v2c trap receivers with their VRF.

NXray never makes SNMP users or read-write communities, and its role does not
allow them: each would be a way in to the whole switch. The **Switch log**
page, linked from Switch admin, shows the newest 50, 200 or 1000 lines of the
switch's own log (`show logging last <n>`), newest first, with a search and a
severity filter; every role may look, and it needs no rule. An install whose
role predates this gets a **Turn on switch admin changes** card on the Switch
page; it adds rules 135 to 170 with no wait. These rules and lines follow
Cisco's NX-OS 9.3 configuration guides and have not yet been tried on a
switch.

**ACLs.** The **Security** menu opens the **ACLs** page: every IPv4 and IPv6
ACL with its numbered entries, where each applies, and a table of them all,
read from the running configuration. Operators and admins can, each after a
confirm page that shows the lines, make and delete an ACL, add an entry
(number, permit or deny, protocol, source and destination as `any`, a network
or one address, TCP, UDP or SCTP ports as `22`, `1024-65535`, `>1023`, `<1024`
or `!=23`, and logging) or a remark, remove one by its number (the switch
refuses a number in use, so changing an entry is removing it and adding it
again), count matches per entry, and apply an ACL: in or out on a VLAN
interface, routed port or routed port-channel (`ip access-group`, `ipv6
traffic-filter`), or in on a switched front port or port-channel (`ip port
access-group`, `ipv6 port traffic-filter`). Every ACL ends with an unwritten
"deny everything else", so applying one can cut off the session you are
using; the confirm page says so.

With layer 2 security changes on (role version 14) the ACLs page also has
**MAC ACLs** (entries matching a source and destination MAC address, `any`, one
address or an address and mask, and optionally an EtherType such as `0x0806`,
a CoS and a VLAN; applied in on a switched port with `mac port access-group`,
where they check the packets that are not IP); **object groups** of IPv4 or
IPv6 networks and of ports, which an entry names as `addrgroup <name>` in place
of a source or destination and `portgroup <name>` in place of a port; **VLAN
access maps** (numbered entries that match an IPv4, IPv6 or MAC ACL and then
forward or drop) and the **VLAN filters** that apply a map to VLANs, so every
packet in them, switched or routed, goes through it; and the **TCAM regions**
(`show hardware access-list tcam region`, with the size each was set to). On a
Nexus 9000 a port ACL needs space in the `ing-ifacl` region and a VLAN ACL in
`vacl`, both 0 by default, and DHCP snooping, ARP inspection and IP Source
Guard need space too; the space must come from another region, and a new size
counts only after Save config and a restart (Config page). The table says
which regions wait for a restart.

**Port security.** The **Port security** page, linked from ACLs, needs the
port-security feature (turn it on on the Features page). For each switched
front port it shows and sets whether port security is on, the most addresses
the port accepts (default 1), what happens on a violation (shut the port
down, the default; restrict; or protect), whether learned addresses are kept
in the configuration (sticky), known addresses (with a VLAN on trunk ports),
and when learned addresses are forgotten.

**DHCP and ARP.** The **DHCP and ARP** page, linked from ACLs, needs the dhcp
feature (turn it on on the Features page) and layer 2 security changes (role
version 14). It shows, read from the running configuration, and sets after a
confirm page: **DHCP snooping** on or off, its VLANs, option 82 and whether a
request's client MAC address must match the frame (on by default); per
switched port or port-channel, whether it is trusted (the port toward the DHCP
server, or an uplink) and its DHCP rate limit (a port over it is turned off);
the **DHCP relay** (on by default with the feature), option 82 and relaying
across VRFs, and the DHCP and DHCPv6 servers of each VLAN interface or routed
port, with the VRF the server is reached in; **dynamic ARP inspection**, its
VLANs, the extra checks (`src-mac`, `dst-mac`, `ip`), its log buffer, which
ports are trusted, and **ARP ACLs** (entries permitting one sender address and
MAC, for hosts with fixed addresses) applied to VLANs; and **IP Source Guard**
per port and its fixed bindings (address, MAC, VLAN and port). The bindings
table lists what DHCP snooping learned (`show ip dhcp snooping binding`) and
the fixed ones. Turning on snooping, ARP inspection or IP Source Guard can cut
devices off at once; each confirm page says how.

**Restarting the switch.** The **Restart** buttons (top bar, menu foot and the
Config page) open the restart page. When the role has the restart rules (role
version 18, from Update the port list), NXray types `terminal dont-ask` and
`reload` over NX-API with its own account: nothing unsaved restarts at once;
with unsaved changes the page asks whether to save first (NXray's own account).
No admin login is asked. Before that update, the page asks for the switch admin
login and SSH port and types the same two lines over SSH, once; the password
is never stored. The switch dropping the connection is how NXray knows it went
down; it answers again after several minutes.

**vPC.** The **vPC** page (role version 19, from Update the port list) needs the
`vpc` and `lacp` features (Features page). It reads `show vpc` and, as text,
`show running-config vpc`, and types the vPC domain with its settings
(`vpc domain 10`, `peer-keepalive destination ...`, `peer-switch`, ...) and on a
port-channel `vpc peer-link` or `vpc <number>`, each with its `no` form. The
port-channel must exist first (Port-channels page); the same domain and vPC
numbers are set on the other switch of the pair, from its own NXray. Written
from Cisco's NX-OS 9.3 guides; not yet tried on a switch.

**Priority flow control.** The **Priority flow control** page needs no rule of its own, so
it works with the broad role and with a stored admin login, and is off with the limited
role (it has no rule numbers left). It reads `show interface priority-flow-control detail`
and `show interface brief`, and types `priority-flow-control mode on|off|auto` and
`priority-flow-control watch-dog-interval on|off` on a port, and, for the whole switch,
`priority-flow-control watch-dog-interval on|off` and `priority-flow-control
override-interface mode off`, each with its `no` form. Which classes are paused is set on the
QoS page (`pause pfc-cos` in a network-qos policy). The show output was read on cisco-25gb
(NX-OS 9.3(16)); the configuration lines are written from Cisco's NX-OS 9.3 guide and were
not tried on a switch.

**QoS.** The **QoS** page needs no rule of its own, so it works with the broad role and
with a stored admin login, and is off with the limited role (it has no rule numbers left).
It reads `show class-map type qos`, `show policy-map type qos`, `show class-map type
network-qos`, `show policy-map type network-qos`, `show policy-map type queuing`, `show
policy-map interface brief`, `show policy-map system` and `show queuing interface`, and
types `class-map type qos match-any|match-all <name>` with `match dscp`, `cos`,
`precedence`, `access-group name` and `ip rtp`; `policy-map type qos <name>` with
`class <class-map>`, `set qos-group`, `set dscp`, `set cos`, `set precedence` and `police
cir ... conform transmit violate drop`; `service-policy type qos input <policy>` on a port;
`class-map` and `policy-map type network-qos` with `mtu` and `pause pfc-cos`;
`policy-map type queuing` with `class type queuing c-out-8q-q3` and `bandwidth remaining
percent`, `priority level`, `shape min ... max ...` and `queue-limit ... bytes`; and, under
`system qos`, `service-policy type network-qos|queuing output|qos input <policy>`, each
with its `no` form. Tried on cisco-25gb (NX-OS 9.3(16)) with throwaway objects on
Ethernet1/54: the switch refuses `match ip dscp`, `match vlan` and DSCP names such as
`af11`; `no set cos` and `no police` alone (the whole line is needed); a classification
policy as `output`; a queuing policy on a port; and `priority level` together with
`bandwidth` in one queue. Applying a policy under `system qos` changes the whole switch
and was not tried, so those lines are written from Cisco's guide. While no class-map or
policy-map was made, the switch prints nothing for the first two commands.

**Monitor sessions.** The **Monitor sessions** page needs no rule of its own, so it works
with the broad role and with a stored admin login, and is off with the limited role (a
role holds 256 rules and the limited one has 254 in use). It reads `show monitor session
all` and, as text, `show running-config monitor` (for the ERSPAN source address), and
types `monitor session <n>` (`monitor session <n> type erspan-source` for ERSPAN, which
the switch needs every time) with its `source interface`, `source vlan`, `filter vlan`,
`destination interface` or `destination ip`, `erspan-id`, `vrf`, `ip ttl`, `ip dscp`,
`mtu` and `shut` / `no shut`, `switchport monitor` on a destination port, and `monitor
erspan origin ip-address <address> global`, each with its `no` form. Tried on
cisco-25gb (NX-OS 9.3(16)) with throwaway sessions: sessions are numbered 1 to 32, the
switch refuses `tx` and `both` on a port source while sFlow is on, a description is at
most 32 characters, and `header-type` was refused. A session did not leave "Session
admin shut" on the test ports (no transceiver on the destination), so a session coming up
was not seen. ERSPAN destination sessions (`monitor session <n> type erspan-destination`,
`source ip`, `erspan-id`, `vrf`, `destination interface`) are written from Cisco's guide:
the switch refuses them while the nve feature is on, and it was on, so they were not tried.

**VXLAN.** The **VXLAN** page (role version 20, from Update the port list) needs the
`nve` and `vnseg_vlan` features (Features page). It reads `show nve interface`,
`show nve peers`, `show nve vni` and, as text, `show running-config` (there is no
`show running-config vxlan`), and types
the NVE interface (`interface nve1`, `source-interface`, `host-reachability protocol
bgp`, `member vni`), a VLAN's `vn-segment`, the `evpn` block of a VNI, a VRF's `vni`
and EVPN route-targets, and the switch-wide `nv overlay evpn` and anycast gateway MAC,
each with its `no` form. Entering `interface nve1` also needs the role's port list to
name it (`permit interface nve1`), which NXray writes only while the nve feature is on
(the switch is expected to refuse it otherwise, as with the VLAN interfaces): turn the
feature on first, then press Update the port list. The same VNIs are set on every
switch of the fabric, from each one's NXray. The EVPN block and a VRF's EVPN
route-targets need `feature bgp` and `nv overlay evpn` first; the switch refuses them
otherwise, and `member vni ... associate-vrf` needs `host-reachability protocol bgp`.
The lines were tried on cisco-25gb (NX-OS 9.3(16)) with throwaway objects; the role
rules and EVPN with a real BGP neighbor were not.

**Config.** The **Config** page (admins only: a configuration holds every
setting of the switch, SNMP communities and password hashes included) shows
whether the running configuration differs from the saved one, line by line,
with a Save config button. **Take a backup now** stores the running
configuration in NXray, with who took it and an optional note, and makes a
switch checkpoint of the same moment named `nxray-<number>`. Backups can be
downloaded as text, compared with the running or saved configuration or with
each other, and deleted (their checkpoint with them). **Roll back to this**
shows what would change and asks for the switch admin login: NXray's own
account has no rule to roll back, so a stolen NXray cannot undo the switch's
configuration wholesale. NXray then takes a backup of the configuration it is
about to replace, and sends `rollback running-config checkpoint nxray-<n>`
with the admin login, once; the password is never stored. NX-OS rolls back all
or nothing: if a line fails, nothing changes. The switch loses its checkpoints
when its configuration is erased; the backup's text stays in NXray. An install
whose role predates this gets a **Turn on security and config changes** card on
the Switch page; it adds rules 171 to 190 with no wait. Without them the
Config page still keeps backups (without checkpoints) once switch admin
changes are on. These rules and lines follow Cisco's NX-OS 9.3 configuration
guides and have not yet been tried on a switch. An install whose role predates
the DHCP and ARP page gets a **Turn on layer 2 security changes** card; it adds
rules 191 to 227 with no wait. They also follow Cisco's NX-OS 9.3 Security
Configuration Guide and have not yet been tried on a switch.
An install whose role predates the rate average and sFlow gets a **Turn on
traffic measuring changes** card; it adds rules 228 to 231 with no wait. They
follow Cisco's NX-OS 9.3 Interfaces and System Management Configuration Guides;
rule 230 (`sflow` lines) has worked on an N9K-C92160YC-X, the others have not
yet been tried on a switch.
An install whose role predates resetting a port or a port-channel gets a
**Turn on reset to defaults changes** card; it adds rule 232 with no wait.
This follows Cisco's NX-OS 9.3 Interfaces Configuration Guide and has not yet
been tried on a switch.
An install whose role predates reading sFlow's status gets a **Turn on sFlow
status changes** card; it adds rule 233 (`show sflow`) with no wait. Without
it the switch refuses `show sflow` for every NXray account, and the Traffic
page's sFlow card shows "Permission denied for the role".

**How long a port averages its rates.** The switch works out a port's In and
Out as an average over the last 30 seconds unless told otherwise. With traffic
measuring changes on (role version 15), a port's page and its side panel have
a **Rate average** card: pick 5, 10, 15 seconds, 1, 2 or 5 minutes, or the
switch's default of 30 seconds, and press **Change the rate average**. NXray
asks you to confirm, then sends `interface <port>` and `load-interval counter
1 <seconds>` (or `no load-interval counter 1` for the default). Only the first
of the switch's three counters is changed, the one NXray reads; the traffic
itself is not touched, only the figures. A shorter average follows bursts
more closely, so the figures jump about more. Cisco's guide gives 5 to 300
seconds for the Nexus 9000; if the switch refuses one of these values, the
page shows the switch's own words. Not saved until you press **Save config**.
NXray's **Live** refresh works its rates out from the byte counters instead,
whatever the average (see [Live figures](live.md)).

**Reset to defaults (#21).** With reset changes on (role version 16), a port's
own page and its side panel have a **Reset to defaults** button, and the
Ports page's **Change several ports** card has **Reset the ticked ports to
their defaults**; the Port-channels page has **Reset `<name>` to defaults**
for each port-channel. All three send `default interface <name>` after a
confirm page that names everything the port, each ticked port, or the
port-channel loses: its description, VLANs (mode, access or native VLAN, the
VLANs a trunk carries), speed, MTU, FEC, flow control, storm control, layer
(switched or routed, with any IPv4 address) — or says there is nothing to
remove when it is already a plain, unconfigured access port. A port goes back
to a plain access port in VLAN 1, turned on; a port-channel's own description
and LACP minimum links reset, but its members keep their channel-group
membership, which is set on each member port, not on the port-channel, so the
confirm page names them and warns that only the port-channel's own settings
change. The confirm page also warns when a port or port-channel is up: the
device on it may lose its connection while it resets. NXray refuses rather
than resetting only part of several ticked ports: an unticked, unknown or
untickable port stops the whole request and names the reason. Like other
changes, this is not saved until you press **Save config**.

**Activity.** The **Activity** page (admins only) lists every change made
through NXray, newest first, with the account, the page it was made on, the
change in plain words (passwords and SNMP communities masked) and the switch's
address: port, VLAN, routing, protocol, spanning tree, switch admin, ACL, port
security, DHCP and ARP and feature changes, Save config, backups, rollbacks and
restarts, the Switch
page's actions, and changes to NXray's own accounts and settings. Filter it by
account, page or text, or download it as CSV. Lines are kept for a year.

**Taking port changes away.** In an SSH session on the switch as admin:

    configure terminal
    no username nxray role nxray-ports
    end
    copy running-config startup-config

(with your account name in place of `nxray`). Remove the role itself with
`no role name nxray-ports` only when no NXray install on the switch uses it.

### How much access NXray's account gets

Each switch has a role mode, chosen in the setup form (next to **Also turn on
changes**) and changeable later on the Switch page under **How much access
NXray's account gets**. Changing it asks for the switch admin login, writes the
`nxray-ports` role again, removes the rules the new mode does not have, and
saves the configuration. The port list (`interface policy deny` and the ports it
names) is the same in every mode, so the account stays limited to those ports.

| Mode | The role | After an NXray update that adds rules |
| --- | --- | --- |
| **Limited role** (default) | Only the listed rules. | An admin presses **Update the port list**; the banner says when. |
| **Broad role with a deny list** | `rule 1 permit command conf t ; *` and `show *`, the few commands typed outside configuration mode (`copy running-config startup-config`, `clear mac address-table dynamic`, `clock set`, `checkpoint`, `terminal dont-ask`, `reload`), and denies for configuration of `username`, `role`, `aaa`, `tacacs-server`, `radius-server` and `boot` (and their `no` forms). | Nothing: new features need no role update. The account can change any other setting on the switch. |
| **Limited role, admin login stored** | The listed rules, as in the limited mode. | NXray adds the rules itself when it starts. A stolen NXray database exposes the switch's real admin login, not only the low-privilege account. |

In the broad role a rule with a higher number wins over a lower one, so the
denies are numbered right after the permit for `conf t ; *`, and the other
permits after them. Checked on a switch (NX-OS 9.3(16)): the `username` deny,
and that the port list still limits the account. Not yet tried: the denies for
`role`, `aaa`, `tacacs-server`, `radius-server` and `boot`, and the `no` forms.

With the login stored, it is kept encrypted with the same key as NXray's own
account password (see [Configuration](configuration.md)), with the SSH port
typed with it. **Delete the stored admin login** removes it and puts the switch
back on the limited role, whose rules are the same; the role on the switch is
not touched. **Forget this switch** removes it too.

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
| Resetting a port is off / Resetting ports is off / Resetting a port-channel is off | Port changes were turned on before NXray could reset ports and port-channels. Press **Turn on reset to defaults changes** on the Switch page |

## The certificate and the SSH host key

The switch's NX-API uses a self-signed certificate. NXray accepts it without
checking, and does the same with the switch's SSH host key when turning on
port changes; see [SECURITY.md](../SECURITY.md).
