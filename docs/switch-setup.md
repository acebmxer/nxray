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
under **Port changes**, tick the box and press **Turn on port changes**.
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
         interface policy deny
           permit interface Ethernet1/1
           ... (one line per front-panel port)
       username <name> role nxray-ports
       end

   NX-API refuses the `;` in these rules, which is why this one step uses
   SSH. The SSH port is 22 unless you change it on the page.
3. Checks over NX-API that the account now has the role, and runs
   `copy running-config startup-config` (again saving any other unsaved
   changes on the switch).

The role lets NXray's account turn front-panel ports on or off, set or
remove their descriptions and set their mode (access or trunk) and VLANs;
create, name and delete VLANs; and save the configuration. The switch
refuses it everything else: mgmt0, speed, MTU, shutting a VLAN down or
suspending it, accounts and other switch-wide settings. Every NXray install
on a switch uses the same `nxray-ports` role.

**The wait.** The switch keeps an account's permissions in its NX-API
session and only reloads them once that session has been idle for NX-API's
timeout (10 minutes unless changed). So after turning port changes on,
NXray does not contact the switch for that long plus a minute, about 11
minutes, and every page says so.

**Installs that turned port changes on before VLANs existed.** Their role
has rules 1 to 5 only. The Switch page then shows a **VLAN changes** card:
type the admin login, tick the box and press **Turn on VLAN changes**. NXray
types the same lines as above (adding rules 6 to 11) and saves the
configuration. There is no wait this time: the switch applies new rules in a
role the account already has at once.

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

**VLANs.** The **VLANs** page lists every VLAN with the ports using it, and
creates (number and optional name), renames and deletes VLANs. Names are up
to 32 letters, digits, dots, dashes or underscores, without spaces: the
switch refuses spaces and silently ignores a longer name. VLAN 1 cannot be
renamed or deleted, and the switch keeps 3968 to 4094 for itself. A VLAN
that a port still uses cannot be deleted: an access port in it, a trunk
using it as native VLAN, or a trunk that names it in its list (a trunk
carrying every VLAN does not count). Move those ports first; the page lists
them. Deleting asks you to confirm.

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
| Port changes are now off: the nxray-ports role is no longer on the switch | Run setup again found the role gone. Press **Turn on port changes** to make it again |
| VLAN changes are off | Port changes were turned on before NXray could change VLANs. Press **Turn on VLAN changes** on the Switch page |

## The certificate and the SSH host key

The switch's NX-API uses a self-signed certificate. NXray accepts it without
checking, and does the same with the switch's SSH host key when turning on
port changes; see [SECURITY.md](../SECURITY.md).
