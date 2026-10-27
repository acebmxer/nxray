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

The role lets NXray's account turn front-panel ports on or off and set or
remove their descriptions, and save the configuration. The switch refuses
it everything else: mgmt0, speed, MTU, VLANs, accounts and switch-wide
settings. Every NXray install on a switch uses the same `nxray-ports` role.

**The wait.** The switch keeps an account's permissions in its NX-API
session and only reloads them once that session has been idle for NX-API's
timeout (10 minutes unless changed). So after turning port changes on,
NXray does not contact the switch for that long plus a minute, about 11
minutes, and every page says so.

**Changing a port.** On a port's own page (Ports, then the port's name),
**Change description** and **Turn off this port** / **Turn on this port**
each show what will happen and ask you to confirm. Turning off a port that is
up warns that whatever is plugged in loses its connection. A change takes
effect at once but is not saved: press **Save config** (on the port's page or
the Switch page) to keep it over a restart of the switch. Descriptions are
up to 254 plain characters; NX-API refuses `?` and `;`.

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
| could not reach the switch | Wrong address or port, a firewall, or NX-API is off |
| the switch refused the admin username or password | The admin login typed during setup is wrong |
| the switch refused the NXray account | NXray's account was removed or changed on the switch. Forget the switch and set it up again with a new name |
| NXray cannot read the stored switch login | `NXRAY_SECRET_KEY` (or the data volume's `secret_key` file) changed. Forget the switch and set it up again with a new name |
| NXray is leaving the switch alone for about N more minutes | Port changes were just turned on; the switch is applying the new role. Wait, then reload |
| could not reach the switch over SSH | Turning on port changes needs SSH from the NXray machine to the switch; check SSH is on and the port |
| may not make this change yet | The switch has not applied the port-changes role, or it was removed. Leave NXray's pages closed for 10 minutes and try again, or turn port changes on again |

## The certificate and the SSH host key

The switch's NX-API uses a self-signed certificate. NXray accepts it without
checking, and does the same with the switch's SSH host key when turning on
port changes; see [SECURITY.md](../SECURITY.md).
