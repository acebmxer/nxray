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

## When it stops working

| The page says | What it means |
| --- | --- |
| could not reach the switch | Wrong address or port, a firewall, or NX-API is off |
| the switch refused the admin username or password | The admin login typed during setup is wrong |
| the switch refused the NXray account | NXray's account was removed or changed on the switch. Forget the switch and set it up again with a new name |
| NXray cannot read the stored switch login | `NXRAY_SECRET_KEY` (or the data volume's `secret_key` file) changed. Forget the switch and set it up again with a new name |

## The certificate

The switch's NX-API uses a self-signed certificate. NXray accepts it without
checking; see [SECURITY.md](../SECURITY.md).
