# Installation

[← back to the README](../README.md)

NXray runs as one Docker container. There is no published image yet, so for
now it is built from a clone of this repository on the machine that runs it.

## Requirements

- Linux with Docker Engine and the Compose plugin, Compose 2.30 or newer
  (`docker compose version`). Older Compose cannot read the `format: raw`
  setting the compose file relies on.
- Network access from that machine to the switch's management address on
  port 443, with NX-API turned on (`feature nxapi`).

## Steps

In a terminal on the machine that will run NXray:

1. Get the code and go into it:

       git clone https://github.com/acebmxer/nxray.git
       cd nxray

2. Make your own copies of the compose file and the settings file:

       cp docker-compose.yml.example docker-compose.yml
       cp nxray.env.example nxray.env

3. Create the hash of the password you will sign in with. This builds the
   image the first time, then asks for the password twice:

       docker compose run --rm nxray python -m app.hashpw

   It prints a line starting with `NXRAY_ADMIN_PASSWORD_HASH=$argon2id$`.

4. Open `nxray.env` in a text editor, replace the empty
   `NXRAY_ADMIN_PASSWORD_HASH=` line with the printed line, and save.

5. Start it:

       docker compose up -d

6. Open `http://<that machine's address>:8080` in a browser and sign in as
   `admin` (or the `NXRAY_ADMIN_USER` you set) with the password from step 3.
   That first account is an admin. Add accounts for other people on the
   **Users** page; see [Accounts and roles](#accounts-and-roles).

7. Click **Switch** at the top and set up the switch. What that does on the
   switch is described in [Switch setup](switch-setup.md).

## Accounts and roles

Each NXray account has one of three roles:

| Role | May |
| --- | --- |
| admin | Everything: the Switch page (setup, address, Run setup again, turning on port and VLAN changes) and the Users page, plus what an operator may do. |
| operator | Change the switch through NXray: turn ports on or off, edit descriptions, create, rename and delete VLANs, set a port's VLANs, Save config. |
| viewer | Look only: the dashboard, ports and VLANs. |

Admins add accounts, change roles, disable accounts and set new passwords on
the **Users** page. Everyone changes their own password on the Account page
(click your name at the top). A new role or a disabled account takes effect
on that account's next click, and a new password signs it out everywhere.
NXray always keeps at least one active admin, and an admin can't change
their own role or disable themselves.

These are NXray's own accounts. They have nothing to do with the accounts on
the switch.

### Forgotten password

Another admin can set a new one on the Users page. If nobody who can is
able to sign in, set it from the machine NXray runs on, in the `nxray`
folder:

    docker compose exec nxray python -m app.resetpw admin

with your account's name in place of `admin`. It asks for the new password
twice, and also enables the account if it was disabled. Changing
`NXRAY_ADMIN_PASSWORD_HASH` in `nxray.env` does not work for this: that line
is only read on the very first start, to make the first account.

## Updating

In the `nxray` folder:

    git pull
    docker compose up -d --build

Your `docker-compose.yml`, `nxray.env` and the data volume are kept.

## If it does not start

    docker compose logs nxray

NXray refuses to start when a setting is missing or wrong, and the log says
which one and how to fix it. The most common one is an empty or mistyped
`NXRAY_ADMIN_PASSWORD_HASH`.
