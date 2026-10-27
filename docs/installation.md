# Installation

[← back to the README](../README.md)

NXray runs as one Docker container. The image is published to GitHub
Container Registry, so two files are the whole deployment: there is nothing
to clone and nothing to build.

## Requirements

- Linux with Docker Engine and the Compose plugin, Compose 2.30 or newer
  (`docker compose version`). Older Compose cannot read the `format: raw`
  setting the compose file relies on.
- Network access from that machine to the switch's management address on
  port 443, with NX-API turned on (`feature nxapi`).

## Steps

In a terminal on the machine that will run NXray:

1. Make a folder and download the two sample files into it:

       mkdir nxray && cd nxray
       curl -o docker-compose.yml https://raw.githubusercontent.com/acebmxer/nxray/main/docker-compose.yml.example
       curl -o nxray.env https://raw.githubusercontent.com/acebmxer/nxray/main/nxray.env.example

   The settings file must be called `nxray.env`, not `.env`: Compose treats a
   file of that name as its own variable source and mangles the password
   hash.

2. Create the hash of the password you will sign in with. This pulls the
   image the first time, then asks for the password twice:

       docker compose run --rm nxray python -m app.hashpw

   It prints a line starting with `NXRAY_ADMIN_PASSWORD_HASH=$argon2id$`.

3. Open `nxray.env` in a text editor, replace the empty
   `NXRAY_ADMIN_PASSWORD_HASH=` line with the printed line, and save.

4. Start it:

       docker compose up -d

5. Open `http://<that machine's address>:8080` in a browser and sign in as
   `admin` (or the `NXRAY_ADMIN_USER` you set) with the password from step 3.
   That first account is an admin. Add accounts for other people on the
   **Users** page; see [Accounts and roles](#accounts-and-roles).

6. Click **Switch** at the top and set up the switch. What that does on the
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

### Two-factor sign-in

Each person can turn it on for their own account: on the Account page, press
**Set up two-factor sign-in**, scan the QR code with an authenticator app on
your phone (Google Authenticator, Microsoft Authenticator, Authy, 1Password
and others), and type the six-digit code the app shows. NXray then shows ten
backup codes, once: print them or keep them in a password manager. From then
on, signing in asks for the app's code after your password. Each code works
once, so after a sign-in you may have to wait for the app's next code to sign
in again.

The codes depend on the clock of the machine NXray runs on. If every code is
refused, check that machine's time (for example with `timedatectl`).

Lost your phone? Sign in with a backup code instead of the app's code, then
on the Account page turn two-factor sign-in off and set it up again on your
new phone. **New backup codes** on the same page gives you ten fresh ones
when you are running low. No phone and no backup codes left: another admin
presses **Turn off** in the Two-factor column on the Users page. If you are
the only admin, run this on the machine NXray runs on, in the `nxray`
folder:

    docker compose exec nxray python -m app.resetpw --2fa-off admin

with your account's name in place of `admin`. It turns off two-factor
sign-in and leaves the password as it is.

Changing `NXRAY_SECRET_KEY` makes the stored two-factor keys unreadable:
those accounts sign in with a backup code (or one of the ways above) and set
two-factor sign-in up again.

### Forgotten password

Another admin can set a new one on the Users page. If nobody who can is
able to sign in, set it from the machine NXray runs on, in the `nxray`
folder:

    docker compose exec nxray python -m app.resetpw admin

with your account's name in place of `admin`. It asks for the new password
twice, and also enables the account if it was disabled. Changing
`NXRAY_ADMIN_PASSWORD_HASH` in `nxray.env` does not work for this: that line
is only read on the very first start, to make the first account.

## HTTPS

Out of the box NXray serves plain HTTP on port 8080, so passwords and sessions
cross the network unencrypted. To have NXray serve HTTPS itself:

1. In `nxray.env`, set:

       NXRAY_ENABLE_HTTPS=true

2. Check that `docker-compose.yml` has the `"8443:8443"` line under `ports:`
   (copies made from `docker-compose.yml.example` before HTTPS existed don't;
   add it below the `"8080:8080"` line).

3. Apply it:

       docker compose up -d

4. Open `https://<that machine's address>:8443`. On the first start NXray
   makes a self-signed certificate, so the browser warns once; accept it to
   continue. `http://<that machine's address>:8080` now sends you to the
   HTTPS address.

To get rid of the warning, upload a certificate your browsers trust (from
your own certificate authority, for example) on the **Settings** page, as an
admin: the certificate file (with its chain, the server's own certificate
first) and its private key, both PEM, the key without a passphrase. The
certificate must carry the name or address you type in the browser. NXray
uses it at once; no restart.

If you publish HTTPS on another port (say `"9443:8443"`), also set
`NXRAY_HTTPS_PORT=9443` in `nxray.env`, so plain-HTTP visits are sent to the
right port.

The certificate and its key are kept in `/data/tls` on the data volume. To
go back to plain HTTP, set `NXRAY_ENABLE_HTTPS=false` and run `docker compose
up -d` again.

## Building from a clone

To run your own changes, or code that has no release yet, clone the
repository instead and build it:

    git clone https://github.com/acebmxer/nxray.git
    cd nxray
    cp docker-compose.yml.example docker-compose.yml
    cp nxray.env.example nxray.env

`docker-compose.dev.yml` is in the clone and adds `build: .`, so the image is
built from your folder instead of pulled. Add it to every `docker compose`
command, including the hash step (step 2 above), or Compose pulls the
published image instead of running your build:

    docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm nxray python -m app.hashpw
    docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build

## Updating

The sample compose file uses the `:latest` tag, which follows every release,
so in the `nxray` folder:

    docker compose pull
    docker compose up -d

To stay on one version until you choose to move, put that version in the
compose file's `image:` line (for example `ghcr.io/acebmxer/nxray:0.1.0`) and
change it when you want to upgrade; then run the same two commands.

From a clone, run `git pull` and then
`docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build`.

Your `docker-compose.yml`, `nxray.env` and the data volume are kept.

## If it does not start

    docker compose logs nxray

NXray refuses to start when a setting is missing or wrong, and the log says
which one and how to fix it. The most common one is an empty or mistyped
`NXRAY_ADMIN_PASSWORD_HASH`.
