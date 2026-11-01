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
| admin | Everything: the Switch page (setup, address, Run setup again, turning on port, VLAN, port settings, feature, neighbor, port-channel, VLAN interface, VRF, static route, routing protocol, spanning tree, switch admin, security and config and layer 2 security changes, updating the port list), turning switch features on and off on the Features page, the Users page, the Config page (configuration backups, comparing them, rolling the switch back and restarting it with the switch admin login) and the Activity page (who changed what through NXray), plus what an operator may do. |
| operator | Change the switch through NXray: turn ports on or off, edit descriptions, create, rename and delete VLANs, set a port's VLANs and settings (speed, MTU, FEC, flow control, storm control, layer), split or join a 100G port, turn CDP and LLDP on or off on a port, set the MAC address aging time, add and remove static MAC addresses, clear learned ones, make, change and delete port-channels and set their LACP options, make, change and delete VLAN interfaces and put IPv4 and IPv6 addresses on them and on routed ports, make and delete VRFs and move interfaces between them, add and remove static routes, run the routing protocols (OSPF, OSPFv3, BGP, EIGRP, RIP, IS-IS, HSRP, VRRP, VRRPv3, PIM, PIM6, IGMP, MSDP, BFD) and change their settings, route-maps, prefix-lists and key chains, change spanning tree (mode, VLAN priorities and timers, the MST region, port types, guards and costs), change the switch's hostname, banner, clock, NTP, DNS, logging and SNMP settings on the Switch admin page, make, change, delete and apply IPv4, IPv6 and MAC ACLs, object groups and VLAN access maps, size the TCAM regions, set port security on the front ports, set DHCP snooping, the DHCP relay, ARP inspection and IP Source Guard, Save config. Also set the labels NXray keeps on ports. |
| viewer | Look only: the dashboard, ports, VLANs, port-channels, spanning tree, routing, routing protocols, neighbors, history, features, switch admin, the switch's log, ACLs, port security and DHCP and ARP. |

Admins add accounts, change roles, disable accounts and set new passwords on
the **Users** page. Everyone changes their own password on the Account page
(click your name at the top). A new role or a disabled account takes effect
on that account's next click, and a new password signs it out everywhere.
NXray always keeps at least one active admin, and an admin can't change
their own role or disable themselves.

An account on the Users page exists only in NXray. Every change it makes
reaches the switch through NXray's own switch account, so the switch's own
logs show NXray's account, and NXray's Activity page shows who did it. Such
an account cannot sign in to the switch over SSH or the console.

### Switch accounts: the same person on the switch's command line

For people who still use the switch's command line, an admin can also give
them a local account on a switch, with the same name and password:

- **When adding someone**, tick the switches under **Where** (leave them all
  unticked for NXray only, the default), type the switch admin username and
  password, and tick the box that confirms the role on the switch.
- **For someone who already exists**, press **Switch accounts** in their row.
  That page makes an account on a switch, links an account that is already
  there, sets one new password for NXray and every switch account, gives a
  switch account the right role, locks it, or removes it.

The role on the switch follows the NXray role:

| NXray | Switch |
| --- | --- |
| viewer | `network-operator` (look only) |
| operator | `network-operator` plus `nxray-ports`, the role NXray's own account gets when changes are on, so the person may change over SSH what NXray may; `network-operator` only on a switch where changes are off |
| admin | `network-admin` |

Only these three roles are added or taken off; any other role an account has
stays. NXray never links, changes or removes its own switch account, nor the
names NX-OS keeps for itself (`admin`, `root` and others).

Things to know:

- **The switch admin login** is typed on each form, used for that one
  request, and never stored, logged or shown. NXray's own switch account
  cannot make accounts and is not given that power.
- **Passwords.** NXray keeps only a hash of a password, so it sets the switch
  password while the plain one is in hand: when the account is made, and
  when an admin sets a new password for NXray and the switch together. The
  switch takes 8 to 64 letters and digits, with upper case, lower case and
  digits and no runs like `aaa` or `abc`; NXray checks that before anything
  is sent and says which side would refuse. A password set for NXray alone
  (on the Users page, or by someone on their own Account page) leaves the
  switch account **out of step**: the Users page, the person's Switch accounts
  page and their Account page say so, and an admin sets a new password for
  both.
- **Out of step** also shows when the NXray role changed (press **Change the
  role** on the Switch accounts page), when an NXray account is disabled but
  its switch account can still sign in, and when a switch account is locked
  but the NXray account is enabled again.
- **Disabling.** NX-OS has no switch to turn a local account off, so **Lock
  the switch account** gives it a random password nobody knows; the account
  and its role stay, and SSH sessions already open stay open until they end.
  A new password for both sides opens it again.
- **Saving.** Every change to a switch account saves the switch
  configuration straight away, which also keeps any other unsaved change
  there. Without that, a restart of the switch would undo it: a lock would
  open again, a removed account would come back. If the save fails, the page
  says a restart undoes the change until you press Save config.
- **Accounts already on the switch** are listed on the Users page, with the
  NXray user each belongs to, so you can link one instead of making a
  duplicate. NXray never makes a second account over an existing one.

**Many people or many switches?** Local accounts suit a few people on a few
switches. Beyond that, TACACS+ or RADIUS is the usual answer: each person has
one sign-in kept on a server, every switch asks that server, and leaving the
company means turning off one account, not one per switch. NXray does not set
up TACACS+ or RADIUS; that is done on the switch (`aaa` commands) and the
server.

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

## Self-update

Off by default. With it on, an admin presses **Update now** on the Settings
page instead of running the two commands under Updating, and NXray checks
ghcr.io once a day to say when one is waiting. The page shows what ghcr.io
has for the tag your compose file uses: `:latest` follows every release, a
pinned `:0.1.0` stays where it is.

It needs the Docker socket inside the container, and **the Docker socket is
root on the machine**: anything that can use it can start a privileged
container. Turn it on only where you already trust this image with root. With
it off, NXray never contacts ghcr.io or Docker.

1. In `docker-compose.yml`, uncomment the `/var/run/docker.sock` volume line
   and the `group_add` lines. NXray runs as a normal user and the socket
   belongs to the `docker` group, so put your group's number in place of
   `999` (find it with `getent group docker | cut -d: -f3`).
2. In `nxray.env`, set `NXRAY_ENABLE_SELF_UPDATE=true`.
3. Run `docker compose up -d`.

**Update now** pulls the new image and has Docker replace the container, so
the page is gone for a few seconds and then reloads itself. Sessions, accounts
and the switch login are on the data volume and carry over. The pull and
restart are done by a short-lived container named `nxray_updater`, started
from the same image; its logs (`docker logs nxray_updater`) say what happened
if a failure is shown. If the page says the container was not recreated, run
`docker compose up -d` in the compose folder to finish by hand.

It works only for a container started by `docker compose` from the published
image. A copy built from a clone (`docker-compose.dev.yml`) is never reported
out of date.

### Beta versions

Under **Settings → Updates**, an admin can tick **Include beta versions** and
press **Save**. Betas are built from the `dev` branch to try what comes next,
and can change and break between builds. Saving installs nothing: it runs the
check again, and **Update now** does the move.

- With betas on, NXray goes to the `:beta` tag while the newest beta is ahead
  of the latest release, and back to `:latest` once a release has caught up.
- With betas off, it follows `:latest`.
- Only a newer version is ever offered. Versions are ranked from the GitHub
  releases list: version numbers first, and a release above every beta of
  its version (0.2.0 is newer than 0.2.0-beta.3, which is newer than
  0.2.0-beta.2). Turning betas off on a beta that is newer than the latest
  release stays on it until a newer release is out, so an install never runs
  an older build against a database a beta already changed.

With betas on, or a beta running, the check also asks `api.github.com` for
the list of releases. With self-update off, NXray contacts neither.

**Update now** hands the chosen tag to the short-lived updater as `NXRAY_TAG`,
and the sample compose file's `image:` line reads it:

    image: ghcr.io/acebmxer/nxray:${NXRAY_TAG:-latest}

Nothing on the host is edited. A compose file whose `image:` line names a
fixed tag (`:latest`, `:beta` or a pinned `:0.1.0`) ignores `NXRAY_TAG`; after
the update the Updates card then says the container is still on the old tag
and shows the line to change, instead of reporting success. See **Updating
from 0.1.x** under Updating.

## History

Once a switch is set up, NXray reads it every minute (`NXRAY_HISTORY_INTERVAL`
changes that, `0` turns it off; with several switches it reads each of them,
one after the other, and keeps their history apart) with four read-only commands, the same ones
the dashboard and the Ports page run when they open: `show environment`, `show system resources`,
`show interface` and `show interface status`. It stores temperatures, total power draw, fan speed, CPU
and memory use, the traffic of every port that is up and each port's new
errors and discards, each VLAN's traffic estimated from its access ports (see
[Traffic per VLAN and per device](traffic.md)), and deletes anything older than 30 days. The History page
draws them for the last hour, 6 hours, 24 hours, 7 days or 30 days, and each
port's page draws its own traffic and errors. Times are UTC. Opening the pages
never contacts the switch.

The numbers live in NXray's database on the data volume and take space with
the number of ports that are up (and, a little, with the number of VLANs that have an access port up): roughly 7 MB a day with a dozen up, so about
200 MB once 30 days have built up, for each switch. Nothing is recorded while NXray cannot
reach the switch or is waiting for it to apply a new role after **Turn on port,
VLAN, port settings, feature, neighbor, port-channel, VLAN interface, VRF, static route, routing protocol, spanning tree, switch admin, security and config and layer 2 security changes**; the charts show that as a gap. A port's errors are recorded as the
increase since the previous sample, so the first sample after NXray starts
records none.

## Alerts

The **Alerts** page (admins only) sends an e-mail, a webhook or both when a
switch needs attention, and again when the problem is over. With several
switches every alert names its switch (`leaf1 (192.0.2.10)`), and the rules
and destinations are the same for all of them. It is checked
each time history reads the switch, from the same four commands, so it asks
nothing more of the switch; with `NXRAY_HISTORY_INTERVAL=0` nothing is
checked (changes made through NXray are still sent when asked for).

What can be alerted on:

| Alert | When it starts | When it is resolved |
| --- | --- | --- |
| Switch unreachable (on) | Two reads in a row fail | The next read works |
| Temperature (on) | A sensor at or above its minor limit, and again at its major one | It is below the limit |
| Fans, power supplies (on) | The switch reports one as not OK | It reports OK |
| CPU, memory (off) | Use at or above the limit you set, three checks in a row | It is below the limit |
| A port that goes down (off) | A watched port that was up goes down while it is turned on; watch every port, or only those with a description or a label | It is up again, or turned off |
| Port errors (off) | A port has at least the number you set of new errors and discards in one check | A check with fewer |
| Changes (off) | Every change made through NXray, as the Activity page lists it | — |

Each problem is sent once when it starts and once when it is resolved, also
across a restart of NXray. Everything found in one check goes out as one
e-mail and one POST to each webhook. The page lists what is open now and the
alerts sent in the last 90 days with how each delivery went; **Send a test**
buttons send one at once.

**E-mail** needs a mail server (SMTP), the port, the connection's security
(STARTTLS, SSL/TLS, or none for a relay on a trusted network), optionally a
username and password, a From address and up to ten addresses to send to.
The server's certificate is checked, and a password is never sent over an
unencrypted connection.

**Webhooks**, up to ten, each POST JSON in one of three formats: NXray's own
(`source`, `switch`, `sent_at`, `text` and an `events` list with each
event's `kind` (`problem`, `resolved`, `change` or `test`), `key`, `message`
and `since`), Slack's (`{"text": ...}`) or Discord's (`{"content": ...}`).
Anything that answers with a 2xx status counts as delivered. NXray's own
format can be signed: with a signing secret, each POST carries
`X-NXray-Signature: sha256=<HMAC-SHA256 of the body with the secret>`.

The SMTP password and each webhook's URL and secret are stored encrypted with
a key derived from `NXRAY_SECRET_KEY`, like the switch login; after a change
of that key, type the password and add the webhooks again (the page says so
when an alert cannot be sent for that reason). The page shows only a
webhook's scheme and host, since a Slack or Discord URL is itself the
password. NXray reaches the mail server and the webhooks from the container: e-mail
directly, webhooks through the proxy in `HTTPS_PROXY` when one is set.

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

The build downloads the IEEE's list of MAC address makers, which the
Neighbors page and a port's page use to name the maker of each device. If
the build cannot reach the IEEE it says so and uses the copy in the
repository instead. Docker keeps that step in its build cache, so a rebuild
reuses the list from the last download; `--no-cache` downloads it again.

## Updating

The sample compose file uses the `:latest` tag unless `NXRAY_TAG` says
otherwise, and `:latest` follows every release, so in the `nxray` folder:

    docker compose pull
    docker compose up -d

To stay on one version until you choose to move, put that version in the
compose file's `image:` line (for example `ghcr.io/acebmxer/nxray:0.2.0`) and
change it when you want to upgrade; then run the same two commands.

To try betas, use the `:beta` tag. It is the beta channel: it moves with every
beta published from the `dev` branch, so it can change and break between
runs, and `:latest` never receives it. Each beta is also listed as a
pre-release on the GitHub Releases page. With self-update on, tick **Include
beta versions** on the Settings page (see [Beta versions](#beta-versions)).
Without it, put a file named `.env` beside `docker-compose.yml` holding only
this line:

    NXRAY_TAG=beta

A plain `docker compose up -d` on the host uses whatever the compose file and
`.env` say. Keep the password hash in `nxray.env`, never in `.env`: compose
reads `.env` to fill in `$` variables, and the hash is full of them. Delete
`.env` (or set `NXRAY_TAG=latest`) to go back to releases.

### Updating from 0.1.x

Every install keeps its own `docker-compose.yml`, and an update never changes
it. Installs set up on 0.1.x (or an earlier beta) have the tag written into
the `image:` line, so edit it once for **Include beta versions** to work:

1. In the `nxray` folder, change the `image:` line from

       image: ghcr.io/acebmxer/nxray:latest

   (or `:beta`, or a pinned `:0.1.0`) to

       image: ghcr.io/acebmxer/nxray:${NXRAY_TAG:-latest}

2. Run `docker compose pull`, then `docker compose up -d`.

Without the edit, 0.2.0 still installs and runs (a `:latest` compose file
pulls it as usual), but the beta switch cannot move the install: the Updates
card says so and shows the line to change.

From a clone, run `git pull` and then
`docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build`.

Your `docker-compose.yml`, `nxray.env` and the data volume are kept.

## If it does not start

    docker compose logs nxray

NXray refuses to start when a setting is missing or wrong, and the log says
which one and how to fix it. The most common one is an empty or mistyped
`NXRAY_ADMIN_PASSWORD_HASH`.
