# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| Latest release | :white_check_mark: |
| Older tags | :x: |

NXray is pre-1.0 and under active development. Fixes go into the next release
rather than being backported.

## Threat model

Read this before deciding where to run NXray.

**What it holds.** Once a switch is set up, the login of its own account on
the switch, encrypted with a key derived from `NXRAY_SECRET_KEY` (or the
generated `secret_key` file on the data volume). The two-factor keys of
NXray accounts that turned two-factor sign-in on are encrypted the same way.
With built-in HTTPS on, its private key is on the data volume too
(`/data/tls/key.pem`, readable by the container user only).
It also keeps 30 days of history in its database, unencrypted: temperatures,
power, fan speed, CPU and memory use, and each port's traffic rate and error
counts (no addresses, no packet contents).
NXray's switch account starts
read-only (`network-operator`). Once port changes are turned on it also has
the `nxray-ports` role: on the front-panel Ethernet ports it may turn a port
on or off, set or remove its description and set its mode (access or trunk)
and VLANs; it may create, name and delete VLANs; and it may run `copy
running-config startup-config`. The switch refuses it anything else,
including mgmt0. Anyone who takes over NXray can do whatever that account
can, so with port changes on that includes turning ports off and moving them
to other VLANs. Like any local NX-OS account it can also
sign in over SSH, with a password nobody has seen.

**The admin login.** The switch's admin username and password are typed into
the Switch page, used for that one action only, and never stored, logged or
shown. Setup runs exactly these commands with them: `show version`, `show
user-account`, `username <name> password <random> role network-operator`,
`no username <name>` (only to undo a failed setup), `copy running-config
startup-config`. Turning on port changes reads `show interface brief`,
`show user-account` and `show nxapi` over NX-API, types the `nxray-ports`
role and `username <name> role nxray-ports` into an SSH session (NX-API
refuses the `;` the role's rules need), and saves the configuration. The SSH
sign-in uses that password only, never keys or an SSH agent on the NXray
machine. Run setup again reads `show version`, `show user-account`, `show
role` and `show nxapi`, runs `username <name> password <random> role
network-operator` for NXray's existing account name only (a new password,
or the account made again), `username <name> role nxray-ports` when port
changes were on and the account lost the role, and saves the
configuration. Changing the switch address needs no admin login: NXray
signs in at the new address with its own account before storing it.

**Where it belongs.** On a trusted management network. NXray serves plain
HTTP on port 8080; turn on its built-in HTTPS (`NXRAY_ENABLE_HTTPS=true`), or
put it behind an HTTPS reverse proxy of your own (and set `NXRAY_HTTPS=true`),
if it is reachable from anywhere you do not trust. Built-in HTTPS starts with a
self-signed certificate, so the first visit shows a browser warning and a device
pretending to be NXray would not be told apart until you upload a certificate
your browsers trust (Settings page). nginx in front runs as the same non-root
user, allows TLS 1.2 and 1.3 only, and passes the visitor's address on so
sign-in throttling still counts per address. It is
not built to be exposed to the internet.

**Self-update.** Off by default, and then NXray never contacts Docker or
ghcr.io. Turning it on means mounting the Docker socket into the container,
which is root on the host: anyone who can make NXray misbehave could start a
privileged container. Only admins can press Update now (and every form is
CSRF-protected); the one outside call is ghcr.io, once a day and on Check
now. Enable it only on a host where you already trust this image with root.

**What protects it.** Sign-in accounts with Argon2id password hashes. The
first one, an admin, comes from a hash in configuration; the app refuses to
start without one and has no default password. Further accounts get one of
three roles (admin, operator, viewer), checked on every request that changes
something, and a disabled account or a new password signs that account out
at once. Sessions are stored server-side so logout invalidates them
immediately. Failed logins are throttled per address. Optional two-factor
sign-in (TOTP) per account: once on, a correct password alone opens nothing;
the six-digit code is accepted once only, wrong codes count towards the same
throttle, the key is stored AES-GCM encrypted and the ten backup codes only
as SHA-256 hashes. Pages are sent with a
strict Content-Security-Policy and may not be framed by other sites. Every
form that changes something carries a per-session anti-forgery token.

**The switch's certificate is not checked.** NX-API uses a self-signed
certificate generated by the switch. NXray accepts it: the connection is
encrypted, but a device on your network pretending to be the switch would not
be detected. This is a deliberate choice for a management network, not an
oversight. The same goes for the switch's SSH host key when port changes are
turned on.

## Reporting a vulnerability

Report privately through GitHub, not in a public issue:

1. Open the [Security tab](https://github.com/acebmxer/nxray/security) of this
   repository.
2. Choose **Report a vulnerability**.
3. Describe the issue, how to reproduce it, and what an attacker gains.

Expect an acknowledgement within a few days. Please give a reasonable window
for a fix before disclosing publicly.

## Scope

In scope: authentication and session handling; storage of the switch login;
anything that lets a request run a switch command it should not; cross-site
request forgery or framing; anything letting an unauthenticated caller reach
a protected page, or an account do what its role does not allow.

Out of scope: vulnerabilities in NX-OS or NX-API themselves (report those to
[Cisco PSIRT](https://sec.cloudapps.cisco.com/security/center/resources/security_vulnerability_policy.html));
anything requiring an attacker to already have an NXray admin password or
the switch's admin login; running NXray exposed to the internet against this
document's advice.
