# Configuration

[← back to the README](../README.md)

Every setting lives in `nxray.env`, next to `docker-compose.yml`. The
commented template is `nxray.env.example`. After changing a value, apply it
with `docker compose up -d`.

NXray checks every value at start. A missing or invalid one stops it with a
message naming the setting; see `docker compose logs nxray`.

| Setting | Default | What it does |
| --- | --- | --- |
| `NXRAY_ADMIN_USER` | `admin` | The name of the first NXray account, an admin, made on the very first start. Read only while NXray has no accounts yet; later accounts are added on the Users page. |
| `NXRAY_ADMIN_PASSWORD_HASH` | none, required | Argon2id hash of that first account's password, from `docker compose run --rm nxray python -m app.hashpw`. Never the password itself. Like the name, it is used once: changing it later does not change any password (use the Account page, the Users page, or `python -m app.resetpw`, see [Installation](installation.md#forgotten-password)). |
| `NXRAY_SECRET_KEY` | generated | Signs session cookies. Left blank, one is generated on first start and kept in `/data/secret_key`. Changing it logs everyone out and makes the stored switch login unreadable, so the switch has to be set up again. Two-factor keys become unreadable too: those accounts sign in with a backup code, or an admin turns two-factor off for them on the Users page. So do the alert e-mail password and webhooks: type the password and add the webhooks again on the Alerts page. |
| `NXRAY_ENABLE_HTTPS` | `false` | Built-in HTTPS. When `true`, NXray makes a self-signed certificate on its first start (kept in `/data/tls`; upload your own on the Settings page), answers HTTPS on port 8443 and redirects plain HTTP on 8080 there. Needs the `8443:8443` line in the compose file's ports. Also turns on `NXRAY_HTTPS`. See [Installation](installation.md#https). |
| `NXRAY_HTTPS_PORT` | `8443` | The port browsers use for HTTPS, where plain-HTTP visits are sent: the left number of the `8443` line in the compose file. Only change it when you change that number. |
| `NXRAY_HTTPS` | `false`, or `true` with built-in HTTPS | Set to `true` when NXray is served over HTTPS by a reverse proxy of your own, so the session cookie is marked Secure. Left `true` on plain HTTP, signing in appears to fail. |
| `NXRAY_ENABLE_SELF_UPDATE` | `false` | Self-update. When `true`, NXray checks ghcr.io once a day for a newer image and an admin can press **Update now** on the Settings page, and choose **Include beta versions** there (stored in the database, not here). Needs the `docker.sock` mount and `group_add` lines in the compose file. The Docker socket is root on the host: see [Installation](installation.md#self-update). |
| `NXRAY_HISTORY_INTERVAL` | `60` | Seconds between history samples, 10 to 3600; `0` turns history off. Each sample is four read-only commands the dashboard and the Ports page run, sent to every switch NXray has, one after the other, and what alerts are checked against: with `0`, no problem is alerted on. 30 days are kept. See [Installation](installation.md#history) and [Alerts](installation.md#alerts). |
| `NXRAY_LIVE_MIN_INTERVAL` | `2` | Fewest seconds, 1 to 60, between two reads of a switch for the self-refreshing switch health and port figures. Applies to all browsers together: ten pages open still cost the switch one read per interval. What a browser picks below this is raised to it. See [Live figures](live.md). |
| `NXRAY_LIVE_CLIENTS_MIN_INTERVAL` | `10` | The same for the MAC address and ARP tables on the Neighbors page, 1 to 300, kept slower because they cost the switch more and change less often. |
| `NXRAY_DEV_BUILD` | empty | Set by `docker-compose.dev.yml` when the image is built from a clone, never by hand. An image built from source is not compared with the published one. |
| `NXRAY_SESSION_HOURS` | `12` | How long a session lasts without use, 1 to 720 hours. |
| `NXRAY_LOGIN_MAX_ATTEMPTS` | `5` | Failed sign-ins from one address before it is blocked, 1 to 100. |
| `NXRAY_LOGIN_LOCKOUT_MINUTES` | `15` | How long that block lasts, and the window failures are counted in, 1 to 1440 minutes. |
| `NXRAY_DATA_DIR` | `/data` | Where the database, session key and certificate live inside the container. Normally left alone; change the volume in the compose file instead. |
| `NXRAY_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR`. |

The switch address and NXray's switch account are not set here. They are
entered on the Switch page, which can also change the address later; see
[Switch setup](switch-setup.md).

The mail server, the addresses and the webhooks alerts go to are not set
here either: an admin sets them, and what is alerted on, on the Alerts page;
see [Installation](installation.md#alerts).
