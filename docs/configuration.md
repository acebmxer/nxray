# Configuration

[← back to the README](../README.md)

Every setting lives in `nxray.env`, next to `docker-compose.yml`. The
commented template is `nxray.env.example`. After changing a value, apply it
with `docker compose up -d`.

NXray checks every value at start. A missing or invalid one stops it with a
message naming the setting; see `docker compose logs nxray`.

| Setting | Default | What it does |
| --- | --- | --- |
| `NXRAY_ADMIN_USER` | `admin` | The username you sign in with. Changing it ends existing sessions. |
| `NXRAY_ADMIN_PASSWORD_HASH` | none, required | Argon2id hash of your password, from `docker compose run --rm nxray python -m app.hashpw`. Never the password itself. |
| `NXRAY_SECRET_KEY` | generated | Signs session cookies. Left blank, one is generated on first start and kept in `/data/secret_key`. Changing it logs everyone out and makes the stored switch login unreadable, so the switch has to be set up again. |
| `NXRAY_HTTPS` | `false` | Set to `true` when NXray is served over HTTPS by a reverse proxy, so the session cookie is marked Secure. Left `true` on plain HTTP, signing in appears to fail. |
| `NXRAY_SESSION_HOURS` | `12` | How long a session lasts without use, 1 to 720 hours. |
| `NXRAY_LOGIN_MAX_ATTEMPTS` | `5` | Failed sign-ins from one address before it is blocked, 1 to 100. |
| `NXRAY_LOGIN_LOCKOUT_MINUTES` | `15` | How long that block lasts, and the window failures are counted in, 1 to 1440 minutes. |
| `NXRAY_DATA_DIR` | `/data` | Where the database and session key live inside the container. Normally left alone; change the volume in the compose file instead. |
| `NXRAY_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR`. |

The switch address and NXray's switch account are not set here. They are
entered on the Switch page; see [Switch setup](switch-setup.md).
