"""The container's health check: exit 0 when NXray answers /healthz.

With built-in HTTPS on it asks nginx over HTTPS, so a stuck nginx in front of
a working app still counts as unhealthy. The certificate is not checked: it
may be the self-signed one, and this runs inside the same container anyway.
"""

from __future__ import annotations

import ssl
import urllib.request

from app.config import ConfigError, env_bool


def https_enabled() -> bool:
    """NXRAY_ENABLE_HTTPS, read by app.config.env_bool; ConfigError for a value the app refuses."""
    return env_bool("NXRAY_ENABLE_HTTPS", False)


def main() -> int:
    """Exit status for Docker's HEALTHCHECK."""
    try:
        https = https_enabled()
    except ConfigError:
        # The app refuses to start with this value, so nothing is healthy.
        return 1
    if https:
        url, context = "https://127.0.0.1:8443/healthz", ssl._create_unverified_context()
    else:
        url, context = "http://127.0.0.1:8080/healthz", None
    try:
        with urllib.request.urlopen(url, timeout=4, context=context) as response:
            return 0 if response.status == 200 else 1
    except OSError:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
