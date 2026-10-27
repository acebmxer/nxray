#!/bin/bash
# Container entrypoint: plain HTTP straight from the app (the default), or
# built-in HTTPS with nginx in front when NXRAY_ENABLE_HTTPS=true.
set -euo pipefail

if [ "$#" -gt 0 ]; then
    # A command was given (docker compose run --rm nxray python -m app.hashpw):
    # run exactly that.
    exec "$@"
fi

# Reads the setting the same way the app does, and with HTTPS on makes the
# self-signed certificate (first start only) and nginx's config.
mode="$(python -m app.tls)"

if [ "$mode" != "https" ]; then
    # Exactly as before built-in HTTPS existed: the app answers port 8080.
    exec uvicorn app.main:app --host 0.0.0.0 --port 8080 --no-proxy-headers
fi

# The app moves to a port only reachable inside the container; nginx holds
# 8080 (redirect to HTTPS) and 8443 (HTTPS). The app believes the visitor's
# address that nginx passes on, and only from nginx (127.0.0.1).
uvicorn app.main:app --host 127.0.0.1 --port 8081 \
    --proxy-headers --forwarded-allow-ips 127.0.0.1 &
app_pid=$!
nginx -c /tmp/nginx/nginx.conf -g "daemon off;" &
nginx_pid=$!

stop() {
    kill -TERM "$app_pid" "$nginx_pid" 2>/dev/null || true
    wait "$app_pid" "$nginx_pid" 2>/dev/null || true
}
trap 'stop; exit 0' TERM INT

# If either stops, stop the other too and let Docker's restart policy start
# the container again, rather than run half of it.
set +e
wait -n "$app_pid" "$nginx_pid"
status=$?
echo "nxray: $( kill -0 "$app_pid" 2>/dev/null && echo nginx || echo the app ) stopped (status $status); stopping the container" >&2
stop
exit "$status"
