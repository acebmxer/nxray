# NXray container image.
#
# Two stages: dependencies are installed into a virtualenv in the build stage
# and only that virtualenv is copied forward. The runtime image carries no
# pip, setuptools or wheel, so nothing in it can install packages, and pip's
# vendored bundle stays out of vulnerability scans.
FROM python:3.14-slim AS build

# Debian's security point-release fixes for the base OS packages, on every
# build rather than whenever Docker Hub refreshes the slim tag.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv/nxray

# Built at the path it occupies at runtime, so shebangs and the recorded
# prefix stay correct after the copy.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Dependencies first: this layer is rebuilt only when pyproject.toml changes.
COPY pyproject.toml README.md LICENSE ./
COPY app/__init__.py ./app/
RUN pip install --no-cache-dir .

RUN pip uninstall --yes pip setuptools wheel 2>/dev/null || true


FROM python:3.14-slim

# Same upgrade as the build stage; this is the stage that ships. nginx is
# for built-in HTTPS (NXRAY_ENABLE_HTTPS, off by default): it sits in front of
# the app only when that setting is on; see docker/entrypoint.sh. Debian's
# package enables a system service and log directories nothing here uses.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends nginx \
    && rm -rf /var/lib/apt/lists/* /etc/nginx/sites-enabled /etc/nginx/conf.d

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    NXRAY_DATA_DIR=/data

WORKDIR /srv/nxray

# The base image's own pip goes too: nothing installs at runtime.
RUN python -m pip uninstall --yes pip 2>/dev/null || true \
    && rm -rf /usr/local/lib/python3.14/site-packages/pip \
              /usr/local/lib/python3.14/site-packages/pip-*.dist-info \
              /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.14

COPY --from=build /opt/venv /opt/venv
COPY app/ ./app/
COPY docker/nginx.conf.template /etc/nxray/nginx.conf.template
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/nxray-entrypoint

# Non-root throughout, nginx included (8080 and 8443 are unprivileged ports).
# The data volume is chowned so the app can write the SQLite database, the
# session signing key and, with HTTPS on, the certificate to it.
RUN useradd --system --create-home --uid 10001 nxray \
    && mkdir -p /data \
    && chown -R nxray:nxray /data /srv/nxray
USER nxray

VOLUME ["/data"]
# 8080: the app over plain HTTP, or with HTTPS on, a redirect to 8443.
EXPOSE 8080 8443

# With HTTPS on this asks nginx, not just the app behind it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-m", "app.healthcheck"]

ENTRYPOINT ["/usr/local/bin/nxray-entrypoint"]
