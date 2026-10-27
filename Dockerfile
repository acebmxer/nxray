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

# Same upgrade as the build stage; this is the stage that ships.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

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

# Non-root throughout. The data volume is chowned so the app can write the
# SQLite database and the session signing key to it.
RUN useradd --system --create-home --uid 10001 nxray \
    && mkdir -p /data \
    && chown -R nxray:nxray /data /srv/nxray
USER nxray

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
