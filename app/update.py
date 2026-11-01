"""Self-update: check GHCR for a newer image and have Docker apply it.

Off unless NXRAY_ENABLE_SELF_UPDATE is true. Applying needs the Docker socket
mounted into the container, which is effectively root on the host, so nothing
here talks to Docker or the registry unless an operator turned it on and the
route that calls it is admin-only.

How it works, and why:

- What is deployed is read from the running container through the socket
  (``docker inspect``), not remembered in the database, so a manual
  ``docker compose pull && up -d`` on the host cannot make the two disagree.
  Image digests are compared, never version strings.
- The tag watched is the one the container was started from (a ``:latest``
  install follows every release, a pinned ``:0.1.0`` stays put), unless
  **Include beta versions** is on or a beta is running. Then versions are
  compared instead, ranked from GitHub's list of releases
  (``pick_target``): a beta is only ever offered while it is ahead of the
  latest release, and nothing older than what runs is ever offered, so no
  install runs an older build against a database a newer one migrated.
- The tag chosen reaches compose as ``NXRAY_TAG`` in the throwaway
  container's environment, which the sample compose file's
  ``image: ghcr.io/acebmxer/nxray:${NXRAY_TAG:-latest}`` line reads. Nothing
  on the host is edited; a compose file that names a fixed tag ignores it,
  and the result says so (``_off_target``).
- A container cannot reliably replace itself, so the pull and recreation are
  handed to a throwaway container outside the compose project. It is told the
  project name, directory and compose files from the labels compose put on
  this container, so there is nothing for the operator to configure beyond
  the socket.
- The process that starts an update does not survive to see it finish, so the
  replacement container confirms success when it starts
  (``finish_pending_update``).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import app
from app.config import Settings

log = logging.getLogger("nxray.update")

_OWNER = "acebmxer"
_IMAGE = "nxray"
_REGISTRY_REPO = f"ghcr.io/{_OWNER}/{_IMAGE}"
_RELEASES_URL = f"https://api.github.com/repos/{_OWNER}/{_IMAGE}/releases?per_page=100"
# The two channels: every release moves :latest (release.yml), every beta
# moves :beta (beta.yml).
RELEASE_TAG = "latest"
BETA_TAG = "beta"
# 0.2.0, v0.2.0, 0.2.0-beta.3, v0.2.0-beta.3: what release.yml and beta.yml name.
_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-beta\.(\d+))?$")
# A Docker tag, which is what NXRAY_TAG may hold.
_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_CHECK_INTERVAL = 86400  # once a day
# "Update applied" stays on the page this long. Failures do not expire: they
# describe something that is still true.
_SUCCESS_TTL = 1800
# The throwaway container that pulls and recreates; its exited container is
# kept (no --rm) so its exit code and logs can be read.
_UPDATER_NAME = "nxray_updater"
_RECREATE_TIMEOUT = 300

# Labels docker compose puts on every container it creates.
_LABEL_PROJECT = "com.docker.compose.project"
_LABEL_WORKDIR = "com.docker.compose.project.working_dir"
_LABEL_FILES = "com.docker.compose.project.config_files"


@dataclass(frozen=True)
class Deployment:
    """What the running container was made from, as Docker reports it."""

    image_id: str
    image_ref: str  # as written in compose, e.g. ghcr.io/acebmxer/nxray:latest
    project: str
    workdir: str
    config_files: tuple[str, ...]

    @property
    def tag(self) -> str | None:
        """The tag watched, or None when this is not the published image."""
        repo, _, tag = self.image_ref.rpartition(":")
        if repo != _REGISTRY_REPO or not tag or "/" in tag:
            return None
        return tag


@dataclass(frozen=True)
class UpdateState:
    """One row of update_state, for the page."""

    latest_digest: str
    latest_checked_at: float | None
    available: bool
    in_progress: bool
    last_result: str
    include_beta: bool = False
    target_tag: str = ""  # the tag Update now moves to
    target_version: str = ""  # the version on it, when versions were compared


@dataclass(frozen=True)
class Target:
    """Where an update goes: a tag, and the version it holds."""

    tag: str
    version: str


Version = tuple[int, int, int, int, int]


def parse_version(text: str) -> Version | None:
    """A sortable key for an NXray version, or None for anything else.

    Version numbers first, then a release above every beta of its version:
    0.1.1 > 0.1.1-beta.3 > 0.1.1-beta.2 > 0.1.0.
    """
    match = _VERSION_RE.match(text.strip())
    if not match:
        return None
    major, minor, patch, beta = match.groups()
    if beta is None:
        return (int(major), int(minor), int(patch), 1, 0)
    return (int(major), int(minor), int(patch), 0, int(beta))


def is_beta(text: str) -> bool:
    """Whether a version names a beta."""
    key = parse_version(text)
    return key is not None and key[3] == 0


def running_version() -> str:
    """The version of the code in this container.

    Comes from the image itself: a beta image is built with its beta name
    (beta.yml passes it to the Dockerfile), so it cannot disagree with what
    is deployed.
    """
    return app.__version__


def pick_target(running: str, releases: list[str], include_beta: bool) -> Target | None:
    """The tag to move to, or None when nothing newer than ``running`` is out.

    ``releases`` are the published version names (betas included). With
    betas on, :beta while the newest beta is ahead of the latest release,
    else :latest. Only a newer version is ever offered.
    """
    current = parse_version(running)
    if current is None:
        return None
    newest_release: tuple[Version, str] | None = None
    newest_beta: tuple[Version, str] | None = None
    for name in releases:
        key = parse_version(name)
        if key is None:
            continue
        entry = (key, name.strip().removeprefix("v"))
        if key[3] == 0:
            newest_beta = max(newest_beta or entry, entry)
        else:
            newest_release = max(newest_release or entry, entry)
    choice: Target | None = None
    choice_key: Version | None = None
    if newest_release:
        choice_key, choice = newest_release[0], Target(RELEASE_TAG, newest_release[1])
    if include_beta and newest_beta and (choice_key is None or newest_beta[0] > choice_key):
        choice_key, choice = newest_beta[0], Target(BETA_TAG, newest_beta[1])
    if choice is None or choice_key is None or choice_key <= current:
        return None
    return choice


def _row(conn: sqlite3.Connection) -> sqlite3.Row:
    conn.execute("INSERT OR IGNORE INTO update_state (id) VALUES (1)")
    conn.commit()
    return conn.execute("SELECT * FROM update_state WHERE id = 1").fetchone()


def _set(conn: sqlite3.Connection, **fields: object) -> None:
    conn.execute("INSERT OR IGNORE INTO update_state (id) VALUES (1)")
    columns = ", ".join(f"{name} = ?" for name in fields)
    conn.execute(f"UPDATE update_state SET {columns} WHERE id = 1", tuple(fields.values()))
    conn.commit()


def _set_result(conn: sqlite3.Connection, value: str) -> None:
    _set(conn, last_result=value, last_result_at=time.time())


def current_state(conn: sqlite3.Connection) -> UpdateState:
    """The update state worth showing, with a stale success hidden."""
    row = _row(conn)
    last_result = row["last_result"] or ""
    if last_result == "success":
        stamped = row["last_result_at"]
        if not stamped or time.time() - stamped >= _SUCCESS_TTL:
            last_result = ""
    return UpdateState(
        latest_digest=row["latest_digest"] or "",
        latest_checked_at=row["latest_checked_at"],
        available=bool(row["available"]),
        in_progress=bool(row["in_progress"]),
        last_result=last_result,
        include_beta=bool(row["include_beta"]),
        target_tag=row["target_tag"] or "",
        target_version=row["target_version"] or "",
    )


def set_include_beta(conn: sqlite3.Connection, include: bool) -> None:
    """Store the Include beta versions choice. It installs nothing by itself.

    Any update found under the old choice is dropped, so a check that then
    cannot reach GitHub does not leave it on offer.
    """
    _set(conn, include_beta=1 if include else 0, available=0, target_tag="", target_version="")


def clear_result(conn: sqlite3.Connection) -> None:
    """Drop the recorded outcome so the page stops showing it."""
    _set_result(conn, "")


def _docker(args: list[str], timeout: int = 30) -> str | None:
    """Run the docker CLI; trimmed stdout, or None on any failure."""
    try:
        proc = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def own_container() -> str:
    """How this process names its own container to Docker.

    Docker sets a container's hostname to its short ID unless the compose
    file overrides it, so this survives a renamed container_name.
    """
    return socket.gethostname()


def deployment() -> Deployment | None:
    """Ask Docker what this container runs, or None if it can't be told."""
    raw = _docker(["inspect", own_container()])
    if not raw:
        return None
    try:
        info = json.loads(raw)[0]
        config = info["Config"]
        labels = config.get("Labels") or {}
        files = tuple(f for f in (labels.get(_LABEL_FILES) or "").split(",") if f)
        return Deployment(
            image_id=info["Image"],
            image_ref=config["Image"],
            project=labels.get(_LABEL_PROJECT, ""),
            workdir=labels.get(_LABEL_WORKDIR, ""),
            config_files=files,
        )
    except (ValueError, KeyError, IndexError, TypeError):
        return None


def deployed_digests(image_id: str) -> set[str] | None:
    """Registry digests of the image the container runs.

    None when it has none: an image built locally, never pulled from GHCR.
    """
    raw = _docker(["image", "inspect", image_id, "--format", "{{json .RepoDigests}}"])
    if not raw:
        return None
    try:
        entries = json.loads(raw)
    except ValueError:
        return None
    prefix = f"{_REGISTRY_REPO}@"
    digests = {e[len(prefix) :] for e in entries if e.startswith(prefix)}
    return digests or None


def ghcr_digest(tag: str) -> str | None:
    """The digest GHCR has for a tag, or None on any error.

    A network failure and an image that was never published both return None
    and leave the recorded state alone: nothing was checked, so nothing is
    reported.
    """
    try:
        token_url = f"https://ghcr.io/token?scope=repository:{_OWNER}/{_IMAGE}:pull&service=ghcr.io"
        with urllib.request.urlopen(token_url, timeout=15) as r:
            token = json.loads(r.read())["token"]
        req = urllib.request.Request(
            f"https://ghcr.io/v2/{_OWNER}/{_IMAGE}/manifests/{tag}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": (
                    "application/vnd.oci.image.index.v1+json,"
                    "application/vnd.oci.image.manifest.v1+json,"
                    "application/vnd.docker.distribution.manifest.list.v2+json,"
                    "application/vnd.docker.distribution.manifest.v2+json"
                ),
            },
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.headers.get("Docker-Content-Digest")
    except Exception as exc:
        log.debug("GHCR digest check failed: %s", exc)
        return None


def github_releases() -> list[str] | None:
    """The version names of NXray's published releases and betas, or None on any error.

    Drafts are left out; they are not published.
    """
    try:
        req = urllib.request.Request(
            _RELEASES_URL,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "nxray-update-check"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            entries = json.loads(r.read())
        return [
            str(e["tag_name"])
            for e in entries
            if isinstance(e, dict) and not e.get("draft") and e.get("tag_name")
        ]
    except Exception as exc:
        log.debug("GitHub releases check failed: %s", exc)
        return None


def check_for_updates(conn: sqlite3.Connection, *, dev_build: bool = False) -> str:
    """Compare GHCR with what runs, record it, and say what happened.

    Returns "available", "current" or a sentence saying why nothing could be
    compared. A failed check keeps what was recorded: one attempt that could
    not reach the registry must not retract a real pending update.

    A dev build never reports an update: it is built from source, so its
    digest differs from the published one whether it is behind or ahead.

    With betas on, or a beta running, versions are compared (``pick_target``)
    instead of the digest of this container's own tag.
    """
    _set(conn, latest_checked_at=time.time())

    current = deployment()
    if current is None:
        return "Docker did not answer. Is the Docker socket mounted into the container?"
    tag = current.tag
    if tag is None:
        return (
            f"This container runs {current.image_ref}, not an image published at "
            f"{_REGISTRY_REPO}, so there is nothing to compare it with."
        )

    include_beta = bool(_row(conn)["include_beta"])
    if include_beta or is_beta(running_version()):
        return _check_by_version(conn, current, include_beta, dev_build=dev_build)

    digest = ghcr_digest(tag)
    if digest is None:
        return "Could not reach ghcr.io, or no image has been published there yet."
    _set(conn, latest_digest=digest)

    deployed = deployed_digests(current.image_id)
    if dev_build or deployed is None:
        return _SOURCE_BUILD

    available = digest not in deployed
    _set(
        conn,
        available=1 if available else 0,
        target_tag=tag if available else "",
        target_version="",
    )
    return "available" if available else "current"


_SOURCE_BUILD = (
    "This is an image built from source, so it is never compared with the published one."
)


def _check_by_version(
    conn: sqlite3.Connection, current: Deployment, include_beta: bool, *, dev_build: bool
) -> str:
    """The check with betas in the picture: rank versions, never digests."""
    running = running_version()
    if parse_version(running) is None:
        return f"NXray cannot read its own version ({running}), so it cannot rank the releases."
    if dev_build or deployed_digests(current.image_id) is None:
        return _SOURCE_BUILD
    releases = github_releases()
    if releases is None:
        return "Could not reach api.github.com to read the list of NXray releases."
    target = pick_target(running, releases, include_beta)
    if target is None:
        _set(conn, available=0, target_tag="", target_version="")
        return "current"
    _set(conn, available=1, target_tag=target.tag, target_version=target.version)
    return "available"


def _off_target(conn: sqlite3.Connection) -> str | None:
    """Why the container is not on the tag the update chose, or None when it is.

    A compose file that names a fixed tag ignores NXRAY_TAG, so the pull and
    recreation can succeed without moving the container anywhere.
    """
    wanted = _row(conn)["target_tag"] or ""
    if not wanted:
        return None
    now = deployment()
    if now is None or now.tag is None or now.tag == wanted:
        return None
    return (
        f"NXray is still on :{now.tag}, not :{wanted}. The image: line in "
        "docker-compose.yml names a fixed tag, so it ignores the one chosen here. "
        f"Change that line to image: {_REGISTRY_REPO}:${{NXRAY_TAG:-latest}} on the host, "
        "then press Update now again."
    )


def _recreate_script(current: Deployment) -> str:
    """The shell line the throwaway container runs."""
    base = ["docker", "compose", "-p", current.project]
    for path in current.config_files:
        base += ["-f", path]
    return f"{shlex.join([*base, 'pull'])} && {shlex.join([*base, 'up', '-d'])}"


def _spawn_recreator(current: Deployment, tag: str) -> str | None:
    """Start the throwaway container that pulls and recreates. None, or an error.

    It runs the image being updated (it carries the docker CLI and compose
    plugin), with the project directory mounted at its own host path so
    compose finds the same files and relative paths the original ``up`` did.
    It is not root: it gets this process's supplementary groups, which is how
    the socket's docker group reaches it (see docker-compose.yml.example).
    ``tag`` reaches compose as NXRAY_TAG, which takes priority over a .env on
    the host.
    """
    _docker(["rm", "-f", _UPDATER_NAME])
    group_args: list[str] = []
    for gid in os.getgroups():
        group_args += ["--group-add", str(gid)]
    try:
        launch = subprocess.run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                _UPDATER_NAME,
                *group_args,
                "-v",
                "/var/run/docker.sock:/var/run/docker.sock",
                "-v",
                f"{current.workdir}:{current.workdir}",
                "-w",
                current.workdir,
                "-e",
                f"NXRAY_TAG={tag}",
                "--entrypoint",
                "sh",
                current.image_ref,
                "-c",
                _recreate_script(current),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return str(exc)[:300]
    if launch.returncode != 0:
        return (launch.stderr or launch.stdout or "unknown error").strip()[:300]
    return None


def finish_pending_update(conn: sqlite3.Connection) -> None:
    """At startup: an update still marked in progress means this is the replacement.

    The previous container was stopped by the recreation and the new image is
    running, the only trustworthy confirmation there is.
    """
    if not current_state(conn).in_progress:
        return
    wrong_tag = _off_target(conn)
    if wrong_tag:
        _set(conn, in_progress=0)
        _set_result(conn, wrong_tag)
        log.warning("update recreated the container, but not on the tag chosen")
        return
    _set(conn, available=0, in_progress=0)
    _set_result(conn, "success")
    log.info("update completed; running the recreated container")


def reap_stalled_update(conn: sqlite3.Connection) -> None:
    """Fail an update that started but never replaced this container."""
    row = _row(conn)
    if not row["in_progress"] or not row["started_at"]:
        return
    if time.time() - row["started_at"] < _RECREATE_TIMEOUT + 30:
        return
    _set(conn, in_progress=0)
    _set_result(
        conn,
        "the image was pulled but the container was not recreated. "
        "Run `docker compose up -d` on the host to finish.",
    )
    log.warning("update stalled: the container was not recreated in time")


def start_update(conn: sqlite3.Connection) -> str | None:
    """Mark an update in progress and start the recreator. None, or an error.

    On error nothing stays marked in progress. Returns once the recreator is
    launched; whether it worked is learned later (``watch_update``, or the
    replacement container's start).
    """
    current = deployment()
    if current is None:
        return "Docker did not answer. Is the Docker socket mounted into the container?"
    if current.tag is None:
        return (
            f"This container runs {current.image_ref}, not an image published at {_REGISTRY_REPO}."
        )
    if not current.project or not current.workdir:
        return (
            "This container was not started by docker compose (it has no compose "
            "labels), so there is no project to recreate."
        )
    if not Path(current.workdir).is_absolute():
        return "Docker reported a project directory that is not an absolute path."
    tag = _row(conn)["target_tag"] or current.tag
    if not _TAG_RE.match(tag):
        return f"{tag!r} is not a Docker tag."

    _set(conn, in_progress=1, started_at=time.time(), target_tag=tag)
    _set_result(conn, "")
    error = _spawn_recreator(current, tag)
    if error:
        _set(conn, in_progress=0)
        _set_result(conn, f"could not start the update: {error}")
        return error
    return None


def _summarise_logs(text: str) -> str:
    """The lines worth showing from the recreator's output.

    Compose repeats its errors and adds bare words ("denied") on lines of
    their own, so: the distinct lines mentioning an error if there are any,
    else the distinct last lines, in order.
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    errors = [line for line in lines if "error" in line.lower()]
    chosen = list(dict.fromkeys(errors or lines[-5:]))
    return " | ".join(chosen)


def watch_update(db_path: Path) -> None:
    """Wait for the recreator to finish, and record a failure.

    Runs on its own thread with its own connection. Normally this process is
    stopped by the recreation and never gets here, which is why the success is
    recorded by the replacement container instead. It does survive when the
    recreator fails, or when nothing needed replacing; then it records that.
    """
    from app.db import connect  # local import: avoids a cycle at import time

    conn = connect(db_path)
    try:
        try:
            wait = subprocess.run(
                ["docker", "wait", _UPDATER_NAME],
                capture_output=True,
                text=True,
                timeout=_RECREATE_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            _set(conn, in_progress=0)
            _set_result(
                conn,
                f"the update is still running after {_RECREATE_TIMEOUT}s. "
                f"Check `docker logs {_UPDATER_NAME}` on the host.",
            )
            return
        code = (wait.stdout or "").strip()
        if wait.returncode == 0 and code == "0":
            _docker(["rm", _UPDATER_NAME])
            wrong_tag = _off_target(conn)
            if wrong_tag:
                _set(conn, in_progress=0)
                _set_result(conn, wrong_tag)
                return
            _set(conn, available=0, in_progress=0)
            _set_result(conn, "success")
            return
        logs = subprocess.run(
            ["docker", "logs", "--tail", "30", _UPDATER_NAME],
            capture_output=True,
            text=True,
            timeout=30,
        )
        detail = _summarise_logs((logs.stderr or "") + (logs.stdout or ""))
        detail = detail or f"the updater exited with code {code or wait.returncode}"
        _set(conn, in_progress=0)
        _set_result(conn, detail[:300])
    except Exception as exc:
        log.exception("watching the update failed")
        _set(conn, in_progress=0)
        _set_result(conn, f"error: {str(exc)[:200]}")
    finally:
        conn.close()


def apply_update(db_path: Path) -> str | None:
    """Start an update and watch it on a background thread. None, or an error."""
    from app.db import connect

    conn = connect(db_path)
    try:
        error = start_update(conn)
    finally:
        conn.close()
    if error is None:
        threading.Thread(target=watch_update, args=(db_path,), daemon=True, name="update").start()
    return error


def start_background_checker(settings: Settings) -> None:
    """Check once a day on its own thread. A no-op unless self-update is on.

    This is the only call NXray makes to anywhere but the switch, so it is
    part of the opt-in rather than something every install does.
    """
    if not settings.enable_self_update:
        return

    from app.db import connect

    def _loop() -> None:
        time.sleep(300)  # let the app settle before the first outside call
        conn = connect(settings.db_path)
        try:
            while True:
                try:
                    check_for_updates(conn, dev_build=settings.dev_build)
                except Exception:
                    log.exception("background update check failed")
                time.sleep(_CHECK_INTERVAL)
        finally:
            conn.close()

    threading.Thread(target=_loop, daemon=True, name="update-checker").start()
