"""Self-update: the check, the apply, and the Settings page card.

Docker and ghcr.io are replaced by fakes; nothing here touches a daemon or
the network.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app import update
from app.config import Settings, load_settings
from app.db import open_db
from app.users import create_user
from tests.conftest import TEST_PASSWORD, with_settings

REF = "ghcr.io/acebmxer/nxray:latest"
OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64
WORKDIR = "/srv/stacks/nxray"


class FakeDocker:
    """Answers the few docker commands app.update asks for."""

    def __init__(
        self,
        *,
        image_ref: str = REF,
        repo_digests: list[str] | None = None,
        labels: dict[str, str] | None = None,
        reachable: bool = True,
    ) -> None:
        self.image_ref = image_ref
        self.repo_digests = (
            repo_digests if repo_digests is not None else [f"ghcr.io/acebmxer/nxray@{OLD}"]
        )
        self.labels = (
            labels
            if labels is not None
            else {
                "com.docker.compose.project": "nxray",
                "com.docker.compose.project.working_dir": WORKDIR,
                "com.docker.compose.project.config_files": f"{WORKDIR}/docker-compose.yml",
            }
        )
        self.reachable = reachable
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], timeout: int = 30) -> str | None:
        self.calls.append(args)
        if not self.reachable:
            return None
        if args[0] == "inspect":
            config = {"Image": self.image_ref, "Labels": self.labels}
            return json.dumps([{"Image": "sha256:imageid", "Config": config}])
        if args[:2] == ["image", "inspect"]:
            return json.dumps(self.repo_digests)
        return ""


@pytest.fixture
def docker(monkeypatch: pytest.MonkeyPatch) -> FakeDocker:
    fake = FakeDocker()
    monkeypatch.setattr(update, "_docker", fake)
    monkeypatch.setattr(update, "own_container", lambda: "abc123")
    return fake


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch) -> dict[str, str | None]:
    """What ghcr.io answers per tag; a missing tag answers None (unreachable)."""
    answers: dict[str, str | None] = {"latest": NEW}
    monkeypatch.setattr(update, "ghcr_digest", lambda tag: answers.get(tag))
    return answers


@pytest.fixture
def conn(tmp_path: Path):
    from app.db import init_db

    path = tmp_path / "u.db"
    init_db(path)
    with open_db(path) as c:
        yield c


# ---- settings ---------------------------------------------------------------------------


def test_self_update_and_dev_build_are_off_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("NXRAY_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NXRAY_ADMIN_PASSWORD_HASH", "$argon2id$x")
    monkeypatch.delenv("NXRAY_ENABLE_SELF_UPDATE", raising=False)
    monkeypatch.setenv("NXRAY_DEV_BUILD", "")  # what the Dockerfile sets on a published image
    loaded = load_settings()
    assert loaded.enable_self_update is False
    assert loaded.dev_build is False


def test_self_update_and_dev_build_can_be_turned_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("NXRAY_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NXRAY_ADMIN_PASSWORD_HASH", "$argon2id$x")
    monkeypatch.setenv("NXRAY_ENABLE_SELF_UPDATE", "true")
    monkeypatch.setenv("NXRAY_DEV_BUILD", "true")
    loaded = load_settings()
    assert loaded.enable_self_update is True
    assert loaded.dev_build is True


# ---- the check --------------------------------------------------------------------------


def test_a_different_digest_on_ghcr_is_an_update(docker, registry, conn) -> None:
    assert update.check_for_updates(conn) == "available"
    state = update.current_state(conn)
    assert state.available and state.latest_digest == NEW and state.latest_checked_at


def test_the_same_digest_is_up_to_date_and_clears_a_pending_update(docker, registry, conn) -> None:
    update.check_for_updates(conn)
    registry["latest"] = OLD
    assert update.check_for_updates(conn) == "current"
    assert update.current_state(conn).available is False


def test_a_pinned_tag_is_checked_under_that_tag(docker, registry, conn) -> None:
    docker.image_ref = "ghcr.io/acebmxer/nxray:0.1.0"
    registry["0.1.0"] = OLD
    registry["latest"] = NEW
    assert update.check_for_updates(conn) == "current"


def test_a_dev_build_is_never_out_of_date(docker, registry, conn) -> None:
    assert update.check_for_updates(conn, dev_build=True) != "available"
    assert update.current_state(conn).available is False


def test_an_image_with_no_registry_digest_is_not_compared(docker, registry, conn) -> None:
    docker.repo_digests = []
    assert "never compared" in update.check_for_updates(conn)
    assert update.current_state(conn).available is False


def test_an_image_from_somewhere_else_is_not_compared(docker, registry, conn) -> None:
    docker.image_ref = "localhost/nxray:dev"
    assert "nothing to compare" in update.check_for_updates(conn)


def test_docker_not_answering_is_said_not_guessed(docker, registry, conn) -> None:
    docker.reachable = False
    assert "Docker socket" in update.check_for_updates(conn)


def test_an_unreachable_registry_keeps_a_pending_update(docker, registry, conn) -> None:
    update.check_for_updates(conn)
    registry.clear()
    assert "ghcr.io" in update.check_for_updates(conn)
    assert update.current_state(conn).available is True


# ---- applying ---------------------------------------------------------------------------


def _capture_run(monkeypatch: pytest.MonkeyPatch, returncode: int = 0, stderr: str = ""):
    seen: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        seen.append(cmd)
        return SimpleNamespace(returncode=returncode, stdout="abc\n", stderr=stderr)

    monkeypatch.setattr(subprocess, "run", fake_run)
    return seen


def test_the_recreator_runs_compose_for_this_project_in_its_folder(
    docker, conn, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(update.os, "getgroups", lambda: [10001, 998])
    seen = _capture_run(monkeypatch)
    assert update.start_update(conn) is None
    (cmd,) = seen
    assert cmd[:3] == ["docker", "run", "--detach"]
    assert cmd[cmd.index("--name") + 1] == "nxray_updater"
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "--group-add"] == ["10001", "998"]
    assert "/var/run/docker.sock:/var/run/docker.sock" in cmd
    assert f"{WORKDIR}:{WORKDIR}" in cmd and cmd[cmd.index("-w") + 1] == WORKDIR
    assert cmd[cmd.index("--entrypoint") + 1] == "sh", "the image's own entrypoint must not run"
    assert REF in cmd
    script = cmd[-1]
    assert script == (
        f"docker compose -p nxray -f {WORKDIR}/docker-compose.yml pull && "
        f"docker compose -p nxray -f {WORKDIR}/docker-compose.yml up -d"
    )
    assert update.current_state(conn).in_progress is True


def test_odd_compose_labels_cannot_inject_shell(docker, conn, monkeypatch) -> None:
    docker.labels["com.docker.compose.project.config_files"] = "/a b/c.yml;touch /x"
    seen = _capture_run(monkeypatch)
    update.start_update(conn)
    assert "'/a b/c.yml;touch /x'" in seen[0][-1]


def test_a_container_compose_did_not_start_is_refused(docker, conn, monkeypatch) -> None:
    docker.labels = {}
    seen = _capture_run(monkeypatch)
    assert "compose" in (update.start_update(conn) or "")
    assert seen == [] and update.current_state(conn).in_progress is False


def test_a_failed_launch_leaves_nothing_in_progress(docker, conn, monkeypatch) -> None:
    _capture_run(monkeypatch, returncode=125, stderr="permission denied")
    assert update.start_update(conn) == "permission denied"
    state = update.current_state(conn)
    assert not state.in_progress and "permission denied" in state.last_result


def test_the_replacement_container_records_the_success(conn) -> None:
    update._set(conn, in_progress=1, available=1, started_at=time.time())
    update.finish_pending_update(conn)
    state = update.current_state(conn)
    assert state.last_result == "success" and not state.in_progress and not state.available


def test_an_old_success_is_hidden_but_a_failure_is_not(conn) -> None:
    update._set(conn, last_result="success", last_result_at=time.time() - 7200)
    assert update.current_state(conn).last_result == ""
    update._set(conn, last_result="boom", last_result_at=time.time() - 7200)
    assert update.current_state(conn).last_result == "boom"


def test_an_update_that_never_replaced_the_container_is_failed(conn) -> None:
    update._set(conn, in_progress=1, started_at=time.time() - 3600)
    update.reap_stalled_update(conn)
    state = update.current_state(conn)
    assert not state.in_progress and "docker compose up -d" in state.last_result


def test_a_recent_update_is_left_running(conn) -> None:
    update._set(conn, in_progress=1, started_at=time.time())
    update.reap_stalled_update(conn)
    assert update.current_state(conn).in_progress is True


def _watch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, wait_code: str, logs: str = ""):
    from app.db import init_db

    path = tmp_path / "w.db"
    init_db(path)
    with open_db(path) as c:
        update._set(c, in_progress=1, available=1, started_at=time.time())

    def fake_run(cmd, **kwargs):
        if cmd[1] == "wait":
            return SimpleNamespace(returncode=0, stdout=wait_code, stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr=logs)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(update, "_docker", lambda args, timeout=30: "")
    update.watch_update(path)
    with open_db(path) as c:
        return update.current_state(c)


def test_a_recreator_that_fails_shows_its_own_message(tmp_path, monkeypatch) -> None:
    # What compose printed for a refused pull: errors repeated, with bare "denied" lines.
    logs = (
        " Image ghcr.io/acebmxer/nxray:latest Pulling \n"
        " Image ghcr.io/acebmxer/nxray:latest Error error from registry: denied\n"
        "denied\n"
        "Error response from daemon: error from registry: denied\n"
        "denied\n"
        "Error response from daemon: error from registry: denied\n"
    )
    state = _watch(tmp_path, monkeypatch, "1", logs=logs)
    assert not state.in_progress
    assert state.last_result == (
        "Image ghcr.io/acebmxer/nxray:latest Error error from registry: denied"
        " | Error response from daemon: error from registry: denied"
    )


def test_a_recreator_with_no_error_lines_shows_its_last_lines(tmp_path, monkeypatch) -> None:
    state = _watch(tmp_path, monkeypatch, "2", logs="one\ntwo\n")
    assert state.last_result == "one | two"


def test_a_recreator_that_succeeds_with_this_container_alive_is_a_success(
    tmp_path, monkeypatch
) -> None:
    state = _watch(tmp_path, monkeypatch, "0")
    assert state.last_result == "success" and not state.in_progress and not state.available


# ---- the Settings page ------------------------------------------------------------------


def _csrf(client: TestClient) -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get("/account").text)
    assert match
    return match.group(1)


@pytest.fixture
def on(settings: Settings) -> Settings:
    return with_settings(settings, enable_self_update=True)


@pytest.fixture
def admin(
    on: Settings, make_client: Callable[[Settings], TestClient], docker, registry
) -> TestClient:
    client = make_client(on)
    client.post("/login", data={"username": "admin", "password": TEST_PASSWORD})
    return client


def _text(response) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", response.text))


def test_with_self_update_off_the_page_explains_and_has_no_forms(logged_in: TestClient) -> None:
    text = _text(logged_in.get("/settings"))
    assert "NXRAY_ENABLE_SELF_UPDATE=true" in text
    assert "/settings/update" not in logged_in.get("/settings").text


def test_with_self_update_off_every_update_route_refuses(
    logged_in: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(update, "_docker", lambda *a, **k: pytest.fail("touched docker"))
    for action in ("check", "apply", "dismiss"):
        response = logged_in.post(f"/settings/update/{action}", data={"csrf": _csrf(logged_in)})
        assert response.status_code in (200, 400), action
        assert "Self-update is off" in response.text or action == "dismiss"


def test_the_card_shows_what_is_running_and_offers_a_check(admin: TestClient) -> None:
    text = _text(admin.get("/settings"))
    assert "Last checked not yet" in text
    assert 'action="/settings/update/check"' in admin.get("/settings").text
    assert "/settings/update/apply" not in admin.get("/settings").text


def test_check_now_then_update_now_starts_the_update(
    admin: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    started: list[Path] = []
    from app.routes import settings_page

    monkeypatch.setattr(settings_page, "apply_update", lambda path: started.append(path))
    response = admin.post("/settings/update/check", data={"csrf": _csrf(admin)})
    assert "A newer image is available" in _text(response)
    assert 'action="/settings/update/apply"' in response.text
    response = admin.post("/settings/update/apply", data={"csrf": _csrf(admin)})
    assert response.status_code == 200 and "Update started" in _text(response)
    assert len(started) == 1


def test_update_now_is_refused_when_nothing_is_waiting(admin: TestClient) -> None:
    response = admin.post("/settings/update/apply", data={"csrf": _csrf(admin)})
    assert response.status_code == 409 and "No update is available" in response.text


def test_update_now_is_refused_while_one_is_running(
    admin: TestClient, on: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    with open_db(on.db_path) as c:
        update._set(c, available=1, in_progress=1, started_at=time.time())
    from app.routes import settings_page

    monkeypatch.setattr(settings_page, "apply_update", lambda path: pytest.fail("started twice"))
    response = admin.post("/settings/update/apply", data={"csrf": _csrf(admin)})
    assert response.status_code == 409 and "already running" in response.text
    assert 'http-equiv="refresh"' in admin.get("/settings").text


def test_a_failure_shows_until_dismissed(admin: TestClient, on: Settings) -> None:
    with open_db(on.db_path) as c:
        update._set(c, last_result="pull access denied", last_result_at=time.time())
    assert "The update failed: pull access denied" in _text(admin.get("/settings"))
    admin.post("/settings/update/dismiss", data={"csrf": _csrf(admin)})
    assert "pull access denied" not in admin.get("/settings").text


def test_the_update_routes_need_a_csrf_token(admin: TestClient) -> None:
    for action in ("check", "apply", "dismiss"):
        assert admin.post(f"/settings/update/{action}", data={"csrf": "wrong"}).status_code == 403


def test_an_operator_cannot_use_the_update_routes(
    admin: TestClient, on: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    with open_db(on.db_path) as c:
        create_user(c, "otto", "another-long-password", "another-long-password", "operator")
    otto = make_client(on)
    otto.post("/login", data={"username": "otto", "password": "another-long-password"})
    token = _csrf(otto)
    for action in ("check", "apply", "dismiss"):
        assert otto.post(f"/settings/update/{action}", data={"csrf": token}).status_code == 403
    assert otto.get("/settings").status_code == 403
