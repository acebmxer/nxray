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


# ---- versions and channels ----------------------------------------------------------------


@pytest.fixture
def releases(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The version names GitHub lists; empty the list's contents to change them."""
    names = ["v0.1.0", "v0.1.1-beta.1", "v0.1.1-beta.2", "v0.1.1"]
    monkeypatch.setattr(update, "github_releases", lambda: names)
    return names


def _running(monkeypatch: pytest.MonkeyPatch, version: str) -> None:
    monkeypatch.setattr(update, "running_version", lambda: version)


def test_versions_rank_by_number_then_beta_with_a_release_above_its_betas() -> None:
    names = ["0.1.1-beta.2", "0.1.0", "v0.1.1", "0.1.1-beta.3", "0.1.1-beta.10", "0.2.0-beta.1"]
    ranked = sorted(names, key=lambda n: update.parse_version(n) or ())
    assert ranked == [
        "0.1.0",
        "0.1.1-beta.2",
        "0.1.1-beta.3",
        "0.1.1-beta.10",
        "v0.1.1",
        "0.2.0-beta.1",
    ]
    assert update.parse_version("latest") is None
    assert update.parse_version("0.1") is None
    assert update.is_beta("0.2.0-beta.1") and not update.is_beta("0.2.0")


def test_with_betas_on_a_beta_ahead_of_the_release_is_picked() -> None:
    target = update.pick_target("0.1.1", ["v0.1.1", "v0.2.0-beta.1", "v0.2.0-beta.2"], True)
    assert target == update.Target("beta", "0.2.0-beta.2")


def test_with_betas_on_a_release_that_caught_up_is_picked_over_its_betas() -> None:
    target = update.pick_target("0.2.0-beta.2", ["v0.2.0-beta.2", "v0.2.0"], True)
    assert target == update.Target("latest", "0.2.0")


def test_an_older_beta_is_never_offered_after_its_release() -> None:
    assert update.pick_target("0.1.1", ["v0.1.1-beta.3", "v0.1.1"], True) is None


def test_with_betas_off_betas_are_ignored() -> None:
    assert update.pick_target("0.1.1", ["v0.1.1", "v0.2.0-beta.1"], False) is None
    target = update.pick_target("0.1.0", ["v0.1.1", "v0.2.0-beta.1"], False)
    assert target == update.Target("latest", "0.1.1")


def test_betas_off_on_a_beta_newer_than_the_release_stays_put() -> None:
    assert update.pick_target("0.2.0-beta.1", ["v0.1.1", "v0.2.0-beta.1"], False) is None
    target = update.pick_target("0.2.0-beta.1", ["v0.1.1", "v0.2.0"], False)
    assert target == update.Target("latest", "0.2.0")


def test_betas_on_offers_beta_through_the_check(docker, releases, conn, monkeypatch) -> None:
    _running(monkeypatch, "0.1.1")
    releases.append("v0.2.0-beta.1")
    update.set_include_beta(conn, True)
    assert update.check_for_updates(conn) == "available"
    state = update.current_state(conn)
    assert state.include_beta and state.target_tag == "beta"
    assert state.target_version == "0.2.0-beta.1"


def test_betas_on_with_no_newer_beta_is_up_to_date(docker, releases, conn, monkeypatch) -> None:
    _running(monkeypatch, "0.1.1")
    update.set_include_beta(conn, True)
    assert update.check_for_updates(conn) == "current"
    state = update.current_state(conn)
    assert not state.available and state.target_tag == ""


def test_a_running_beta_compares_versions_even_with_betas_off(
    docker, releases, conn, monkeypatch
) -> None:
    monkeypatch.setattr(update, "ghcr_digest", lambda tag: pytest.fail("compared digests"))
    docker.image_ref = "ghcr.io/acebmxer/nxray:beta"
    _running(monkeypatch, "0.2.0-beta.1")
    assert update.check_for_updates(conn) == "current"
    releases.append("v0.2.0")
    assert update.check_for_updates(conn) == "available"
    assert update.current_state(conn).target_tag == "latest"


def test_github_not_answering_is_said_and_keeps_a_pending_update(
    docker, releases, conn, monkeypatch
) -> None:
    _running(monkeypatch, "0.1.0")
    update.set_include_beta(conn, True)
    assert update.check_for_updates(conn) == "available"
    monkeypatch.setattr(update, "github_releases", lambda: None)
    assert "api.github.com" in update.check_for_updates(conn)
    assert update.current_state(conn).available is True


def test_changing_the_choice_drops_an_update_found_under_the_old_one(
    docker, releases, conn, monkeypatch
) -> None:
    _running(monkeypatch, "0.1.1")
    releases.append("v0.2.0-beta.1")
    update.set_include_beta(conn, True)
    update.check_for_updates(conn)
    update.set_include_beta(conn, False)
    state = update.current_state(conn)
    assert not state.available and state.target_tag == ""


def test_a_dev_build_with_betas_on_is_never_out_of_date(
    docker, releases, conn, monkeypatch
) -> None:
    _running(monkeypatch, "0.1.0")
    update.set_include_beta(conn, True)
    assert "built from source" in update.check_for_updates(conn, dev_build=True)
    assert update.current_state(conn).available is False


def test_the_releases_list_leaves_out_drafts(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps(
        [
            {"tag_name": "v0.2.0-beta.2", "draft": True, "prerelease": True},
            {"tag_name": "v0.2.0-beta.1", "draft": False, "prerelease": True},
            {"tag_name": "v0.1.1", "draft": False, "prerelease": False},
        ]
    ).encode()

    class Answer:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self) -> bytes:
            return body

    seen: list[str] = []

    def fake_urlopen(req, timeout=0):
        seen.append(req.full_url)
        return Answer()

    monkeypatch.setattr(update.urllib.request, "urlopen", fake_urlopen)
    assert update.github_releases() == ["v0.2.0-beta.1", "v0.1.1"]
    assert seen == ["https://api.github.com/repos/acebmxer/nxray/releases?per_page=100"]


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


def _env(cmd: list[str]) -> list[str]:
    return [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"]


def test_the_recreator_is_told_the_container_s_own_tag_when_digests_are_compared(
    docker, registry, conn, monkeypatch
) -> None:
    update.check_for_updates(conn)
    seen = _capture_run(monkeypatch)
    assert update.start_update(conn) is None
    assert _env(seen[0]) == ["NXRAY_TAG=latest"]


def test_the_recreator_is_told_the_tag_betas_chose(docker, releases, conn, monkeypatch) -> None:
    _running(monkeypatch, "0.1.1")
    releases.append("v0.2.0-beta.1")
    update.set_include_beta(conn, True)
    update.check_for_updates(conn)
    seen = _capture_run(monkeypatch)
    assert update.start_update(conn) is None
    assert _env(seen[0]) == ["NXRAY_TAG=beta"]
    assert REF in seen[0], "the updater still runs the image this container has"


def test_a_tag_that_is_not_a_docker_tag_is_refused(docker, conn, monkeypatch) -> None:
    update._set(conn, target_tag="beta; rm -rf /")
    seen = _capture_run(monkeypatch)
    assert "not a Docker tag" in (update.start_update(conn) or "")
    assert seen == [] and update.current_state(conn).in_progress is False


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


def test_a_replacement_on_another_tag_says_the_compose_file_ignores_it(docker, conn) -> None:
    update._set(conn, in_progress=1, available=1, started_at=time.time(), target_tag="beta")
    update.finish_pending_update(conn)
    state = update.current_state(conn)
    assert not state.in_progress and state.available, "Update now stays on offer"
    assert "still on :latest, not :beta" in state.last_result
    assert "ghcr.io/acebmxer/nxray:${NXRAY_TAG:-latest}" in state.last_result


def test_a_replacement_on_the_chosen_tag_is_a_success(docker, conn) -> None:
    docker.image_ref = "ghcr.io/acebmxer/nxray:beta"
    update._set(conn, in_progress=1, available=1, started_at=time.time(), target_tag="beta")
    update.finish_pending_update(conn)
    assert update.current_state(conn).last_result == "success"


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


def test_a_recreator_that_succeeds_but_leaves_this_tag_says_why(tmp_path, monkeypatch) -> None:
    from app.db import init_db

    path = tmp_path / "w.db"
    init_db(path)
    with open_db(path) as c:
        update._set(c, in_progress=1, available=1, started_at=time.time(), target_tag="beta")
    monkeypatch.setattr(
        subprocess, "run", lambda cmd, **kw: SimpleNamespace(returncode=0, stdout="0", stderr="")
    )
    fake = FakeDocker()  # still on :latest: compose pinned it
    monkeypatch.setattr(update, "_docker", fake)
    monkeypatch.setattr(update, "own_container", lambda: "abc123")
    update.watch_update(path)
    with open_db(path) as c:
        state = update.current_state(c)
    assert not state.in_progress and "not :beta" in state.last_result


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
    for action in ("check", "apply", "dismiss", "beta"):
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
    for action in ("check", "apply", "dismiss", "beta"):
        assert admin.post(f"/settings/update/{action}", data={"csrf": "wrong"}).status_code == 403


def test_an_operator_cannot_use_the_update_routes(
    admin: TestClient, on: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    with open_db(on.db_path) as c:
        create_user(c, "otto", "another-long-password", "another-long-password", "operator")
    otto = make_client(on)
    otto.post("/login", data={"username": "otto", "password": "another-long-password"})
    token = _csrf(otto)
    for action in ("check", "apply", "dismiss", "beta"):
        assert otto.post(f"/settings/update/{action}", data={"csrf": token}).status_code == 403
    assert otto.get("/settings").status_code == 403


def test_the_card_has_the_beta_switch_off_by_default(admin: TestClient) -> None:
    page = admin.get("/settings").text
    assert 'action="/settings/update/beta"' in page
    assert re.search(r'name="include_beta" value="on"\s+>', page), "unticked by default"


def test_turning_betas_on_saves_checks_and_offers_the_beta(
    admin: TestClient, on: Settings, releases, registry, monkeypatch: pytest.MonkeyPatch
) -> None:
    _running(monkeypatch, "0.1.1")
    releases.append("v0.2.0-beta.1")
    response = admin.post(
        "/settings/update/beta", data={"csrf": _csrf(admin), "include_beta": "on"}
    )
    text = _text(response)
    assert response.status_code == 200
    assert "Beta versions are now included. NXray v0.2.0-beta.1 is available." in text
    assert "on the :beta tag" in text
    assert 'action="/settings/update/apply"' in response.text
    with open_db(on.db_path) as c:
        assert update.current_state(c).include_beta is True
        logged = c.execute("SELECT what FROM activity").fetchall()
    assert any("Include beta versions on" in row[0] for row in logged)

    # Off again on a release: back to comparing :latest's digest, which matches.
    registry["latest"] = OLD
    response = admin.post("/settings/update/beta", data={"csrf": _csrf(admin)})
    assert "Beta versions are now left out. NXray is up to date." in _text(response)
    assert "/settings/update/apply" not in response.text


def test_the_beta_switch_is_refused_while_an_update_runs(
    admin: TestClient, on: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    with open_db(on.db_path) as c:
        update._set(c, in_progress=1, started_at=time.time())
    monkeypatch.setattr(update, "check_for_updates", lambda *a, **k: pytest.fail("checked"))
    response = admin.post(
        "/settings/update/beta", data={"csrf": _csrf(admin), "include_beta": "on"}
    )
    assert response.status_code == 409 and "update is running" in response.text
    with open_db(on.db_path) as c:
        assert update.current_state(c).include_beta is False


def test_a_running_beta_with_betas_off_says_it_stays(
    admin: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _running(monkeypatch, "0.2.0-beta.1")
    from app.routes import settings_page

    monkeypatch.setattr(settings_page, "running_version", lambda: "0.2.0-beta.1")
    assert "This is a beta." in _text(admin.get("/settings"))
