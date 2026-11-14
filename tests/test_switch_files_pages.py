"""The Files (#85), Software (#84) and Tech support (#86) pages, end to end against the
fake switch, and their parsers. Copies, deletes, checks, the install and tech-support need
the stored admin login and an NXray admin."""

from __future__ import annotations

import gzip
import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.nxapi import NxapiClient, SwitchTarget
from app.switch_files import (
    check_delete,
    load_files_page,
    parse_impact,
    parse_install_status,
    parse_listing,
    ready_to_install,
)
from app.switch_jobs import DONE, FAILED, Job
from tests.conftest import FIXTURES, load_fixture
from tests.fake_switch import FakeSwitch
from tests.stage_d_helpers import config_requests, csrf, enable, set_up, sign_in_as, text

IMPACT = (FIXTURES / "show_install_all_impact.txt").read_text()
INSTALL_OUTPUT = (
    "Installer will perform compatibility check first. Please wait.\n"
    "Compatibility check is done:\n"
    "Install is in progress, please wait.\n"
    "Finishing the upgrade, switch will reboot in 10 seconds.\n"
)


def test_the_impact_check_is_read() -> None:
    result = parse_impact(IMPACT)
    assert result["bootable"] == "yes" and result["impact"] == "disruptive"
    assert result["reason"] == "default upgrade is not hitless"
    assert result["versions"].startswith("nxos 9.3(16) to 9.3(16) (upgrade not needed)")
    assert "sFlow" in result["notes"]
    status = parse_install_status(load_fixture("show_install_all_status"))
    assert status.compatibility == (("yes", "disruptive", "reset", "Incompatible image for ISSU"),)
    assert status.images[0] == ("nxos", "7.0(3)I7(3)", "9.3(16)I9(1)", "yes")


def test_the_listing_is_read() -> None:
    listing = parse_listing(FakeSwitch().dir_body())
    assert [f.name for f in listing.files][-2:] == [".rpmstore", "scripts"]
    assert listing.has("backup_initial.cfg") and not listing.has("scripts")


def test_install_needs_both_checks_of_the_same_image() -> None:
    def job(kind: str, subject: str, state: str = DONE, **result: str) -> Job:
        made = Job(1, kind, subject, "admin", state=state)
        made.result = result
        return made

    good_sum, good_check = (
        job("checksum", "a.bin", match="yes"),
        job("impact", "a.bin", bootable="yes"),
    )
    assert ready_to_install(good_sum, good_check, "a.bin") == ""
    assert "checksum first" in ready_to_install(None, good_check, "a.bin")
    assert "did not match" in ready_to_install(
        job("checksum", "a.bin", match="no"), good_check, "a.bin"
    )
    assert "compatibility check" in ready_to_install(good_sum, job("impact", "b.bin"), "a.bin")
    assert "refused" in ready_to_install(good_sum, job("impact", "a.bin", bootable="no"), "a.bin")
    assert "first" in ready_to_install(good_sum, job("impact", "a.bin", FAILED), "a.bin")


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    return set_up(logged_in)


@pytest.fixture
def stored(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    enable(logged_in, settings, switch, "stored")
    switch.feature_state["scpServer"] = True
    return switch


def test_files_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/files")
    assert page.status_code == 200, text(page.text)
    shown = text(page.text)
    assert "nxos.9.3.16.bin" in shown and "in use" in shown and "backup_initial.cfg" in shown
    assert "/files/delete" not in page.text  # changes are off
    assert "need the stored admin login" in shown
    # NXray's own (limited) account is refused show boot, as on cisco-25gb.
    assert "may not read which image the switch starts from" in shown
    software = text(logged_in.get("/software").text)
    assert "Starts next time from not readable" in software and "no boot image" not in software


def test_with_the_broad_role_show_boot_is_read(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    shown = text(logged_in.get("/software").text)
    assert "may not read" not in shown and "Starts next time from nxos.9.3.16.bin" in shown


def test_without_the_boot_image_no_image_is_deleted(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    target = SwitchTarget("192.0.2.10", 443, "nxray", switch.users["nxray"][0], 10.0)
    with NxapiClient(target, transport=switch.transport()) as client:
        page = load_files_page(client)
    assert not page.boot_known
    with pytest.raises(ValueError, match="is kept"):
        check_delete(page, "nxos.7.0.3.I7.3.bin")
    check_delete(page, "backup_initial.cfg")


def test_the_broad_role_cannot_delete(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    refused = logged_in.post(
        "/files/delete", data={"csrf": csrf(logged_in), "name": "backup_initial.cfg"}
    )
    assert refused.status_code == 400 and "need the stored admin login" in text(refused.text)


def test_a_file_is_deleted_after_asking(logged_in: TestClient, stored: FakeSwitch) -> None:
    data = {"csrf": csrf(logged_in), "name": "nxos.7.0.3.I7.3.bin"}
    asked = logged_in.post("/files/delete", data=data)
    assert "delete bootflash:nxos.7.0.3.I7.3.bin no-prompt" in text(asked.text)
    assert "nxos.7.0.3.I7.3.bin" in stored.flash
    done = logged_in.post("/files/delete", data={**data, "confirm": "yes"})
    assert done.status_code == 200, text(done.text)
    assert "nxos.7.0.3.I7.3.bin" not in stored.flash and "admin" in stored.signed_in


def test_the_running_image_is_never_deleted(logged_in: TestClient, stored: FakeSwitch) -> None:
    refused = logged_in.post(
        "/files/delete",
        data={"csrf": csrf(logged_in), "name": "nxos.9.3.16.bin", "confirm": "yes"},
    )
    assert refused.status_code == 400 and "is kept" in text(refused.text)
    assert config_requests(stored) == [] and "nxos.9.3.16.bin" in stored.flash
    for bad in ("../etc", "scripts", "volatile:x"):
        refused = logged_in.post(
            "/files/delete", data={"csrf": csrf(logged_in), "name": bad, "confirm": "yes"}
        )
        assert refused.status_code == 400


def test_a_file_is_copied_both_ways(logged_in: TestClient, stored: FakeSwitch) -> None:
    sent = logged_in.post(
        "/files/upload",
        data={"csrf": csrf(logged_in)},
        files={"upload": ("lab.p12", b"certificate bytes", "application/octet-stream")},
    )
    assert sent.status_code == 200, text(sent.text)
    assert stored.flash["lab.p12"] == b"certificate bytes"
    assert "lab.p12 is on bootflash" in text(sent.text)
    got = logged_in.get("/files/download?name=lab.p12")
    assert got.status_code == 200 and got.content == b"certificate bytes"
    assert 'filename="lab.p12"' in got.headers["content-disposition"]
    again = logged_in.post(
        "/files/upload",
        data={"csrf": csrf(logged_in)},
        files={"upload": ("lab.p12", b"other", "application/octet-stream")},
    )
    assert again.status_code == 400 and "already has lab.p12" in text(again.text)


def test_copies_need_the_scp_server(logged_in: TestClient, stored: FakeSwitch) -> None:
    stored.feature_state["scpServer"] = False
    page = text(logged_in.get("/files").text)
    assert "turn on scp-server" in page
    refused = logged_in.get("/files/download?name=backup_initial.cfg")
    assert refused.status_code == 400 and "turn on scp-server" in text(refused.text)


def test_software_page_reads_the_switch(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "stored")
    page = logged_in.get("/software")
    assert page.status_code == 200, text(page.text)
    shown = text(page.text)
    assert "nxos.9.3.16.bin running" in shown and "nxos.7.0.3.I7.3.bin" in shown
    assert "Incompatible image for ISSU" in shown
    assert "/software/install" in page.text and "Run steps 1 and 2" in shown


def test_an_image_is_checked_then_installed(logged_in: TestClient, stored: FakeSwitch) -> None:
    image = "nxos.7.0.3.I7.3.bin"
    stored.impact_text = IMPACT
    stored.install_text = INSTALL_OUTPUT
    early = logged_in.post(
        "/software/install", data={"csrf": csrf(logged_in), "image": image, "confirm": "yes"}
    )
    assert early.status_code == 400 and "checksum first" in text(early.text)
    wrong = logged_in.post(
        "/software/checksum", data={"csrf": csrf(logged_in), "image": image, "checksum": "ab" * 32}
    )
    assert "does not match" in text(wrong.text)
    digest = hashlib.sha512(stored.flash[image]).hexdigest()
    summed = logged_in.post(
        "/software/checksum", data={"csrf": csrf(logged_in), "image": image, "checksum": digest}
    )
    assert "matches the SHA512 checksum" in text(summed.text)
    checked = logged_in.post("/software/check", data={"csrf": csrf(logged_in), "image": image})
    assert "passed the check" in text(checked.text) and "restarts the switch" in text(checked.text)
    asked = logged_in.post("/software/install", data={"csrf": csrf(logged_in), "image": image})
    assert "Type the switch's name" in text(asked.text) and stored.installs == []
    typo = logged_in.post(
        "/software/install",
        data={"csrf": csrf(logged_in), "image": image, "confirm": "yes", "hostname": "nope"},
    )
    assert typo.status_code == 400 and stored.installs == []
    done = logged_in.post(
        "/software/install",
        data={"csrf": csrf(logged_in), "image": image, "confirm": "yes", "hostname": "nexus-lab"},
    )
    assert done.status_code == 200, text(done.text)
    assert stored.installs == [image]
    assert "is restarting with" in text(done.text)
    assert stored.session_commands[-1] == f"install all nxos bootflash:{image} non-interruptive"


def test_an_install_the_switch_stops_is_reported(logged_in: TestClient, stored: FakeSwitch) -> None:
    image = "nxos.7.0.3.I7.3.bin"
    stored.impact_text = IMPACT
    stored.install_text = "Install has been aborted: not enough space.\n"
    digest = hashlib.md5(stored.flash[image]).hexdigest()  # noqa: S324 - as Cisco's page gives
    logged_in.post(
        "/software/checksum", data={"csrf": csrf(logged_in), "image": image, "checksum": digest}
    )
    logged_in.post("/software/check", data={"csrf": csrf(logged_in), "image": image})
    stopped = logged_in.post(
        "/software/install",
        data={"csrf": csrf(logged_in), "image": image, "confirm": "yes", "hostname": "nexus-lab"},
    )
    assert "stopped the install" in text(stopped.text)


def test_tech_support_is_collected_and_downloaded(
    logged_in: TestClient, stored: FakeSwitch, settings: Settings
) -> None:
    page = text(logged_in.get("/tech-support").text)
    assert "None yet" in page
    done = logged_in.post("/tech-support/collect", data={"csrf": csrf(logged_in)})
    assert done.status_code == 200, text(done.text)
    assert "Collected" in text(done.text)
    got = logged_in.get("/tech-support/download")
    assert got.status_code == 200 and gzip.decompress(got.content) == stored.tech_text
    assert "nexus-lab-tech-support-" in got.headers["content-disposition"]
    kept = list(Path(settings.data_dir, "tech-support").iterdir())
    assert [p.name for p in kept] == ["switch-1.txt.gz"] and kept[0].stat().st_mode & 0o077 == 0
    logged_in.post("/tech-support/delete", data={"csrf": csrf(logged_in)})
    assert not kept[0].exists()


def test_viewers_and_operators_look_only(logged_in: TestClient, stored: FakeSwitch) -> None:
    for name, role in (("vera", "viewer"), ("otto", "operator")):
        other = sign_in_as(logged_in, name, role)
        page = other.get("/files")
        assert "only an NXray admin" in text(page.text) and "/files/delete" not in page.text
        refused = other.post("/tech-support/collect", data={"csrf": csrf(other)})
        assert refused.status_code == 403
        assert other.get("/files/download?name=backup_initial.cfg").status_code == 403
