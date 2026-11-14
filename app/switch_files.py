"""The switch's files and software: what is on bootflash (and copying files to and from it,
deleting them), the NX-OS image it runs and boots, checking a new image and installing it,
and collecting ``show tech-support`` for a support case.

Three pages use this module: Files (#85), Software (#84) and Tech support (#86). Reading
goes over NX-API (``dir bootflash:``, ``show version``, ``show boot``, ``show install all
status``), with the stored admin login when there is one and NXray's own account
otherwise; network-operator, and so NXray's limited account, is refused ``show boot`` and
``show install all status`` (seen on cisco-25gb), and the pages then say so. Everything
else goes over SSH with the stored admin login (``app/switch_ssh.py``): the copies use SCP,
which needs ``feature scp-server``, and the slow commands (a checksum of a 2 GB image takes
about a minute, the install check about three, ``show tech-support`` about four and prints
over 100 MB) run as background jobs (``app/switch_jobs.py``). Deleting a file goes over
NX-API with the same login.

Seen on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-12): every command above, SCP
both ways and ``delete bootflash:<file> no-prompt`` with a throwaway file, the checksums
(``show file bootflash:<f> md5sum|sha256sum|sha512sum``), ``show install all impact nxos
bootflash:nxos.9.3.16.bin`` (it reported "disruptive": an install restarts this model) and
``show tech-support``. Not run, because it restarts the switch: the install itself
(``install all nxos bootflash:<image> non-interruptive``, from Cisco's NX-OS 9.3 Software
Upgrade and Downgrade Guide). As the guide says, the install saves the running
configuration ("Performing configuration copy") before it restarts.
"""

from __future__ import annotations

import gzip
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from app.nxapi import FLASH_FILE, NxapiClient, NxapiCommandError
from app.protocols import table_rows
from app.switch import text
from app.switch_jobs import DONE, Job
from app.switch_ssh import Session, SshCommandError, SshUnreachable

FILESYSTEM = "bootflash:"
VERSION_COMMAND = "show version"
BOOT_COMMAND = "show boot"
INSTALL_STATUS_COMMAND = "show install all status"
FEATURE_COMMAND = "show feature"
# show feature's name for the SCP server (``feature scp-server`` turns it on).
SCP_FEATURE = "scpServer"
IMAGE_ENDINGS = (".bin",)
# How long the slow commands may run before NXray gives up on them.
CHECKSUM_TIMEOUT = 600.0
IMPACT_TIMEOUT = 1800.0
INSTALL_TIMEOUT = 3600.0
TECH_TIMEOUT = 3600.0
# A checksum's length in hex digits -> the word ``show file`` takes for it.
CHECKSUMS = {32: "md5sum", 64: "sha256sum", 128: "sha512sum"}
# Room left on bootflash after a copy, so the switch still has space for its logs.
SPARE_BYTES = 64 * 1024 * 1024
TECH_DIR = "tech-support"
UPLOAD_DIR = "uploads"
OUTPUT_KEEP = 20000  # characters of a command's output kept for its page


# ---- files ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class FlashFile:
    name: str
    size: int
    date: str
    folder: bool


@dataclass(frozen=True)
class Listing:
    files: tuple[FlashFile, ...]
    used: int
    free: int
    total: int

    def has(self, name: str) -> bool:
        return any(f.name == name and not f.folder for f in self.files)

    def size_of(self, name: str) -> int:
        return next((f.size for f in self.files if f.name == name and not f.folder), 0)


def _number(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def parse_listing(body: dict[str, Any]) -> Listing:
    """``dir bootflash:`` as NX-API answers it: files first by name, folders last."""
    found = []
    for row in table_rows(body, "TABLE_dir", "ROW_dir"):
        name = text(row.get("fname"))
        if not name:
            continue
        folder = name.endswith("/")
        found.append(
            FlashFile(
                name.rstrip("/"), _number(row.get("fsize")), text(row.get("timestring")), folder
            )
        )
    found.sort(key=lambda f: (f.folder, f.name.lower()))
    return Listing(
        tuple(found),
        _number(body.get("bytesused")),
        _number(body.get("bytesfree")),
        _number(body.get("bytestotal")),
    )


def _image_name(path: str) -> str:
    """'bootflash:///nxos.9.3.16.bin' or 'bootflash:/nxos.9.3.16.bin' -> 'nxos.9.3.16.bin'."""
    return path.split(":", 1)[-1].lstrip("/") if path else ""


@dataclass(frozen=True)
class Software:
    """What the switch runs and boots."""

    version: str
    running_image: str  # file name on bootflash
    boot_image: str  # what the next start loads ("" when no boot line)
    current_boot: str  # the boot variable now


def parse_software(version: dict[str, Any], boot: dict[str, Any] | None) -> Software:
    """``boot`` is None when the account may not read ``show boot``."""
    current = table_rows(boot, "TABLE_Current_Bootvar", "ROW_Current_Bootvar")
    start = table_rows(boot, "TABLE_Startup_Bootvar", "ROW_Startup_Bootvar")
    return Software(
        text(version.get("nxos_ver_str")) or "-",
        _image_name(text(version.get("nxos_file_name"))),
        _image_name(text(start[0].get("start_image"))) if start else "",
        _image_name(text(current[0].get("current_image"))) if current else "",
    )


BOOT_UNREAD = (
    "NXray's account may not read which image the switch starts from (show boot): store "
    "the switch admin login on the Switch page to see it here."
)


@dataclass(frozen=True)
class FilesPage:
    listing: Listing
    protected: frozenset[str]  # the images the switch runs or boots: never deleted
    scp_on: bool
    problem: str = ""
    boot_known: bool = True  # False: show boot was refused, so every image is kept


def _boot(client: NxapiClient) -> dict[str, Any] | None:
    try:
        (body,) = client.show(BOOT_COMMAND)
    except NxapiCommandError:
        return None
    return body


def scp_on(feature_body: dict[str, Any]) -> bool:
    for row in table_rows(feature_body, "TABLE_cfcFeatureCtrlTable", "ROW_cfcFeatureCtrlTable"):
        if text(row.get("cfcFeatureCtrlName2")) == SCP_FEATURE:
            return text(row.get("cfcFeatureCtrlOpStatus2")) == "enabled"
    return False


def load_files_page(client: NxapiClient) -> FilesPage:
    """The file list; the images in use; whether the SCP server is on."""
    listing = parse_listing(client.list_files())
    version, features = client.show(VERSION_COMMAND, FEATURE_COMMAND)
    boot = _boot(client)
    software = parse_software(version, boot)
    protected = frozenset(
        n for n in (software.running_image, software.boot_image, software.current_boot) if n
    )
    if boot is None:
        return FilesPage(listing, protected, scp_on(features), BOOT_UNREAD, False)
    return FilesPage(listing, protected, scp_on(features))


def check_delete(page: FilesPage, name: str) -> None:
    """ValueError when ``name`` may not be deleted: not a plain file on bootflash, or
    an image the switch runs or boots."""
    if not FLASH_FILE.fullmatch(name) or not page.listing.has(name):
        raise ValueError(f"bootflash has no file {name!r} NXray deletes (folders are kept)")
    if name in page.protected:
        raise ValueError(f"{name} is the image the switch runs or starts from; it is kept")
    if not page.boot_known and name.lower().endswith(IMAGE_ENDINGS):
        raise ValueError(f"NXray cannot read which image the switch starts from, so {name} is kept")


def check_upload(page: FilesPage, name: str, size: int) -> None:
    """ValueError when a file of ``size`` bytes may not be copied as ``name``."""
    if not FLASH_FILE.fullmatch(name):
        raise ValueError(
            "the file name is letters, digits, '.', '_' or '-' (rename the file first)"
        )
    if page.listing.has(name) or any(f.name == name for f in page.listing.files):
        raise ValueError(f"bootflash already has {name}: delete it first, or rename the file")
    if size <= 0:
        raise ValueError("the file is empty")
    if size + SPARE_BYTES > page.listing.free:
        raise ValueError(
            f"bootflash has {page.listing.free} bytes free, too few for {size} bytes and "
            "room for the switch's own files"
        )


def upload_work(
    session: Callable[[], Session], local: Path, size: int, name: str
) -> Callable[[Job], str]:
    """The job that copies ``local`` (an upload NXray holds) to bootflash; the local
    copy is removed either way."""

    def work(job: Job) -> str:
        try:
            with local.open("rb") as source, _closing(session()) as ssh:

                def progress(sent: int) -> None:
                    job.progress = f"{sent * 100 // size}% ({sent} of {size} bytes)"

                ssh.upload(source, size, f"{FILESYSTEM}{name}", progress)
        finally:
            local.unlink(missing_ok=True)
        return f"{name} is on bootflash ({size} bytes)."

    return work


class _closing:
    """``with`` for a Session: closed afterwards whatever happens."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def __enter__(self) -> Session:
        return self.session

    def __exit__(self, *exc: object) -> None:
        try:
            self.session.close()
        except Exception:  # noqa: BLE001 - closing a dropped session may fail any way
            pass


def save_upload(source: BinaryIO, data_dir: Path) -> tuple[Path, int]:
    """Copy an uploaded file to NXray's data folder (it is gone once the request ends);
    the path and the size."""
    folder = data_dir / UPLOAD_DIR
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = folder / f"{os.urandom(8).hex()}.part"
    size = 0
    with path.open("wb") as out:
        while chunk := source.read(1024 * 1024):
            out.write(chunk)
            size += len(chunk)
    return path, size


# ---- software -------------------------------------------------------------------------------


@dataclass(frozen=True)
class InstallStatus:
    """The last install's (or install check's) result, as ``show install all status``
    keeps it."""

    images: tuple[tuple[str, ...], ...]  # image, running version, new version, upgrade needed
    compatibility: tuple[tuple[str, ...], ...]  # bootable, impact, install type, reason
    stages: tuple[tuple[str, str], ...]  # stage, its result


def parse_install_status(body: dict[str, Any]) -> InstallStatus:
    return InstallStatus(
        tuple(
            (
                text(r.get("image")),
                text(r.get("running_version")),
                text(r.get("new_version")),
                text(r.get("upg_required")),
            )
            for r in table_rows(body, "TABLE_installversion", "ROW_installversion")
        ),
        tuple(
            (
                text(r.get("bootable")),
                text(r.get("impact")),
                text(r.get("install_type")),
                text(r.get("reason")),
            )
            for r in table_rows(body, "TABLE_installcompatibility", "ROW_installcompatibility")
        ),
        tuple(
            (text(r.get("stage")), text(r.get("stagestatus")))
            for r in table_rows(body, "TABLE_installstage", "ROW_installstage")
        ),
    )


@dataclass(frozen=True)
class SoftwarePage:
    software: Software
    images: tuple[FlashFile, ...]  # the .bin files on bootflash
    status: InstallStatus | None
    free: int
    problem: str = ""
    boot_known: bool = True  # False: show boot was refused


def load_software_page(client: NxapiClient) -> SoftwarePage:
    """The version and boot images, the images on bootflash, the last install status."""
    (version,) = client.show(VERSION_COMMAND)
    boot = _boot(client)
    listing = parse_listing(client.list_files())
    images = tuple(
        f for f in listing.files if not f.folder and f.name.lower().endswith(IMAGE_ENDINGS)
    )
    problem = BOOT_UNREAD if boot is None else ""
    try:
        (status_body,) = client.show(INSTALL_STATUS_COMMAND)
        status: InstallStatus | None = parse_install_status(status_body)
    except NxapiCommandError as exc:
        status = None
        problem = " ".join(
            p for p in (problem, f"The switch did not report its last install: {exc}.") if p
        )
    return SoftwarePage(
        parse_software(version, boot), images, status, listing.free, problem, boot is not None
    )


def check_image(page: SoftwarePage, name: str) -> None:
    if not FLASH_FILE.fullmatch(name) or not any(f.name == name for f in page.images):
        raise ValueError(f"bootflash has no image {name!r}: copy it there on the Files page")


def checksum_word(expected: str) -> tuple[str, str]:
    """The pasted checksum in lower case and the ``show file`` word for its length;
    ValueError when it is not an MD5, SHA-256 or SHA-512 written in hex."""
    value = re.sub(r"\s+", "", expected).lower()
    if not re.fullmatch(r"[0-9a-f]+", value) or len(value) not in CHECKSUMS:
        raise ValueError(
            "paste the image's MD5, SHA-256 or SHA-512 checksum from Cisco's download page "
            "(32, 64 or 128 hex digits)"
        )
    return value, CHECKSUMS[len(value)]


def _collect(stream: Any) -> str:
    return b"".join(stream).decode("utf-8", errors="replace")


def checksum_work(
    session: Callable[[], Session], image: str, expected: str
) -> Callable[[Job], str]:
    """The job that has the switch work out the image's checksum and compares it."""
    value, word = checksum_word(expected)

    def work(job: Job) -> str:
        job.progress = f"The switch is reading {image} ({word}); this takes a minute or two."
        with _closing(session()) as ssh:
            printed = _collect(
                ssh.stream(f"show file {FILESYSTEM}{image} {word}", CHECKSUM_TIMEOUT)
            )
        found = re.search(r"\b[0-9a-fA-F]{32,128}\b", printed)
        if found is None:
            raise SshCommandError(f"the switch printed no checksum: {printed.strip()[:200]}")
        got = found.group(0).lower()
        job.result = {"algorithm": word, "switch": got, "match": "yes" if got == value else "no"}
        if got != value:
            raise ValueError(
                f"{image} does not match: the switch worked out {got}. The copy is damaged "
                "or it is another file; copy it again before installing"
            )
        return f"{image} matches the {word.removesuffix('sum').upper()} checksum."

    return work


_COMPAT_ROW = re.compile(r"^\s*(\d+)\s+(yes|no)\s+(\S+)\s+(\S+)\s+(.*?)\s*$")
_IMAGE_ROW = re.compile(r"^\s*(\d+)\s+(\S+)\s+(.+?)\s{2,}(\S+)\s+(yes|no)\s*$")


def parse_impact(printed: str) -> dict[str, str]:
    """The compatibility check's result from what ``show install all impact`` prints:
    bootable, impact, install type and reason of module 1, the versions, and the
    additional notes."""
    result: dict[str, str] = {}
    section = ""
    notes: list[str] = []
    versions: list[str] = []
    for raw in printed.splitlines():
        line = raw.rstrip()
        if line.startswith("Compatibility check is done"):
            section = "compat"
            continue
        if line.startswith("Images will be upgraded"):
            section = "images"
            continue
        if line.startswith("Additional info"):
            section = "notes"
            continue
        if section == "compat" and (match := _COMPAT_ROW.match(line)) and "bootable" not in result:
            result.update(
                bootable=match.group(2),
                impact=match.group(3),
                install_type=match.group(4),
                reason=match.group(5),
            )
        elif section == "images" and (match := _IMAGE_ROW.match(line)):
            versions.append(
                f"{match.group(2)} {match.group(3).strip()} to {match.group(4)}"
                f" (upgrade {'needed' if match.group(5) == 'yes' else 'not needed'})"
            )
        elif section == "notes" and line.strip() and not set(line.strip()) <= {"-"}:
            notes.append(line.strip())
    if versions:
        result["versions"] = "; ".join(versions)
    if notes:
        result["notes"] = " ".join(notes)
    return result


def impact_work(session: Callable[[], Session], image: str) -> Callable[[Job], str]:
    """The job that runs the switch's own compatibility check for ``image``."""

    def work(job: Job) -> str:
        job.progress = "The switch is checking the image; this takes about three minutes."
        with _closing(session()) as ssh:
            printed = _collect(
                ssh.stream(f"show install all impact nxos {FILESYSTEM}{image}", IMPACT_TIMEOUT)
            )
        job.output = printed[-OUTPUT_KEEP:]
        result = parse_impact(printed)
        job.result = result
        if result.get("bootable") != "yes":
            reason = result.get("reason") or _last_lines(printed)
            raise ValueError(f"the switch says {image} cannot be installed: {reason}")
        restart = result.get("impact") != "non-disruptive"
        return f"{image} passed the check. Impact: {result.get('impact', '-')}" + (
            " (the install restarts the switch)." if restart else "."
        )

    return work


def _last_lines(printed: str, count: int = 3) -> str:
    lines = [line.strip() for line in printed.splitlines() if line.strip()]
    return " ".join(lines[-count:]) or "it printed nothing"


def ready_to_install(checksum: Job | None, impact: Job | None, image: str) -> str:
    """Why ``image`` may not be installed yet ("" when it may): its checksum and the
    compatibility check must both have passed in this run of NXray."""
    if checksum is None or checksum.subject != image or checksum.state != DONE:
        return f"check {image}'s checksum first"
    if checksum.result.get("match") != "yes":
        return f"{image}'s checksum did not match"
    if impact is None or impact.subject != image or impact.state != DONE:
        return f"run the compatibility check for {image} first"
    if impact.result.get("bootable") != "yes":
        return f"the compatibility check refused {image}"
    return ""


_RESTARTING = re.compile(r"(?i)switch will (?:be reloaded|reboot)|finishing the upgrade")
_INSTALL_FAILED = re.compile(r"(?i)install has been aborted|install failed|failed\.|failure")


def install_work(session: Callable[[], Session], image: str) -> Callable[[Job], str]:
    """The job that installs ``image``. The switch drops the session when it restarts,
    which is how a good install ends."""

    def work(job: Job) -> str:
        job.progress = "The switch is installing; it restarts when it is done."
        printed = ""
        try:
            with _closing(session()) as ssh:
                for chunk in ssh.stream(
                    f"install all nxos {FILESYSTEM}{image} non-interruptive", INSTALL_TIMEOUT
                ):
                    printed += chunk.decode("utf-8", errors="replace")
                    job.output = printed[-OUTPUT_KEEP:]
        except SshUnreachable:
            if not _RESTARTING.search(printed):
                raise
        if _INSTALL_FAILED.search(printed) and not _RESTARTING.search(printed):
            raise ValueError(f"the switch stopped the install: {_last_lines(printed)}")
        if not _RESTARTING.search(printed):
            raise ValueError(f"the install ended without a restart: {_last_lines(printed)}")
        return (
            f"The switch is restarting with {image}. It answers again in about ten to twenty "
            "minutes; until then NXray cannot reach it."
        )

    return work


# ---- tech support ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TechFile:
    """The last tech-support NXray collected for a switch."""

    path: Path
    size: int
    made: float


def tech_path(data_dir: Path, switch_id: int) -> Path:
    return data_dir / TECH_DIR / f"switch-{switch_id}.txt.gz"


def tech_file(data_dir: Path, switch_id: int) -> TechFile | None:
    path = tech_path(data_dir, switch_id)
    try:
        info = path.stat()
    except FileNotFoundError:
        return None
    return TechFile(path, info.st_size, info.st_mtime)


def tech_work(session: Callable[[], Session], target: Path) -> Callable[[Job], str]:
    """The job that runs ``show tech-support`` and keeps it gzipped at ``target``,
    replacing the last one only once the new one is whole."""

    def work(job: Job) -> str:
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        part = target.with_suffix(".part")
        received = 0
        started = time.monotonic()
        try:
            with _closing(session()) as ssh, gzip.open(part, "wb") as out:
                for chunk in ssh.stream("show tech-support", TECH_TIMEOUT):
                    out.write(chunk)
                    received += len(chunk)
                    job.progress = (
                        f"{received // (1024 * 1024)} MB received in "
                        f"{int(time.monotonic() - started)} seconds"
                    )
            if received == 0:
                raise SshCommandError("the switch printed nothing for show tech-support")
            part.chmod(0o600)
            part.replace(target)
        finally:
            part.unlink(missing_ok=True)
        job.result = {"bytes": str(received)}
        return f"Collected {received // (1024 * 1024)} MB of show tech-support."

    return work
