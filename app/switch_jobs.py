"""Slow work on the switch that runs after the page has answered: collecting ``show
tech-support`` (minutes, over 100 MB), a file's checksum, the install's compatibility
check, the install itself, and copying a file to bootflash.

Each runs on its own thread; its page shows how far it got and reloads itself until it
ends. One job of each kind runs per switch at a time. Jobs live in memory only: a restart
of NXray forgets them (and a job running then stops), and the page offers to run it again.
The last job of each kind stays until the next one of that kind starts, so its result can
be read (the install is allowed only after its image's checksum and check passed).
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

log = logging.getLogger("nxray.jobs")

KINDS = ("techsupport", "checksum", "impact", "install", "upload")
RUNNING, DONE, FAILED = "running", "done", "failed"


class JobBusy(Exception):
    """A job of that kind is already running for that switch."""


@dataclass
class Job:
    """One piece of slow work and how it went."""

    switch_id: int
    kind: str
    subject: str  # what it works on: an image or file name ("" for tech-support)
    username: str  # the NXray account that started it
    started: float = field(default_factory=time.time)
    state: str = RUNNING
    message: str = ""  # done: what came of it; failed: why
    progress: str = ""  # while running: how far it got, in words
    result: dict[str, str] = field(default_factory=dict)
    finished: float | None = None
    output: str = ""  # what the switch printed, where the page shows it

    @property
    def running(self) -> bool:
        return self.state == RUNNING

    @property
    def seconds(self) -> int:
        return int((self.finished or time.time()) - self.started)


class Jobs:
    """Every switch's jobs; ``app.state.jobs``. With ``background`` false (tests) a job
    runs before ``start`` returns."""

    def __init__(self, background: bool = True) -> None:
        self.background = background
        self._lock = threading.Lock()
        self._jobs: dict[tuple[int, str], Job] = {}

    def get(self, switch_id: int, kind: str) -> Job | None:
        with self._lock:
            return self._jobs.get((switch_id, kind))

    def forget(self, switch_id: int, kind: str) -> None:
        """Drop the last finished job of that kind (a running one stays)."""
        with self._lock:
            job = self._jobs.get((switch_id, kind))
            if job is not None and not job.running:
                del self._jobs[(switch_id, kind)]

    def start(
        self,
        switch_id: int,
        kind: str,
        subject: str,
        username: str,
        work: Callable[[Job], str],
    ) -> Job:
        """Run ``work`` for a new job; it returns the message for when it ends well, and
        raises with the reason when not (the message of a ValueError or OSError is shown
        as it is). JobBusy when one of that kind is running."""
        if kind not in KINDS:
            raise ValueError(f"unknown job kind {kind!r}")
        with self._lock:
            current = self._jobs.get((switch_id, kind))
            if current is not None and current.running:
                raise JobBusy(kind)
            job = Job(switch_id, kind, subject, username)
            self._jobs[(switch_id, kind)] = job
        if self.background:
            threading.Thread(target=self._run, args=(job, work), daemon=True, name=kind).start()
        else:
            self._run(job, work)
        return job

    def _run(self, job: Job, work: Callable[[Job], str]) -> None:
        try:
            message = work(job)
        except Exception as exc:  # the job's page shows why it stopped
            log.warning("%s on switch %s stopped: %s", job.kind, job.switch_id, exc)
            job.message = str(exc) or type(exc).__name__
            job.state = FAILED
        else:
            job.message = message
            job.state = DONE
        job.progress = ""
        job.finished = time.time()
