"""Recent switch answers, reused while a person clicks through pages (#98).

A Nexus answers one NX-API request at a time and spends 70 ms to over a second
on each command, so a page costs the switch almost all of its load time, and
the same answers (``show feature`` on most pages, ``show interface brief``, the
all-ports reads of the Ports, Neighbors, Traffic and every port's page) are read
again by page after page.

``PageReads`` keeps the answers to a short list of read-only commands for
``NXRAY_PAGE_READ_SECONDS`` (``show version``, which changes only when the switch
restarts, for longer). A page a person opens reads through it
(``app/dependencies.py``, ``reuse_page_reads``); it asks the switch only for the
commands it has no recent answer to. Nothing else does:

- a form sent (any request that is not a GET) empties it, so the page shown after
  a change is read from the switch;
- a reload from the browser (F5, or Ctrl+Shift+R) empties it too;
- the pages that refresh themselves read through the live cache (``app/live.py``),
  and the history and alert readings run on their own, so neither is held back.

A change made at the switch's own command line shows on a page only after the
seconds above, or after a reload.
"""

from __future__ import annotations

import copy
import re
import threading
import time
from collections.abc import Callable
from typing import Any

# The answers worth keeping: the whole-switch lists most pages read, and what one
# port's page reads about that port. The port lists carry states and rates, so a page
# opened inside the seconds shows them as they were (a reload, or Live, shows them as
# they are). A show command that is not named here is always asked of the switch: CPU,
# memory, temperatures, uptime, queue counters and everything else a page is opened to
# look at must be current.
SHORT_LIVED = frozenset(
    {
        "show feature",
        "show interface",
        "show interface brief",
        "show interface status",
        "show interface switchport",
        "show interface transceiver",
        "show vlan",
        "show vlan brief",
        "show vrf",
        "show vrf interface",
        "show port-channel summary",
        "show cdp global",
        "show cdp neighbors detail",
        "show lldp neighbors detail",
        "show mac address-table",
        "show mac address-table aging-time",
        "show ip arp detail vrf all",
        "show ip interface vrf all",
        "show ipv6 interface vrf all",
        "show hardware access-list tcam region",
    }
)
_PER_PORT = re.compile(
    r"show (?:interface \S+ (?:capabilities|flowcontrol|counters storm-control)"
    r"|(?:cdp|lldp) interface \S+)"
)

# Commands whose answer changes only when the switch restarts or upgrades, with how
# many seconds it is kept (a reload from the browser still reads it again).
LONG_LIVED = {"show version": 300}

# How many answers are kept at most, so a long-running NXray with many switches
# or ports cannot grow without limit.
MAX_ANSWERS = 2000

Switch = tuple[str, ...]
Answer = tuple[float, dict[str, Any]]


def lifetime(command: str, seconds: int) -> int:
    """How many seconds the answer to ``command`` is kept; 0 when it is never kept.

    ``seconds`` is the setting (``NXRAY_PAGE_READ_SECONDS``): 0 keeps nothing.
    """
    if seconds <= 0:
        return 0
    if command in LONG_LIVED:
        return max(seconds, LONG_LIVED[command])
    if command in SHORT_LIVED or _PER_PORT.fullmatch(command):
        return seconds
    return 0


class PageReads:
    """The recent answers per switch and command, shared by every page opened."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._answers: dict[tuple[Switch, str], Answer] = {}

    def clear(self) -> None:
        """Forget every answer: something may have changed on a switch."""
        with self._lock:
            self._answers.clear()

    def reader(
        self, seconds: int
    ) -> Callable[
        [Switch, list[str], Callable[[list[str]], list[dict[str, Any]]]], list[dict[str, Any]]
    ]:
        """The function ``nxapi.page_reads`` holds for one page being opened."""

        def reuse(
            switch: Switch,
            commands: list[str],
            read: Callable[[list[str]], list[dict[str, Any]]],
        ) -> list[dict[str, Any]]:
            found: dict[str, dict[str, Any]] = {}
            missing: list[str] = []
            now = self._clock()
            with self._lock:
                for command in commands:
                    answer = self._answers.get((switch, command))
                    life = lifetime(command, seconds)
                    if life and answer is not None and now - answer[0] < life:
                        found[command] = answer[1]
                    elif command not in missing:
                        missing.append(command)
            if missing:
                bodies = read(missing)
                with self._lock:
                    stamp = self._clock()
                    for command, body in zip(missing, bodies, strict=True):
                        found[command] = body
                        if lifetime(command, seconds):
                            self._answers[(switch, command)] = (stamp, body)
                    self._forget_old(stamp)
            # Each page parses its own copy: nothing it does can reach another's.
            return [copy.deepcopy(found[command]) for command in commands]

        return reuse

    def _forget_old(self, now: float) -> None:
        """Drop answers past their longest life, and the oldest ones past the cap."""
        longest = max(LONG_LIVED.values())
        for key in [k for k, (stamp, _) in self._answers.items() if now - stamp >= longest]:
            del self._answers[key]
        extra = len(self._answers) - MAX_ANSWERS
        if extra > 0:
            for key in sorted(self._answers, key=lambda k: self._answers[k][0])[:extra]:
                del self._answers[key]
