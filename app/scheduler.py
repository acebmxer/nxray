"""The scheduler: jobs (a list of commands the switch runs on its own) and schedules
(when to run which jobs), with what each run did.

A job is made once with all its commands: the switch refuses a job's name typed again
("Error: job exists"), so a job is changed by deleting it and making it again. Its
commands come from the fixed menu of ``app/command_menu.py``, never typed. A job runs
as the switch account that made it, so its commands get no more than that account's
role allows (an account with NXray's broad role is refused a copy to bootflash, for
one).

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (the switch's scheduler, a job, a schedule), each setting
the line it sends with checked values in its blanks, and ``build_change`` building the
lines; making a job turns the picked menu entries into the job's lines
(``build_scheduler_change``). ``NxapiClient.configure_scheduler`` sends them.

Read from the switch: ``show feature`` and ``show interface brief`` in one request; while
``feature scheduler`` is on (the commands are refused before), ``show scheduler config``,
``show scheduler schedule`` and ``show scheduler logfile`` in one.

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-11) with throwaway jobs and schedules, all
removed afterwards: making jobs with one or more lines, ``job name``, every ``time`` form
below (``time start now`` alone is refused: it needs ``repeat``), ``no time``, deleting
a job and a schedule. A schedule whose time is set cannot be deleted ("schedule in
progress") until ``no time``, so Delete sends that first. Not tried: ``scheduler logfile
size``.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
from typing import Any

from app.command_menu import MENU, SHOW_COMMANDS, menu_lines, port_and_channel_names
from app.features import feature_states
from app.nxapi import NxapiClient
from app.protocols import (
    Field,
    Instance,
    Protocol,
    ProtocolChange,
    ProtocolView,
    Scope,
    Setting,
    Table,
    build_change,
    check_value,
    table_rows,
)
from app.switch import text

PAGE_COMMANDS = ("show feature", "show interface brief")
COMMANDS = ("show scheduler config", "show scheduler schedule", "show scheduler logfile")
FEATURE = "scheduler"
DAYS = ("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")
JOB_COMMANDS = 4  # menu picks one job may hold
NAME_MAX = 31


def _name(name: str, label: str, hint: str) -> Field:
    return Field(name, label, "name", maximum=NAME_MAX, hint=hint, placeholder="nightly")


_SCHEDULER = Scope(
    key="scheduler",
    label="Scheduler",
    ident=(),
    enter=(),
    settings=(
        Setting(
            key="logfile",
            label="Log size",
            line="scheduler logfile size {kb}",
            removable=False,
            group="Log",
            fields=(
                Field(
                    "kb", "Kilobytes", "int", 16, 1024, hint="16 to 1024; the switch starts with 16"
                ),
            ),
            help="How much of the jobs' output the switch keeps (the Log below).",
        ),
    ),
)


def _command(number: int) -> Field:
    return Field(
        f"command{number}",
        f"Command {number}",
        "choice",
        choices=MENU,
        optional=number > 1,
    )


_JOB = Scope(
    key="job",
    label="Jobs",
    ident=(_name("job", "Job", "A name of your own"),),
    enter=("scheduler job name {job}",),
    delete=("no scheduler job name {job}",),
    delete_warning="Schedules that name it run without it.",
    help=(
        "A job is made once with all its commands, run in order. To change one, delete it "
        "and make it again. With the broad role the switch refuses the bootflash copy and "
        "clearing counters: they need the stored admin login."
    ),
    settings=(
        Setting(
            key="make",
            label="Make the job",
            line="{command1}",
            removable=False,
            group="Make a job",
            fields=(
                *(_command(n) for n in range(1, JOB_COMMANDS + 1)),
                Field(
                    "port",
                    "Port",
                    "port",
                    optional=True,
                    hint="For turning a port off or on and clearing its counters",
                ),
                Field(
                    "file",
                    "Bootflash file",
                    "flashfile",
                    optional=True,
                    hint="For the copy: the file is written again at each run",
                    placeholder="nightly.cfg",
                ),
                Field(
                    "show",
                    "Show command",
                    "choice",
                    choices=SHOW_COMMANDS,
                    optional=True,
                    hint="Its output goes to the Log below",
                ),
            ),
            help="Pick up to four commands; the port, file and show command fields serve "
            "the ones that need them.",
        ),
    ),
)


def _check_start(values: dict[str, str]) -> None:
    if values.get("start") == "now" and not values.get("repeat"):
        raise ValueError("starting now needs how often it repeats")


def _time(key: str, label: str, line: str, fields: tuple[Field, ...], hint: str) -> Setting:
    return Setting(
        key=key,
        label=label,
        line=line,
        no_line="no time",
        group="When",
        fields=fields,
        help=f"{hint + ' ' if hint else ''}Setting a time replaces the one before; Remove "
        "takes it away.",
        check=_check_start if key == "start" else None,
    )


_SCHEDULE = Scope(
    key="schedule",
    label="Schedules",
    ident=(_name("schedule", "Schedule", "A name of your own"),),
    enter=("scheduler schedule name {schedule}",),
    delete=(
        "scheduler schedule name {schedule}",
        "no time",
        "exit",
        "no scheduler schedule name {schedule}",
    ),
    help=(
        "A schedule runs its jobs, in order, at its time. Without a time it never runs. To "
        "make one, pick a new name, add a job, then set the time."
    ),
    settings=(
        Setting(
            key="job",
            label="Job",
            line="job name {job}",
            group="Jobs",
            fields=(Field("job", "Job", "name", maximum=NAME_MAX, hint="A job made above"),),
            help="Set adds the job; Remove takes it off this schedule.",
        ),
        _time("daily", "Every day", "time daily {at}", (Field("at", "At", "hhmm"),), ""),
        _time(
            "weekly",
            "Every week",
            "time weekly {day}:{at}",
            (Field("day", "Day", "choice", choices=DAYS), Field("at", "At", "hhmm")),
            "",
        ),
        _time(
            "monthly",
            "Every month",
            "time monthly {day}:{at}",
            (
                Field("day", "Day", "int", 1, 31, hint="29, 30 or 31: the month's last day"),
                Field("at", "At", "hhmm"),
            ),
            "",
        ),
        _time(
            "start",
            "Once, or repeating",
            "time start {start}[ repeat {repeat}]",
            (
                Field(
                    "start",
                    "Start",
                    "schedstart",
                    hint="now, +02:00 (in two hours), 23:30 (today) or 2026-12-01 03:00",
                    placeholder="now",
                ),
                Field(
                    "repeat",
                    "Repeat every",
                    "schedrepeat",
                    optional=True,
                    hint="02:00 (hours:minutes) or 1:00:00 (days:hours:minutes); needed with now",
                ),
            ),
            "The switch's clock decides when.",
        ),
    ),
)


# ---- reading the switch ------------------------------------------------------------------

_LABEL = re.compile(r"^[A-Za-z ]+:\s*")


def _value(raw: Any) -> str:
    """'Last Execution Time : Wed Nov 11 22:34:18 2026\\n' -> 'Wed Nov 11 22:34:18 2026'."""
    return _LABEL.sub("", text(raw).strip(), count=1)


def parse_jobs(config: Any) -> dict[str, list[str]]:
    """``job -> its lines`` from ``show scheduler config``."""
    jobs: dict[str, list[str]] = {}
    for row in table_rows(config, "TABLE_jobconfig", "ROW_jobconfig"):
        name = ""
        for line in text(row.get("jobdata")).splitlines():
            stripped = line.strip()
            if match := re.fullmatch(r"scheduler job name (\S+)", stripped):
                name = match.group(1)
                jobs[name] = []
            elif name and stripped and stripped not in ("config terminal", "end"):
                jobs[name].append(stripped)
    return jobs


def _job_names(row: dict[str, Any], key: str) -> list[str]:
    return [text(j.get(key)) for j in table_rows(row, "TABLE_jobs", "ROW_jobs") if j.get(key)]


def _values_for(when: str) -> dict[str, dict[str, str]]:
    """The time form a schedule's ``time ...`` line fills in."""
    words = when.split()
    if len(words) < 3 or words[0] != "time":
        return {}
    if words[1] == "daily":
        return {"daily": {"at": words[2]}}
    if words[1] in ("weekly", "monthly") and words[2].count(":") == 2:
        day, at = words[2].split(":", 1)
        if words[1] == "weekly" and day.isdigit() and 1 <= int(day) <= 7:
            day = DAYS[int(day) - 1]
        return {words[1]: {"day": day.lstrip("0") if words[1] == "monthly" else day, "at": at}}
    return {}


def parse_scheduler(bodies: list[Any]) -> ProtocolView:
    """The page from ``show scheduler config``, ``show scheduler schedule`` and ``show
    scheduler logfile`` (bodies in that order; each empty while there is nothing)."""
    config = bodies[0] if bodies else None
    states = bodies[1] if len(bodies) > 1 else None
    log = bodies[2] if len(bodies) > 2 else None
    size = ""
    if isinstance(config, dict):
        match = re.search(r"logfile size (\d+)", text(config.get("logfilesize")))
        size = match.group(1) if match else ""
    instances: list[Instance] = [
        Instance(
            "scheduler",
            {},
            "Scheduler",
            (("Log size", f"{size} KB" if size else "-"),),
            {"logfile": {"kb": size}} if size else {},
        )
    ]
    jobs = parse_jobs(config)
    for name, lines in jobs.items():
        instances.append(
            Instance("job", {"job": name}, name, (("Commands", ", ".join(lines) or "none"),))
        )
    status = {
        text(row.get("schedulename")): row
        for row in table_rows(states, "TABLE_schedules", "ROW_schedules")
    }
    for row in table_rows(config, "TABLE_scheduleconfig", "ROW_scheduleconfig"):
        name = text(row.get("schedulename"))
        when = text(row.get("scheduletype")).strip()
        state = status.get(name, {})
        results = {
            text(j.get("jobname")): _value(j.get("execstatus"))
            for j in table_rows(state, "TABLE_jobs", "ROW_jobs")
        }
        listed = _job_names(row, "status") or list(results)
        facts = (
            ("When", when or "no time: it never runs"),
            ("Runs", _value(state.get("scheduletype")) or "-"),
            ("Made by", text(state.get("scheduleusername")) or "-"),
            ("Last run", _value(state.get("lastexectime")) or "-"),
            ("Times run", _value(state.get("execcount")) or "0"),
            (
                "Jobs",
                ", ".join(f"{j} ({results[j]})" if results.get(j) else j for j in listed) or "none",
            ),
        )
        instances.append(Instance("schedule", {"schedule": name}, name, facts, _values_for(when)))
    rows = tuple(
        (
            text(row.get("jobname")),
            text(row.get("schedulename")),
            text(row.get("scheduleusername")),
            text(row.get("completiontime")).strip(),
            "Success"
            if text(row.get("jobstatus")) == "0"
            else f"Failed ({text(row.get('jobstatus'))})",
            text(row.get("joboutput")).strip(),
        )
        for row in table_rows(log, "TABLE_joblog", "ROW_joblog")
    )
    tables = (
        Table(
            "Log",
            ("Job", "Schedule", "Made by", "Finished", "Result", "Output"),
            rows,
            empty="No job has run yet (or the log was cleared).",
            note="The switch keeps the log for the account that reads it: runs of jobs "
            "made by other accounts may be missing.",
            wrap_column=5,
        ),
    )
    return ProtocolView(tuple(instances), tables)


SCHEDULER = Protocol(
    key="scheduler",
    name="Scheduler",
    summary="Jobs the switch runs on its own, at the times their schedules give",
    features=(FEATURE,),
    commands=COMMANDS,
    parse=parse_scheduler,
    scopes=(_SCHEDULER, _JOB, _SCHEDULE),
    about=(
        "Make a job from the commands offered (such as copying the configuration to a "
        "bootflash file), then a schedule that runs it every night or at a set time."
    ),
)


@dataclass(frozen=True)
class SchedulerPage:
    """Everything the Scheduler page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # the front ports and port-channels
    problem: str = ""
    missing: tuple[str, ...] = ()  # the feature, when it is off


def load_scheduler_page(client: NxapiClient) -> SchedulerPage:
    """One request for the feature and the ports; while scheduler is on, one for the
    configuration, the schedules and the log."""
    feature, brief = client.show(*PAGE_COMMANDS)
    ports = tuple(port_and_channel_names(brief))
    if not feature_states(feature).get(FEATURE, False):
        return SchedulerPage(SCHEDULER, ProtocolView(), ports, missing=(FEATURE,))
    return SchedulerPage(SCHEDULER, parse_scheduler(client.show(*COMMANDS)), ports)


def build_scheduler_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Scheduler page; making a job turns the picked menu entries
    into its lines."""
    change = build_change(SCHEDULER, scope, setting, action, ident, values)
    if (scope, setting, action) != ("job", "make", "set"):
        return change
    made = _JOB.setting("make")
    if made is None:  # pragma: no cover - defined above
        raise ValueError("the job form is missing")
    checked = {f.name: check_value(f, values.get(f.name, "")) for f in made.fields}
    picked = [checked[f"command{n}"] for n in range(1, JOB_COMMANDS + 1) if checked[f"command{n}"]]
    lines: list[str] = []
    for entry in picked:
        lines += menu_lines(entry, checked["port"], checked["file"], checked["show"])
    job = change.lines[0]
    return dataclasses.replace(
        change,
        lines=(job, *lines),
        labels=(job, *lines),
        describe=f"Scheduler: make job {job.rsplit(' ', 1)[-1]} to " + "; then ".join(picked) + ".",
    )
