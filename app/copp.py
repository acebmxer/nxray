"""Control-plane policing (CoPP): the policy that limits the traffic sent to the switch's
own CPU, its classes, their rate limits and what each class passed or dropped.

The switch puts every packet meant for its CPU (routing protocols, ARP, LLDP, SSH, ...)
into one of the classes of the policy applied to the control plane, and polices each
class to a rate so a flood cannot overload the CPU. The page only shows it; it is built
on the same parts as the Priority flow control page (``app/protocols.py``), with no
scopes.

Read from the switch: ``show policy-map interface control-plane`` (JSON). Read on
cisco-25gb (NX-OS 9.3(16), 2026-11-10): the policy is ``copp-system-p-policy-strict``
with 25 classes; each class row has its matches (access groups, exceptions, protocols),
``set cos``, the police rate and burst, and per module the bytes that conformed
(transmitted) and violated (dropped) with their 5-minute rates in bytes per second.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.nxapi import NxapiClient
from app.ports import human_bytes, human_rate
from app.protocols import Protocol, ProtocolView, Table, table_rows
from app.switch import int_or, text

COMMAND = "show policy-map interface control-plane"

# Cisco's built-in profiles name their policy copp-system-p-policy-<profile>.
_PROFILE = re.compile(r"copp-system-p-policy-(strict|moderate|lenient|dense)")


def _matches(row: dict[str, Any]) -> str:
    """A class's match lines in a few words: "access-group copp-system-p-acl-bgp,
    exception glean, protocol arp"."""
    found: list[str] = []
    for match in table_rows(row, "TABLE_match", "ROW_match"):
        if group := text((match.get("access_grp") or {}).get("acc_grp_name")):
            found.append(f"access-group {group}")
        if exception := text((match.get("exception") or {}).get("opt_match_excpt")):
            found.append(f"exception {exception}")
        if proto := text((match.get("protocol") or {}).get("opt_match_protocol")):
            found.append(f"protocol {proto}")
    return ", ".join(found) or "-"


def _amount(value: Any, unit: Any) -> str:
    """A rate or size with its unit ("800 kbps", "32000 bytes"), or "-"."""
    amount = text(value)
    return f"{amount} {text(unit)}".strip() if amount else "-"


def parse_copp(bodies: list[dict[str, Any]]) -> ProtocolView:
    """The control-plane policy from ``show policy-map interface control-plane``: a note
    naming it, and a table of its classes with their limits and counters, the counters of
    every module added up."""
    body = bodies[0] if bodies else {}
    name = text((body or {}).get("pmap-name"))
    if not name:
        return ProtocolView(notes=("No CoPP policy is applied to the control plane.",))
    profile = _PROFILE.fullmatch(name)
    notes = (
        f"Policy on the control plane: {name}"
        + (f" (Cisco's {profile.group(1)} profile)." if profile else "."),
    )
    classes: list[tuple[str, ...]] = []
    for row in table_rows(body, "TABLE_cmap", "ROW_cmap"):
        cls = text(row.get("cmap-name-out")) or text(row.get("cmap-key"))
        if not cls:
            continue
        cos = text((row.get("cos") or {}).get("cos-val"))
        slots = table_rows(row, "TABLE_slot", "ROW_slot")
        passed = sum(int_or(s.get("conform-bytes")) for s in slots)
        dropped = sum(int_or(s.get("violate-bytes")) for s in slots)
        offered = sum(int_or(s.get("conform-avg-rate")) for s in slots)
        dropping = sum(int_or(s.get("violate-avg-rate")) for s in slots)
        classes.append(
            (
                cls,
                _matches(row),
                cos or "-",
                _amount(row.get("cir"), row.get("opt_kbps_mbps_gbps_pps_cir")),
                _amount(row.get("bc"), row.get("opt_kbytes_mbytes_gbytes_bc")),
                human_bytes(passed),
                human_bytes(dropped),
                human_rate(offered * 8),
                human_rate(dropping * 8),
            )
        )
    table = Table(
        "Classes",
        (
            "Class",
            "Matches",
            "CoS",
            "Rate limit",
            "Burst",
            "Passed",
            "Dropped",
            "Offered (5 min)",
            "Dropped (5 min)",
        ),
        tuple(classes),
        empty="The policy has no classes.",
        wrap_column=1,
        note="Passed and dropped count bytes since the counters were last cleared. Traffic "
        "over a class's rate limit is dropped before it reaches the switch's CPU.",
    )
    return ProtocolView(tables=(table,), notes=notes)


COPP = Protocol(
    key="copp",
    name="Control-plane policing",
    summary="The limits on traffic sent to the switch's own CPU, per class, with what each "
    "class passed and dropped (CoPP)",
    features=(),
    commands=(COMMAND,),
    parse=parse_copp,
    scopes=(),
)


@dataclass(frozen=True)
class CoppPage:
    """Everything the Control-plane policing page shows."""

    protocol: Protocol
    view: ProtocolView
    problem: str = ""
    missing: tuple[str, ...] = ()  # CoPP needs no feature; kept for the template


def load_copp_page(client: NxapiClient) -> CoppPage:
    """One request for the control-plane policy and its counters."""
    (body,) = client.show(COMMAND)
    return CoppPage(COPP, parse_copp([body]))
