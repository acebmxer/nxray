"""Control-plane policing (app/copp.py): reading the policy, its classes and counters."""

from __future__ import annotations

from app.copp import parse_copp
from tests.conftest import load_fixture

BODY = load_fixture("show_policy-map_interface_control-plane")


def _classes() -> dict[str, tuple[str, ...]]:
    return {row[0]: row for row in parse_copp([BODY]).tables[0].rows}


def test_the_policy_is_named_with_its_profile() -> None:
    assert parse_copp([BODY]).notes == (
        "Policy on the control plane: copp-system-p-policy-strict (Cisco's strict profile).",
    )


def test_every_class_is_in_the_table_in_the_switch_order() -> None:
    rows = parse_copp([BODY]).tables[0].rows
    assert len(rows) == 25
    assert rows[0][0] == "copp-system-p-class-l3uc-data"
    assert rows[-1][0] == "class-default"


def test_a_class_shows_its_matches_limit_and_counters() -> None:
    important = _classes()["copp-system-p-class-important"]
    assert important[1].startswith(
        "access-group copp-system-p-acl-hsrp, access-group copp-system-p-acl-vrrp"
    )
    assert important[2:5] == ("6", "2500 kbps", "1280000 bytes")
    assert important[5] == "24.4 MB"  # 25534830 bytes conformed
    assert important[6] == "0 B"


def test_exception_and_protocol_matches() -> None:
    assert _classes()["copp-system-p-class-l3uc-data"][1] == "exception glean"
    assert _classes()["copp-system-p-class-normal"][1] == (
        "access-group copp-system-p-acl-mac-dot1x, protocol arp"
    )
    assert _classes()["class-default"][1] == "-"


def test_a_police_rate_in_mbps() -> None:
    assert _classes()["copp-system-p-class-l2-unpoliced"][3] == "50 mbps"


def test_the_modules_are_added_up_and_rates_are_bits() -> None:
    body = {
        "pmap-name": "my-copp",
        "TABLE_cmap": {
            "ROW_cmap": {
                "cmap-name-out": "c1",
                "cir": "100",
                "opt_kbps_mbps_gbps_pps_cir": "pps",
                "TABLE_slot": {
                    "ROW_slot": [
                        {"conform-bytes": "1000", "violate-bytes": "10", "violate-avg-rate": "5"},
                        {"conform-bytes": "24", "violate-bytes": "2", "conform-avg-rate": "250"},
                    ]
                },
            }
        },
    }
    view = parse_copp([body])
    assert view.notes == ("Policy on the control plane: my-copp.",)
    assert view.tables[0].rows == (
        ("c1", "-", "-", "100 pps", "-", "1.0 KB", "12 B", "2.0 kb/s", "40 b/s"),
    )


def test_no_policy_is_said_plainly() -> None:
    for body in ({}, None):
        view = parse_copp([body])  # type: ignore[list-item]
        assert view.tables == ()
        assert view.notes == ("No CoPP policy is applied to the control plane.",)
    assert parse_copp([]).notes == ("No CoPP policy is applied to the control plane.",)
