"""The NX-API client, against a mock transport (no switch, no network)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app.nxapi import (
    NxapiAuthError,
    NxapiClient,
    NxapiCommandError,
    NxapiProtocolError,
    NxapiUnreachable,
    SwitchTarget,
    build_payload,
    error_message,
    is_valid_host,
    parse_response,
    validate_show_command,
)

TARGET = SwitchTarget(
    host="192.0.2.10", port=443, username="nxray", password="s3cret-pw", timeout=5.0
)


def _ok(index: int, body: dict[str, Any] | None) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "result": {"body": body} if body is not None else None, "id": index}


def _client(handler) -> NxapiClient:
    return NxapiClient(TARGET, transport=httpx.MockTransport(handler))


# ---- input checks -------------------------------------------------------


@pytest.mark.parametrize("value", ["192.0.2.10", "2001:db8::1", "switch", "nexus-lab.example.net"])
def test_valid_hosts(value: str) -> None:
    assert is_valid_host(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "https://192.0.2.10",
        "192.0.2.10:8443",
        "192.0.2.10/ins",
        "user@192.0.2.10",
        "-bad.example",
        "a" * 254,
        "host name",
    ],
)
def test_invalid_hosts(value: str) -> None:
    assert not is_valid_host(value)


def test_show_command_is_stripped() -> None:
    assert validate_show_command("  show version ") == "show version"


@pytest.mark.parametrize(
    "command",
    [
        "configure terminal",
        "copy running-config startup-config",
        "showversion",
        "show version ; configure terminal",
        "show version\nreload",
        "show version\rreload",
    ],
)
def test_anything_but_a_lone_show_is_refused(command: str) -> None:
    with pytest.raises(ValueError):
        validate_show_command(command)


def test_url_brackets_ipv6() -> None:
    target = SwitchTarget(host="2001:db8::1", port=443, username="u", password="p", timeout=1)
    assert target.url == "https://[2001:db8::1]:443/ins"
    assert TARGET.url == "https://192.0.2.10:443/ins"


def test_password_never_appears_in_repr() -> None:
    assert "s3cret-pw" not in repr(TARGET)
    assert "s3cret-pw" not in str(TARGET)
    assert "nxray" in repr(TARGET)


# ---- request and reply shapes -------------------------------------------


def test_payload_is_one_json_rpc_entry_per_command() -> None:
    assert build_payload(["show version", "show clock"]) == [
        {
            "jsonrpc": "2.0",
            "method": "cli",
            "params": {"cmd": "show version", "version": 1},
            "id": 1,
        },
        {"jsonrpc": "2.0", "method": "cli", "params": {"cmd": "show clock", "version": 1}, "id": 2},
    ]


def test_single_command_reply_as_an_object_is_accepted() -> None:
    # NX-API answers a one-command request with an object, not a list.
    assert parse_response(_ok(1, {"a": 1}), ["show x"]) == [{"a": 1}]


def test_replies_are_matched_by_id_not_position() -> None:
    reply = [_ok(2, {"second": True}), _ok(1, {"first": True})]
    assert parse_response(reply, ["show a", "show b"]) == [{"first": True}, {"second": True}]


def test_command_with_no_output_gives_an_empty_body() -> None:
    assert parse_response([_ok(1, None)], ["show x"]) == [{}]


def test_wrong_number_of_replies_is_a_protocol_error() -> None:
    with pytest.raises(NxapiProtocolError):
        parse_response([_ok(1, {})], ["show a", "show b"])


def test_reply_without_id_is_a_protocol_error() -> None:
    with pytest.raises(NxapiProtocolError):
        parse_response([{"jsonrpc": "2.0", "result": {"body": {}}}], ["show a"])


def test_text_body_is_a_protocol_error() -> None:
    reply = {"jsonrpc": "2.0", "result": {"body": "plain text"}, "id": 1}
    with pytest.raises(NxapiProtocolError):
        parse_response(reply, ["show a"])


def test_rejected_command_reports_the_switch_message() -> None:
    reply = {
        "jsonrpc": "2.0",
        "error": {
            "code": -32602,
            "message": "Invalid params",
            "data": {"msg": "% Invalid command at '^' marker.\n"},
        },
        "id": 1,
    }
    with pytest.raises(NxapiCommandError) as excinfo:
        parse_response(reply, ["show nonsense"])
    assert "Invalid command" in str(excinfo.value)
    assert "show nonsense" in str(excinfo.value)


def test_error_message_falls_back() -> None:
    assert error_message({"message": "Invalid params"}) == "Invalid params"
    assert error_message({"data": {"msg": "  "}, "message": "fallback"}) == "fallback"
    assert error_message("garbage") == "unknown error"


# ---- the client over HTTP -----------------------------------------------


def test_show_posts_json_rpc_with_basic_auth() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["type"] = request.headers.get("content-type")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=[_ok(1, {"host_name": "nexus-lab"}), _ok(2, {})])

    with _client(handler) as client:
        bodies = client.show("show version", "show clock")

    assert bodies == [{"host_name": "nexus-lab"}, {}]
    assert seen["url"] == "https://192.0.2.10/ins"  # httpx drops the default port
    assert seen["auth"].startswith("Basic ")
    assert seen["type"] == "application/json-rpc"
    assert [entry["params"]["cmd"] for entry in seen["body"]] == ["show version", "show clock"]


def test_a_bad_command_is_refused_before_anything_is_sent() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("nothing may reach the switch")

    with _client(handler) as client, pytest.raises(ValueError):
        client.show("show version", "configure terminal")


def test_no_commands_is_refused() -> None:
    with _client(lambda request: httpx.Response(200)) as client, pytest.raises(ValueError):
        client.show()


@pytest.mark.parametrize("status", [401, 403])
def test_refused_login_is_an_auth_error(status: int) -> None:
    with _client(lambda request: httpx.Response(status)) as client:
        with pytest.raises(NxapiAuthError):
            client.show("show version")


def test_http_500_with_a_json_rpc_error_is_a_command_error() -> None:
    reply = {"jsonrpc": "2.0", "error": {"message": "Input CLI command error"}, "id": 1}
    with _client(lambda request: httpx.Response(500, json=reply)) as client:
        with pytest.raises(NxapiCommandError):
            client.show("show nonsense")


def test_non_json_answer_is_a_protocol_error() -> None:
    with _client(lambda request: httpx.Response(200, text="<html>hi</html>")) as client:
        with pytest.raises(NxapiProtocolError) as excinfo:
            client.show("show version")
    assert "HTTP 200" in str(excinfo.value)


def test_timeout_is_unreachable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out", request=request)

    with _client(handler) as client, pytest.raises(NxapiUnreachable) as excinfo:
        client.show("show version")
    assert "within 5 seconds" in str(excinfo.value)


def test_connection_refused_is_unreachable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with _client(handler) as client, pytest.raises(NxapiUnreachable):
        client.show("show version")


def test_errors_never_carry_the_password() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with _client(handler) as client, pytest.raises(NxapiUnreachable) as excinfo:
        client.show("show version")
    assert "s3cret-pw" not in str(excinfo.value)


def test_certificate_is_not_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    # Project decision: the switch's self-signed certificate is accepted.
    captured: dict[str, Any] = {}
    real_client = httpx.Client

    def spy(*args: Any, **kwargs: Any) -> httpx.Client:
        captured.update(kwargs)
        return real_client(*args, **kwargs)

    monkeypatch.setattr("app.nxapi.httpx.Client", spy)
    NxapiClient(TARGET).close()
    assert captured["verify"] is False


# ---- the guarded configuration commands ---------------------------------


def _recording_client(seen: list[str], reply: dict[str, Any] | None = None) -> NxapiClient:
    def handler(request: httpx.Request) -> httpx.Response:
        (entry,) = json.loads(request.content)
        seen.append(entry["params"]["cmd"])
        return httpx.Response(200, json=reply or {"jsonrpc": "2.0", "result": None, "id": 1})

    return _client(handler)


def test_create_user_sends_exactly_one_username_command() -> None:
    seen: list[str] = []
    with _recording_client(seen) as client:
        client.create_user("nxray-dev", "Abc1Def2Ghi3", "network-operator")
    assert seen == ["username nxray-dev password Abc1Def2Ghi3 role network-operator"]


@pytest.mark.parametrize(
    ("name", "password", "role"),
    [
        ("nxray ; reload", "Abc1Def2Ghi3", "network-operator"),
        ("admin", "Abc1Def2Ghi3", "network-operator"),
        ("nxray", "has space 123A", "network-operator"),
        ("nxray", "semi;colon1A", "network-operator"),
        ("nxray", "Short1", "network-operator"),
        ("nxray", "Abc1Def2Ghi3", "network-admin"),
    ],
)
def test_create_user_refuses_unsafe_values_before_sending(
    name: str, password: str, role: str
) -> None:
    seen: list[str] = []
    with _recording_client(seen) as client, pytest.raises(ValueError):
        client.create_user(name, password, role)
    assert seen == []


def test_create_user_error_names_the_command_without_the_password() -> None:
    reply = {"jsonrpc": "2.0", "error": {"message": "Password is weak"}, "id": 1}
    with _client(lambda request: httpx.Response(500, json=reply)) as client:
        with pytest.raises(NxapiCommandError) as excinfo:
            client.create_user("nxray", "Abc1Def2Ghi3", "network-operator")
    assert "Abc1Def2Ghi3" not in str(excinfo.value)
    assert "username nxray password ... role network-operator" in str(excinfo.value)
    assert "Password is weak" in str(excinfo.value)


def test_delete_user_and_save_config_send_their_one_command() -> None:
    seen: list[str] = []
    with _recording_client(seen) as client:
        client.delete_user("nxray-dev")
        client.save_config()
    assert seen == ["no username nxray-dev", "copy running-config startup-config"]


def test_delete_user_refuses_a_bad_name() -> None:
    seen: list[str] = []
    with _recording_client(seen) as client, pytest.raises(ValueError):
        client.delete_user("nxray\nreload")
    assert seen == []


def test_give_role_sends_one_username_role_command() -> None:
    seen: list[str] = []
    with _recording_client(seen) as client:
        client.give_role("nxray-dev", "nxray-ports")
    assert seen == ["username nxray-dev role nxray-ports"]


@pytest.mark.parametrize(
    ("name", "role"),
    [
        ("nxray-dev", "network-admin"),
        ("nxray-dev", "nxray-ports ; reload"),
        ("nxray dev", "nxray-ports"),
        ("admin", "nxray-ports"),
    ],
)
def test_give_role_refuses_any_other_role_or_a_bad_name(name: str, role: str) -> None:
    seen: list[str] = []
    with _recording_client(seen) as client, pytest.raises(ValueError):
        client.give_role(name, role)
    assert seen == []


def test_save_config_text_answers() -> None:
    def reply(text: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "result": {"body": text}, "id": 1}

    with _recording_client([], reply("[########] 100%\nCopy complete.\n")) as client:
        client.save_config()  # success text is fine
    with _recording_client([], reply("Copy failed: no space\n")) as client:
        with pytest.raises(NxapiCommandError) as excinfo:
            client.save_config()
    assert "Copy failed" in str(excinfo.value)


def test_save_config_gets_a_longer_timeout() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["timeout"] = request.extensions["timeout"]
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": None, "id": 1})

    with _client(handler) as client:
        client.save_config()
    assert seen["timeout"]["read"] == 120.0


def test_two_saves_at_once_both_succeed() -> None:
    # A double-clicked Save config: the second press lands while the first
    # copy runs, which cisco-25gb refuses. NXray must wait, not pass it on.
    import threading
    import time

    from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

    switch = FakeSwitch(save_seconds=0.5)
    target = SwitchTarget("192.0.2.10", 443, "admin", ADMIN_PASSWORD, 5.0)
    results: list[str] = []

    def press() -> None:
        try:
            with NxapiClient(target, transport=switch.transport()) as client:
                client.save_config()
            results.append("saved")
        except NxapiCommandError as exc:
            results.append(f"error: {exc}")

    threads = [threading.Thread(target=press) for _ in range(2)]
    for thread in threads:
        thread.start()
        time.sleep(0.2)
    for thread in threads:
        thread.join()
    assert results == ["saved", "saved"]
    assert [r for r in switch.requests if r == ["copy running-config startup-config"]] == [
        ["copy running-config startup-config"]
    ] * 2


def test_a_save_stuck_behind_another_gives_up_with_a_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.nxapi as nxapi

    monkeypatch.setattr(nxapi, "SAVE_CONFIG_TIMEOUT", 0.1)
    target = SwitchTarget("192.0.2.10", 443, "nxray", "s3cret-pw", 0.1)
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.content.decode())
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": None, "id": 1})

    assert nxapi._save_lock.acquire(timeout=1)
    try:
        with NxapiClient(target, transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(NxapiCommandError) as excinfo:
                client.save_config()
    finally:
        nxapi._save_lock.release()
    assert "another save from NXray is still running" in str(excinfo.value)
    assert seen == []  # nothing reached the switch


def test_show_still_refuses_text_bodies() -> None:
    reply = {"jsonrpc": "2.0", "result": {"body": "text"}, "id": 1}
    with _client(lambda request: httpx.Response(200, json=reply)) as client:
        with pytest.raises(NxapiProtocolError):
            client.show("show version")
