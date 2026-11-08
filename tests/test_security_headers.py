"""Security headers go out on every kind of response."""

from __future__ import annotations

import re
from collections.abc import Callable

from fastapi.testclient import TestClient

from app.config import Settings
from app.dependencies import HSTS_VALUE, SECURITY_HEADERS
from tests.conftest import with_settings


def _assert_headers(response) -> None:
    for name, value in SECURITY_HEADERS.items():
        assert response.headers.get(name) == value, name


def test_headers_on_pages_redirects_and_static(client: TestClient) -> None:
    _assert_headers(client.get("/login"))
    _assert_headers(client.get("/"))  # the redirect to /login
    _assert_headers(client.get("/healthz"))
    _assert_headers(client.get("/static/style.css"))
    _assert_headers(client.get("/no-such-page"))


def test_framing_is_refused(client: TestClient) -> None:
    response = client.get("/login")
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_pages_use_no_inline_script_or_style(logged_in: TestClient) -> None:
    # The Content-Security-Policy forbids inline script and style, so a page
    # that used either would silently break in the browser.
    # A script file served by NXray itself is allowed ('self'); script written
    # into the page is not.
    for path in ("/", "/login"):
        body = logged_in.get(path, follow_redirects=True).text.lower()
        for tag in re.findall(r"<script[^>]*>", body):
            assert 'src="/static/' in tag, path
        assert "<style" not in body, path
        assert " style=" not in body, path


def test_no_hsts_while_https_is_off(client: TestClient) -> None:
    assert "strict-transport-security" not in client.get("/login").headers


def test_hsts_is_sent_on_every_kind_of_response_when_https_is_on(
    settings: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    client = make_client(with_settings(settings, https_only=True))
    for path in ("/login", "/", "/healthz", "/static/style.css", "/no-such-page"):
        header = client.get(path).headers.get("strict-transport-security")
        assert header == HSTS_VALUE, path
    assert "includesubdomains" not in HSTS_VALUE.lower()
