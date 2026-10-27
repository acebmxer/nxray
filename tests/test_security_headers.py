"""Security headers go out on every kind of response."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.dependencies import SECURITY_HEADERS


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
    for path in ("/", "/login"):
        body = logged_in.get(path, follow_redirects=True).text.lower()
        assert "<script" not in body, path
        assert "<style" not in body, path
        assert " style=" not in body, path
