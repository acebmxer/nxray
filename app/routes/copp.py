"""The Control-plane policing page: the CoPP policy on the control plane, its classes and
what each passed or dropped, on the same parts as the Priority flow control page.

``GET /copp`` shows it. The page changes nothing, so it has no change route.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.copp import COPP, load_copp_page
from app.dependencies import login_required
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, render_site_page

router = APIRouter()


def _no_place(page: Any, ident: dict[str, str]) -> None:
    """The page has no places to check."""


def _no_change(*_: Any) -> ProtocolChange:
    """The page sends nothing; never reached, as it has no change route."""
    raise ValueError("the Control-plane policing page changes nothing")


SITE = ProtocolSite(
    url="/copp",
    back_url="/ports",
    back_label="Ports",
    save_back={"back": "copp"},
    changes_name="Control-plane policing",
    subject="control-plane policing",
    off_message="",
    enabled=lambda connection: False,
    load=load_copp_page,
    check_place=_no_place,
    build=_no_change,
    send=_no_change,
    scroll_tables=True,
    read_only=True,
)


def render_copp_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
) -> Response:
    """Read the switch fresh and show the Control-plane policing page, with a message."""
    return render_site_page(request, username, COPP, SITE, error=error, notice=notice)


@router.get("/copp", response_class=HTMLResponse)
def copp_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /copp``: the control-plane policy and its counters, read live; every role
    looks."""
    return render_copp_page(request, username)
