"""How a browser wants NXray to look and behave: the colour theme, the menu's
width and how often figures refresh themselves.

Kept in cookies, per browser, like the switch picker's choice: neither is a
secret and neither changes anything on a switch. Templates read them through
``ui_preferences`` (a template global) to set the page's theme and menu.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request, Response

from app.live import DEFAULT_CHOICE, LIVE_CHOICES

THEME_COOKIE = "nxray_theme"
MENU_COOKIE = "nxray_menu"
LIVE_COOKIE = "nxray_live"
PREFERENCE_COOKIE_DAYS = 365

# "system" follows the computer's light or dark setting.
THEMES = {"system": "System", "light": "Light", "dark": "Dark"}
MENUS = ("wide", "narrow")


@dataclass(frozen=True)
class UiPreferences:
    theme: str = "system"
    menu: str = "wide"
    live: str = DEFAULT_CHOICE


def ui_preferences(request: Request) -> UiPreferences:
    """The theme and menu width this browser picked; the defaults for anything unknown."""
    theme = request.cookies.get(THEME_COOKIE, "")
    menu = request.cookies.get(MENU_COOKIE, "")
    live = request.cookies.get(LIVE_COOKIE, "")
    return UiPreferences(
        theme=theme if theme in THEMES else "system",
        menu=menu if menu in MENUS else "wide",
        live=live if live in LIVE_CHOICES else DEFAULT_CHOICE,
    )


def remember_preferences(
    request: Request, response: Response, *, theme: str = "", menu: str = "", live: str = ""
) -> Response:
    """Set the cookies for whichever of ``theme``, ``menu`` and ``live`` is a known value."""
    for key, value, allowed in (
        (THEME_COOKIE, theme, THEMES),
        (MENU_COOKIE, menu, MENUS),
        (LIVE_COOKIE, live, LIVE_CHOICES),
    ):
        if value in allowed:
            response.set_cookie(
                key=key,
                value=value,
                max_age=PREFERENCE_COOKIE_DAYS * 86400,
                httponly=True,
                samesite="lax",
                secure=request.app.state.settings.https_only,
            )
    return response
