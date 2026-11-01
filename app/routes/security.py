"""The ACLs, Port security and DHCP and ARP pages, on the same parts as the routing
protocol pages.

``GET /security/acls``, ``GET /security/port-security`` and ``GET
/security/dhcp`` show them; every change goes through ``POST
/security/acls/change``, ``POST /security/port-security/change`` or ``POST
/security/dhcp/change`` with the same form fields as a protocol page (scope,
setting, action, ``id_<name>``, ``v_<name>``) and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.acls import ACLS, AclPage, build_acl_change, load_acls_page, needs_v14
from app.dependencies import login_required, operator_required
from app.dhcp_security import DHCP, DhcpPage, build_dhcp_change, load_dhcp_page
from app.nxapi import NxapiClient
from app.port_security import (
    PORT_SECURITY,
    PortSecurityPage,
    build_port_security_change,
    load_port_security_page,
)
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.switch_connection import SwitchConnection

router = APIRouter()

SECURITY_CHANGES_OFF = (
    "Security and config changes are off. An NXray admin turns them on on the Switch page "
    "first: NXray's role on the switch does not allow them yet."
)
LAYER2_CHANGES_OFF = (
    "Layer 2 security changes are off. An NXray admin turns them on on the Switch page "
    "first: NXray's role on the switch does not allow them yet."
)


def acl_needs(connection: SwitchConnection, scope: str, setting: str) -> str:
    """Why the ACLs page may not make a change yet: MAC ACLs, object groups, VLAN
    access maps and TCAM regions need role version 14."""
    if needs_v14(scope, setting) and not connection.layer2_security_changes_enabled:
        return (
            "Not changed: MAC ACLs, object groups, VLAN access maps and TCAM regions need "
            "NXray's newer role on the switch. An NXray admin turns on layer 2 security "
            "changes on the Switch page."
        )
    return ""


def check_acl_place(page: AclPage, ident: dict[str, str]) -> None:
    """Refuse an interface or port the switch does not have (or that is the other
    kind: routed where a switched port is needed, or the other way round)."""
    interface = ident.get("interface", "").strip()
    if interface and interface not in page.interfaces:
        raise ValueError(
            f"{interface} is not a VLAN interface (up to Vlan254), routed port or routed "
            "port-channel on the switch"
        )
    port = ident.get("port", "").strip()
    if port and port not in page.ports:
        raise ValueError(f"{port} is not a front port or port-channel carrying VLANs")


def check_port_security_place(page: PortSecurityPage, ident: dict[str, str]) -> None:
    """Refuse a port that is not a switched front port."""
    port = ident.get("port", "").strip()
    if port and port not in page.ports:
        raise ValueError(
            f"{port} is not a front port carrying VLANs; port security works on switched "
            "front ports only"
        )


def _send_acl(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_acl(change.scope, change.setting, change.action, ident, values)


def check_dhcp_place(page: DhcpPage, ident: dict[str, str]) -> None:
    """Refuse a port or interface the switch does not have (or that is the other
    kind)."""
    port = ident.get("port", "").strip()
    if port and port not in page.ports:
        raise ValueError(f"{port} is not a front port or port-channel carrying VLANs")
    interface = ident.get("interface", "").strip()
    if interface and interface not in page.interfaces:
        raise ValueError(
            f"{interface} is not a VLAN interface (up to Vlan254), routed port or routed "
            "port-channel on the switch"
        )


def _send_dhcp(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_dhcp(change.scope, change.setting, change.action, ident, values)


def _send_port_security(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_port_security(change.scope, change.setting, change.action, ident, values)


ACL_SITE = ProtocolSite(
    url="/security/acls",
    back_url="/",
    back_label="Dashboard",
    save_back={"back": "acls"},
    changes_name="Security and config",
    subject="ACLs",
    off_message=SECURITY_CHANGES_OFF,
    enabled=lambda connection: connection.security_changes_enabled,
    load=load_acls_page,
    check_place=check_acl_place,
    build=build_acl_change,
    send=_send_acl,
    links=(
        ("/security/port-security", "Port security: which devices each port accepts"),
        ("/security/dhcp", "DHCP and ARP: DHCP snooping and relay, ARP inspection"),
    ),
    needs=lambda connection, scope, setting: acl_needs(connection, scope, setting),
)

PORT_SECURITY_SITE = ProtocolSite(
    url="/security/port-security",
    back_url="/security/acls",
    back_label="ACLs",
    save_back={"back": "port-security"},
    changes_name="Security and config",
    subject="port security",
    off_message=SECURITY_CHANGES_OFF,
    enabled=lambda connection: connection.security_changes_enabled,
    load=load_port_security_page,
    check_place=check_port_security_place,
    build=build_port_security_change,
    send=_send_port_security,
    links=(
        ("/security/acls", "ACLs: which packets the switch lets through"),
        ("/security/dhcp", "DHCP and ARP: DHCP snooping and relay, ARP inspection"),
    ),
)

DHCP_SITE = ProtocolSite(
    url="/security/dhcp",
    back_url="/security/acls",
    back_label="ACLs",
    save_back={"back": "dhcp"},
    changes_name="Layer 2 security",
    subject="DHCP and ARP",
    off_message=LAYER2_CHANGES_OFF,
    enabled=lambda connection: connection.layer2_security_changes_enabled,
    load=load_dhcp_page,
    check_place=check_dhcp_place,
    build=build_dhcp_change,
    send=_send_dhcp,
    links=(
        ("/security/acls", "ACLs: which packets the switch lets through, and TCAM space"),
        ("/security/port-security", "Port security: which devices each port accepts"),
    ),
)


def render_acls_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the ACLs page, with a message."""
    return render_site_page(
        request, username, ACLS, ACL_SITE, error=error, notice=notice, form=form
    )


def render_port_security_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Port security page, with a message."""
    return render_site_page(
        request, username, PORT_SECURITY, PORT_SECURITY_SITE, error=error, notice=notice, form=form
    )


@router.get("/security/acls", response_class=HTMLResponse)
def acls_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /security/acls``: the IPv4 and IPv6 ACLs and where they apply, read live;
    every role looks, operators and admins change."""
    return render_acls_page(request, username)


@router.post("/security/acls/change", response_class=HTMLResponse)
def acls_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the ACLs page. Without confirm=yes, asks first."""
    return site_change(request, username, form, ACLS, ACL_SITE)


@router.get("/security/port-security", response_class=HTMLResponse)
def port_security_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /security/port-security``: each port's port security, read live; every role
    looks, operators and admins change."""
    return render_port_security_page(request, username)


@router.post("/security/port-security/change", response_class=HTMLResponse)
def port_security_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Port security page. Without confirm=yes, asks first."""
    return site_change(request, username, form, PORT_SECURITY, PORT_SECURITY_SITE)


def render_dhcp_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the DHCP and ARP page, with a message."""
    return render_site_page(
        request, username, DHCP, DHCP_SITE, error=error, notice=notice, form=form
    )


@router.get("/security/dhcp", response_class=HTMLResponse)
def dhcp_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /security/dhcp``: DHCP snooping and relay, ARP inspection and IP Source
    Guard, read live; every role looks, operators and admins change."""
    return render_dhcp_page(request, username)


@router.post("/security/dhcp/change", response_class=HTMLResponse)
def dhcp_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the DHCP and ARP page. Without confirm=yes, asks first."""
    return site_change(request, username, form, DHCP, DHCP_SITE)
