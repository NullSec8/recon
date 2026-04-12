"""Target normalization and enrichment helpers."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from recon.models import TargetInfo


def _is_ip(value: str) -> bool:
    """Return True if value is a valid IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _infer_type(raw: str) -> str:
    """Infer target type as url, ip, or domain."""
    parsed = urlparse(raw)
    if parsed.scheme and parsed.netloc:
        return "url"
    if _is_ip(raw):
        return "ip"
    return "domain"


def analyze_target(raw: str) -> TargetInfo:
    """Normalize user input and resolve domain hosts to IPs."""
    value = raw.strip()
    target_type = _infer_type(value)

    host = value
    url = None
    if target_type == "url":
        parsed = urlparse(value)
        host = parsed.hostname or value
        url = value

    resolved_ips: list[str] = []
    if target_type == "ip":
        resolved_ips = [value]
    else:
        try:
            _, _, ips = socket.gethostbyname_ex(host)
            resolved_ips = sorted(set(ips))
        except OSError:
            resolved_ips = []

    return TargetInfo(
        raw=value,
        target_type=target_type,
        host=host,
        primary_ip=resolved_ips[0] if resolved_ips else None,
        resolved_ips=resolved_ips,
        url=url,
    )
