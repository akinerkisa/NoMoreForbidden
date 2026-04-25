
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


def normalize_host(hostname: str | None) -> str | None:
    if not hostname:
        return None
    h = hostname.strip().lower()
    if h.startswith("[") and "]" in h:
        return h[1 : h.index("]")].lower()
    if ":" in h and not h.startswith("["):
        return h.split(":")[0].lower()
    return h


def validate_target_scope(
    url: str,
    allowed_hosts: list[str],
    allowed_url_prefixes: list[str],
    require_scope: bool = False,
    allow_private: bool = False,
) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "Only http and https URLs are supported."

    host = normalize_host(parsed.hostname)
    if not host:
        return "URL has no hostname; provide a valid target."

    if not allow_private and is_private_or_local_host(host):
        return "Target appears private/local. Use --allow-private to run intentionally."

    if require_scope and not allowed_hosts and not allowed_url_prefixes:
        return "--require-scope requires --allow-host or --allow-url-prefix."

    if not allowed_hosts and not allowed_url_prefixes:
        return None

    if allowed_url_prefixes:
        ok = any(url.startswith(p) for p in allowed_url_prefixes)
        if not ok:
            return (
                "Target URL does not start with any allowed --allow-url-prefix: "
                + ", ".join(repr(p) for p in allowed_url_prefixes)
            )

    if allowed_hosts:
        allowed_norm = {normalize_host(h) for h in allowed_hosts if h.strip()}
        allowed_norm.discard(None)
        if host not in allowed_norm:
            return (
                f"Hostname is not in allowlist: {host!r} "
                f"(allowed: {sorted(allowed_norm)})"
            )

    return None


def is_private_or_local_host(host: str) -> bool:
    value = host.strip().lower()
    if value in {"localhost", "localhost.localdomain"}:
        return True
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return value.endswith(".local")
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )
