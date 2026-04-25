"""Hedef URL için isteğe bağlı host / URL öneki allowlist (yanlışlıkla geniş taramayı azaltır)."""

from __future__ import annotations

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
) -> str | None:
    """Uygunsa None; değilse Türkçe hata mesajı."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "Yalnızca http veya https URL'leri desteklenir."

    if not allowed_hosts and not allowed_url_prefixes:
        return None

    if allowed_url_prefixes:
        ok = any(url.startswith(p) for p in allowed_url_prefixes)
        if not ok:
            return (
                "Hedef URL, --allow-url-prefix ile verilen öneklerden biriyle başlamıyor: "
                + ", ".join(repr(p) for p in allowed_url_prefixes)
            )

    if allowed_hosts:
        host = normalize_host(parsed.hostname)
        if not host:
            return "URL'de hostname yok; --allow-host ile eşleştirilemez."
        allowed_norm = {normalize_host(h) for h in allowed_hosts if h.strip()}
        allowed_norm.discard(None)
        if host not in allowed_norm:
            return (
                f"Hostname izin listesinde değil: {host!r} "
                f"(izin verilenler: {sorted(allowed_norm)})"
            )

    return None
