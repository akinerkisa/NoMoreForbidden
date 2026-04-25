"""Tahmini HTTP istek sayıları (probes ile aynı boyutlar; üst sınır)."""

from __future__ import annotations

from urllib.parse import urlparse

from nomoreforbidden.context import RunContext
from nomoreforbidden.probes import (
    _CACHE_HEADERS,
    _METHOD_OVERRIDE_PAIRS,
    _REWRITE_HEADERS,
    _build_path_variants,
    build_cache_header_targets,
    build_content_header_combos,
    build_merged_ip_headers,
    collect_url_payloads,
)


def fp_baseline_upper_bound(fp_baseline: str) -> int:
    if fp_baseline == "auto":
        return 2
    return 1


def estimate_nmf_main_http_requests(url: str, ctx: RunContext) -> int:
    """nmf() içindeki session tabanlı GET/POST vb. (fp baseline hariç)."""
    parsed = urlparse(url)
    path = parsed.path
    base = f"{parsed.scheme}://{parsed.netloc}"
    payloads = collect_url_payloads(ctx)
    pv = len(_build_path_variants(base, path))
    ip_n = len(build_merged_ip_headers(ctx))
    forwarded = 1
    targets = len(build_cache_header_targets(base, url))
    cache_n = len(_CACHE_HEADERS) * targets * 2
    rewrite_n = len(_REWRITE_HEADERS) * targets * 2
    method_n = len(_METHOD_OVERRIDE_PAIRS)
    host_n = 5
    combo_n = len(build_content_header_combos(parsed, path, ctx.ip))
    case_n = 2 + len(ctx.extra_methods)
    return (
        len(payloads)
        + pv
        + ip_n
        + forwarded
        + cache_n
        + rewrite_n
        + method_n
        + host_n
        + combo_n
        + case_n
    )


def estimate_probe_http_upper_bound(url: str, ctx: RunContext, enabled: set[str]) -> dict:
    """Uçtan uca tahmini HTTP istek üst sınırı (Wayback dâhil dış origin)."""
    parts: dict[str, int | dict[str, int]] = {}
    total = 0

    if "nmf" in enabled:
        fp_max = fp_baseline_upper_bound(ctx.fp_baseline)
        main = estimate_nmf_main_http_requests(url, ctx)
        parts["nmf"] = {"fp_baseline_max": fp_max, "main": main}
        total += fp_max + main

    if "wayback" in enabled:
        parts["wayback"] = 1
        total += 1

    if "ssl_switch" in enabled:
        parts["ssl_switch"] = 1
        total += 1

    if "http_version" in enabled:
        parsed = urlparse(url)
        h = 2
        if ctx.enable_http2 and parsed.scheme == "https":
            h += 1
        parts["http_version"] = h
        total += h

    if "get_ip" in enabled:
        parts["get_ip"] = 1
        total += 1

    parts["total_upper_bound"] = total
    return parts
