"""HTTP/1.0 and HTTP/1.1 probes via http.client.

Assigning response.raw.version in requests does not change the wire protocol; this
module uses low-level connections. Optional HTTP/2 probing uses httpx when enabled.
Proxies apply only to requests.Session traffic; HTTP/1.x probes bypass the session.
"""

from __future__ import annotations

import http.client
import ssl
from urllib.parse import urlparse

from nomoreforbidden.context import RunContext

try:
    import httpx
except ImportError:  # pragma: no cover - exercised via helper
    httpx = None


def probe_http_version(
    url: str, version: int, timeout: float = 5.0
) -> tuple[int | None, str | None]:
    """Issue GET; returns (status_code, error_message). status_code None on failure."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return None, "Invalid URL: no host"

    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    try:
        if parsed.scheme == "https":
            ctx_ssl = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port, context=ctx_ssl, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn._http_vsn = version
        conn._http_vsn_str = "HTTP/1.0" if version == 10 else "HTTP/1.1"

        headers = {"Host": host, "Connection": "close", "User-Agent": "NoMoreForbidden/0.4"}
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()
        return status, None
    except OSError as e:
        return None, str(e)
    except http.client.HTTPException as e:
        return None, str(e)


def probe_http2(url: str, timeout: float = 5.0) -> tuple[int | None, str | None]:
    """Try HTTP/2 with httpx. Returns (status_code, error_message)."""
    if httpx is None:
        return None, "httpx is not installed"

    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None, "HTTP/2 probe requires https URL"

    try:
        with httpx.Client(http2=True, verify=False, timeout=timeout) as client:
            response = client.get(url, follow_redirects=False)
        return response.status_code, None
    except httpx.HTTPError as e:
        return None, str(e)


def run_http_version_checks(url: str, verbose: bool, ctx: RunContext | None = None) -> None:
    """Try HTTP/1.0 and HTTP/1.1 in separate connections; print or structured record."""
    labels = {10: "HTTP/1.0", 11: "HTTP/1.1"}
    structured = ctx is not None and ctx.structured

    for version in (10, 11):
        status, err = probe_http_version(url, version)
        label = labels[version]
        if err:
            if structured:
                ctx.record(
                    category="http_version",
                    label=label,
                    version=version,
                    error=err,
                    note="does_not_use_proxy",
                )
            elif verbose:
                print(f"{label}: request failed — {err}")
            continue
        if structured:
            ctx.record(
                category="http_version",
                label=label,
                version=version,
                status_code=status,
                note="does_not_use_proxy",
            )
            if status in (200, 302):
                ctx.register_hit()
        elif status in (200, 302):
            print(f"{label} request successful [{status}]")
            if ctx is not None:
                ctx.register_hit()
        elif verbose:
            print(f"{label} status code: [{status}]")

    if ctx is not None and not ctx.enable_http2:
        return

    status, err = probe_http2(url)
    if structured:
        row = {
            "category": "http_version",
            "label": "HTTP/2",
            "version": 20,
            "note": "uses_httpx_direct_client",
        }
        if err:
            row["error"] = err
        else:
            row["status_code"] = status
            if status in (200, 302):
                ctx.register_hit()
        ctx.record(**row)
        return

    if err:
        if verbose:
            print(f"HTTP/2: request failed — {err}")
        return
    if status in (200, 302):
        print(f"HTTP/2 request successful [{status}]")
        if ctx is not None:
            ctx.register_hit()
    elif verbose:
        print(f"HTTP/2 status code: [{status}]")
