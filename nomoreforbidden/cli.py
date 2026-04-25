"""CLI parsing and execution."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from nomoreforbidden import BANNER, __version__
from nomoreforbidden.context import RunContext, build_session
from nomoreforbidden.http_version import run_http_version_checks
from nomoreforbidden.plan import estimate_probe_http_upper_bound
from nomoreforbidden.probes import get_ip, nmf, ssl_switch, wayback
from nomoreforbidden.scope import validate_target_scope


def parse_header_pairs(items: list[str], parser: argparse.ArgumentParser) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        if ":" not in item:
            parser.error(f"Invalid --header (expected Name: Value): {item!r}")
        name, sep, value = item.partition(":")
        name = name.strip()
        value = value.lstrip()
        if not name:
            parser.error(f"Invalid --header (empty name): {item!r}")
        out[name] = value
    return out


def load_list_file(path: str | None) -> list[str]:
    if not path:
        return []
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def parse_csv_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def resolve_profile(profile: str, aggressive: bool) -> dict[str, object]:
    presets: dict[str, dict[str, object]] = {
        "safe": {
            "methods": ["HEAD"],
            "payloads": [],
            "headers": [],
            "concurrency": 1,
            "http2": False,
        },
        "default": {
            "methods": ["HEAD", "OPTIONS"],
            "payloads": [],
            "headers": [],
            "concurrency": 1,
            "http2": False,
        },
        "aggressive": {
            "methods": ["HEAD", "OPTIONS", "PATCH", "PUT", "DELETE"],
            "payloads": [
                "/;/",
                "/%2e/",
                "/%2e%2f/",
                ";/",
                "..%2f..%2f",
                "/%252e/",
                "/....//",
                "/%2f%2f",
            ],
            "headers": ["X-Host", "X-Original-Host", "X-Forwarded-Server"],
            "concurrency": 4,
            "http2": True,
        },
        "proxy-aware": {
            "methods": ["HEAD", "OPTIONS"],
            "payloads": ["/;/", "/%2e/"],
            "headers": ["X-Host", "X-Forwarded-Server"],
            "concurrency": 2,
            "http2": False,
        },
    }
    selected = dict(presets[profile])
    if aggressive and profile != "aggressive":
        aggressive_defaults = presets["aggressive"]
        selected["methods"] = sorted(
            set(selected["methods"]) | set(aggressive_defaults["methods"])
        )
        selected["payloads"] = list(selected["payloads"]) + [
            p for p in aggressive_defaults["payloads"] if p not in selected["payloads"]
        ]
        selected["headers"] = list(selected["headers"]) + [
            h for h in aggressive_defaults["headers"] if h not in selected["headers"]
        ]
        selected["concurrency"] = max(int(selected["concurrency"]), 4)
        selected["http2"] = True
    return selected


def resolve_enabled_probes(
    only_csv: str | None, skip_csv: str | None, parser: argparse.ArgumentParser
) -> set[str]:
    all_probes = {
        "nmf",
        "wayback",
        "ssl_switch",
        "http_version",
        "get_ip",
    }
    only = set(parse_csv_list(only_csv))
    skip = set(parse_csv_list(skip_csv))
    unknown = (only | skip) - all_probes
    if unknown:
        parser.error(f"Unknown probe name(s): {', '.join(sorted(unknown))}")
    enabled = set(all_probes) if not only else set(only)
    return enabled - skip


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Try various techniques to bypass 403 responses (authorized testing only)."
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"NoMoreForbidden {__version__}",
        help="Print version and exit",
    )
    p.add_argument("-u", "--url", required=True, help="Target URL")
    p.add_argument(
        "-i",
        "-ip",
        "--ip",
        dest="ip",
        default="127.0.0.1",
        metavar="ADDR",
        help="IP for IP-based header tests (default: 127.0.0.1)",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show all valid/invalid results and error details",
    )
    p.add_argument(
        "--proxy",
        metavar="URL",
        default=None,
        help="HTTP(S) proxy URL for requests (uses requests.Session)",
    )
    p.add_argument(
        "--cookie",
        default=None,
        metavar="STRING",
        help="Cookie header value (shortcut; applied after -H headers)",
    )
    p.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="NAME:VALUE",
        help="Extra HTTP header (repeatable). Example: -H 'Authorization: Bearer token'",
    )
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument(
        "--output-format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format: human text (default), JSON, or CSV rows",
    )
    fmt.add_argument(
        "--json",
        action="store_true",
        dest="json_legacy",
        help="Shorthand for --output-format json",
    )
    p.add_argument(
        "--delay",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Pause SEC seconds after each HTTP request (default: 0)",
    )
    p.add_argument(
        "--fp-bytes",
        type=int,
        default=64,
        metavar="N",
        help="Bytes to hash for false-positive comparison (default: 64)",
    )
    p.add_argument(
        "--fp-threshold",
        type=int,
        default=40,
        metavar="N",
        help="False-positive score threshold (default: 40)",
    )
    p.add_argument(
        "--fp-baseline",
        choices=["auto", "target", "root"],
        default="auto",
        help="False-positive baseline strategy (default: auto)",
    )
    p.add_argument(
        "--payloads-file",
        metavar="PATH",
        help="Read extra URL payload suffixes from file (one per line)",
    )
    p.add_argument(
        "--headers-file",
        metavar="PATH",
        help="Read extra spoofing header names from file (one per line)",
    )
    p.add_argument(
        "--methods",
        metavar="CSV",
        default="HEAD,OPTIONS",
        help="Extra HTTP methods for case-path probe, comma-separated (default: HEAD,OPTIONS)",
    )
    p.add_argument(
        "--http2",
        action="store_true",
        help="Try an additional HTTP/2 probe via httpx when available",
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=1,
        metavar="N",
        help="Concurrent workers for URL payload probes (default: 1)",
    )
    p.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        metavar="RPS",
        help="Global request cap in requests/sec across session traffic (default: 0 = disabled)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="SEC",
        help="Per-request timeout in seconds (default: 5)",
    )
    p.add_argument(
        "--retries",
        type=int,
        default=0,
        metavar="N",
        help="Retry count for failed HTTP requests (default: 0)",
    )
    p.add_argument(
        "--profile",
        choices=["safe", "default", "aggressive", "proxy-aware"],
        default="default",
        help="Probe profile preset (default: default)",
    )
    p.add_argument(
        "--aggressive",
        action="store_true",
        help="Expand methods, payloads, headers, and concurrency beyond the selected profile",
    )
    p.add_argument(
        "--only",
        metavar="CSV",
        help="Run only selected probes: nmf,wayback,ssl_switch,http_version,get_ip",
    )
    p.add_argument(
        "--skip",
        metavar="CSV",
        help="Skip selected probes: nmf,wayback,ssl_switch,http_version,get_ip",
    )
    p.add_argument(
        "--allow-host",
        action="append",
        default=[],
        metavar="HOST",
        help="İzin verilen hostname (tekrarlanabilir, küçük/büyük duyarsız). Boşsa kısıt yok.",
    )
    p.add_argument(
        "--allow-url-prefix",
        action="append",
        default=[],
        metavar="URL",
        help="İzin verilen tam URL öneki; hedef bu öneklerden biriyle başlamalı (tekrarlanabilir).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="HTTP isteği göndermeden tahmini istek sayısını yazdır ve çık (çıkış kodu 0).",
    )
    p.add_argument(
        "--max-requests",
        type=int,
        default=0,
        metavar="N",
        help="Tahmini toplam HTTP üst sınırı N'den büyükse taramayı başlatma ve çık (2). 0=kapalı.",
    )
    return p


def _write_csv(findings: list[dict]) -> None:
    if not findings:
        w = csv.writer(sys.stdout)
        w.writerow(["category"])
        return
    keys = sorted(set().union(*(f.keys() for f in findings)))
    w = csv.DictWriter(sys.stdout, fieldnames=keys, extrasaction="ignore")
    w.writeheader()
    w.writerows(findings)


def build_summary(findings: list[dict], hit: bool) -> dict[str, object]:
    by_category: dict[str, int] = {}
    status_hits = 0
    possible_false_positives = 0
    errors = 0

    for row in findings:
        category = str(row.get("category", "unknown"))
        by_category[category] = by_category.get(category, 0) + 1
        if row.get("status_code") in (200, 302):
            status_hits += 1
        if row.get("possible_false_positive") is True:
            possible_false_positives += 1
        if "error" in row:
            errors += 1

    return {
        "total_findings": len(findings),
        "by_category": by_category,
        "status_hits": status_hits,
        "possible_false_positives": possible_false_positives,
        "errors": errors,
        "hit": hit,
    }


def render_text_summary(summary: dict[str, object]) -> str:
    return (
        "Scan Summary: "
        f"findings={summary['total_findings']} "
        f"status_hits={summary['status_hits']} "
        f"possible_fp={summary['possible_false_positives']} "
        f"errors={summary['errors']} "
        f"hit={str(summary['hit']).lower()}"
    )


def run_cli() -> None:
    """setuptools `project.scripts` girişi: çıkış kodunu işletim sistemine iletir."""
    raise SystemExit(main())


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    scope_err = validate_target_scope(
        args.url, list(args.allow_host), list(args.allow_url_prefix)
    )
    if scope_err:
        parser.error(scope_err)
    extra_headers = parse_header_pairs(args.header, parser)
    profile_settings = resolve_profile(args.profile, args.aggressive)
    extra_payloads = load_list_file(args.payloads_file)
    extra_ip_headers = load_list_file(args.headers_file)
    extra_methods = [m.strip().upper() for m in args.methods.split(",") if m.strip()]
    enabled_probes = resolve_enabled_probes(args.only, args.skip, parser)

    for payload in profile_settings["payloads"]:
        if payload not in extra_payloads:
            extra_payloads.append(payload)
    for header in profile_settings["headers"]:
        if header not in extra_ip_headers:
            extra_ip_headers.append(header)
    for method in profile_settings["methods"]:
        if method not in extra_methods:
            extra_methods.append(method)

    output_format = "json" if args.json_legacy else args.output_format

    session = build_session(args.proxy, args.cookie, extra_headers)
    ctx = RunContext(
        session=session,
        verbose=args.verbose,
        output_format=output_format,
        ip=args.ip,
        delay_sec=max(0.0, args.delay),
        rate_limit=max(0.0, args.rate_limit),
        timeout_sec=max(0.1, args.timeout),
        retries=max(0, args.retries),
        fp_bytes=max(1, args.fp_bytes),
        fp_threshold=max(0, args.fp_threshold),
        fp_baseline=args.fp_baseline,
        enable_http2=args.http2 or bool(profile_settings["http2"]),
        extra_payloads=extra_payloads,
        extra_ip_headers=extra_ip_headers,
        extra_methods=extra_methods,
        aggressive=args.aggressive,
        profile=args.profile,
        enabled_probes=enabled_probes,
        concurrency=max(int(profile_settings["concurrency"]), max(1, args.concurrency)),
    )

    est = estimate_probe_http_upper_bound(args.url, ctx, ctx.enabled_probes)
    total_est = int(est["total_upper_bound"])

    if args.dry_run:
        if output_format == "json":
            out = {
                "dry_run": True,
                "target": args.url,
                "allow_host": list(args.allow_host),
                "allow_url_prefix": list(args.allow_url_prefix),
                "estimated_http_upper_bound": est,
            }
            json.dump(out, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            print("NoMoreForbidden — dry-run (HTTP gönderilmedi)")
            print(f"Hedef: {args.url}")
            if args.allow_host:
                print(f"İzin verilen host: {', '.join(args.allow_host)}")
            if args.allow_url_prefix:
                print(f"İzin verilen önek: {', '.join(args.allow_url_prefix)}")
            print("Tahmini HTTP istek üst sınırı (session + düşük seviye http_version):")
            for k, v in est.items():
                if k == "total_upper_bound":
                    continue
                print(f"  {k}: {v}")
            print(f"  TOPLAM (üst sınır): {total_est}")
        return 0

    max_req = max(0, int(args.max_requests))
    if max_req > 0 and total_est > max_req:
        print(
            f"Tahmini HTTP istek üst sınırı ({total_est}) --max-requests ({max_req}) "
            "değerini aşıyor; iptal.",
            file=sys.stderr,
        )
        return 2

    if not ctx.structured:
        print(BANNER)

    if "nmf" in ctx.enabled_probes:
        nmf(args.url, ctx)
    if "wayback" in ctx.enabled_probes:
        wayback(args.url, ctx)
    if "ssl_switch" in ctx.enabled_probes:
        ssl_switch(args.url, ctx)
    if "http_version" in ctx.enabled_probes:
        run_http_version_checks(args.url, args.verbose, ctx)
    if "get_ip" in ctx.enabled_probes:
        get_ip(args.url, ctx)
    summary = build_summary(ctx.findings, ctx.has_hit)

    if output_format == "json":
        out = {
            "schema_version": ctx.schema_version,
            "version": __version__,
            "target": args.url,
            "proxy": args.proxy,
            "profile": ctx.profile,
            "aggressive": ctx.aggressive,
            "enabled_probes": sorted(ctx.enabled_probes),
            "timeout": ctx.timeout_sec,
            "retries": ctx.retries,
            "fp_threshold": ctx.fp_threshold,
            "fp_baseline": ctx.fp_baseline,
            "summary": summary,
            "findings": ctx.findings,
            "hit": ctx.has_hit,
        }
        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif output_format == "csv":
        _write_csv(ctx.findings)
    else:
        print(render_text_summary(summary))

    return 0 if ctx.has_hit else 1


if __name__ == "__main__":
    sys.exit(main())
