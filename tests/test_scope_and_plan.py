"""Allowlist ve tahmini istek sayımı."""

import subprocess
import sys
from pathlib import Path

from nomoreforbidden.context import RunContext, build_session
from nomoreforbidden.plan import (
    estimate_nmf_main_http_requests,
    estimate_probe_http_upper_bound,
    fp_baseline_upper_bound,
)
from nomoreforbidden.scope import normalize_host, validate_target_scope


def _default_ctx(**kwargs: object) -> RunContext:
    s = build_session(None, None, {})
    base = dict(
        session=s,
        verbose=False,
        output_format="json",
        ip="127.0.0.1",
        extra_payloads=[],
        extra_ip_headers=[],
        extra_methods=["HEAD", "OPTIONS"],
        fp_baseline="auto",
        enable_http2=False,
        enabled_probes={"nmf"},
    )
    base.update(kwargs)
    return RunContext(**base)  # type: ignore[arg-type]


def test_normalize_host_ipv6_bracket():
    assert normalize_host("[::1]") == "::1"


def test_validate_scope_ok():
    assert validate_target_scope("https://a.example.com/x", ["a.example.com"], []) is None
    assert (
        validate_target_scope(
            "https://a.example.com/x",
            [],
            ["https://a.example.com/"],
        )
        is None
    )


def test_validate_scope_host_mismatch():
    err = validate_target_scope("https://evil.com/", ["example.com"], [])
    assert err is not None
    assert "evil.com" in err or "izin" in err.lower()


def test_validate_scope_prefix_mismatch():
    err = validate_target_scope("https://evil.com/", [], ["https://good.com/"])
    assert err is not None


def test_fp_baseline_upper_bound():
    assert fp_baseline_upper_bound("auto") == 2
    assert fp_baseline_upper_bound("target") == 1


def test_estimate_nmf_main_stable():
    ctx = _default_ctx()
    n = estimate_nmf_main_http_requests("https://example.com/secret/path", ctx)
    assert n == 110


def test_estimate_total_all_probes():
    ctx = _default_ctx(enable_http2=True, enabled_probes=set())
    est = estimate_probe_http_upper_bound("https://x.com/a", ctx, set())
    assert est["total_upper_bound"] == 0

    ctx2 = _default_ctx(enable_http2=True)
    est2 = estimate_probe_http_upper_bound(
        "https://x.com/a",
        ctx2,
        {"nmf", "wayback", "ssl_switch", "http_version", "get_ip"},
    )
    fp = fp_baseline_upper_bound("auto")
    main = estimate_nmf_main_http_requests("https://x.com/a", ctx2)
    assert est2["nmf"] == {"fp_baseline_max": fp, "main": main}
    assert est2["wayback"] == 1
    assert est2["ssl_switch"] == 1
    assert est2["http_version"] == 3
    assert est2["get_ip"] == 1
    assert est2["total_upper_bound"] == fp + main + 1 + 1 + 3 + 1


def test_cli_max_requests_aborts_before_http():
    root = Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        [
            sys.executable,
            str(root / "nmf.py"),
            "-u",
            "https://example.com/t",
            "--only",
            "nmf",
            "--max-requests",
            "50",
        ],
        cwd=str(root),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    combined = (proc.stderr + proc.stdout).lower()
    assert "50" in combined or "iptal" in combined
