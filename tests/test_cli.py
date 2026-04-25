"""CLI parser tests."""

import pytest

from nomoreforbidden.cli import (
    apply_safe_mode,
    build_parser,
    build_summary,
    load_list_file,
    parse_csv_list,
    parse_header_pairs,
    render_text_summary,
    resolve_enabled_probes,
    resolve_profile,
    validate_runtime_args,
)


def test_parser_ip_aliases_ip_and_i():
    p = build_parser()
    a = p.parse_args(["-u", "http://example.com/x", "-ip", "8.8.8.8"])
    assert a.ip == "8.8.8.8"
    a2 = p.parse_args(["-u", "http://example.com/x", "-i", "1.1.1.1"])
    assert a2.ip == "1.1.1.1"
    a3 = p.parse_args(["-u", "http://example.com/x", "--ip", "9.9.9.9"])
    assert a3.ip == "9.9.9.9"


def test_version_exits_via_action():
    p = build_parser()
    with pytest.raises(SystemExit) as exc:
        p.parse_args(["--version"])
    assert exc.value.code == 0


def test_verbose_flag():
    p = build_parser()
    a = p.parse_args(["-u", "http://x", "-v"])
    assert a.verbose is True
    a2 = p.parse_args(["-u", "http://x"])
    assert a2.verbose is False


def test_proxy_and_json_flags():
    p = build_parser()
    a = p.parse_args(
        ["-u", "http://x", "--proxy", "http://127.0.0.1:8080", "--json"]
    )
    assert a.proxy == "http://127.0.0.1:8080"
    assert a.json_legacy is True


def test_output_format_csv():
    p = build_parser()
    a = p.parse_args(["-u", "http://x", "--output-format", "csv"])
    assert a.output_format == "csv"
    assert a.json_legacy is False


def test_delay():
    p = build_parser()
    a = p.parse_args(["-u", "http://x", "--delay", "0.5"])
    assert a.delay == 0.5


def test_fp_bytes():
    p = build_parser()
    a = p.parse_args(["-u", "http://x", "--fp-bytes", "128"])
    assert a.fp_bytes == 128


def test_fp_threshold():
    p = build_parser()
    a = p.parse_args(["-u", "http://x", "--fp-threshold", "55"])
    assert a.fp_threshold == 55


def test_fp_baseline():
    p = build_parser()
    a = p.parse_args(["-u", "http://x", "--fp-baseline", "root"])
    assert a.fp_baseline == "root"


def test_header_repeatable():
    p = build_parser()
    a = p.parse_args(["-u", "http://x", "-H", "X-Test: 1", "-H", "Y: 2"])
    assert a.header == ["X-Test: 1", "Y: 2"]


def test_parse_header_pairs():
    p = build_parser()
    h = parse_header_pairs(["Authorization: Bearer x", "Foo: bar baz"], p)
    assert h["Authorization"] == "Bearer x"
    assert h["Foo"] == "bar baz"


def test_methods_csv():
    p = build_parser()
    a = p.parse_args(["-u", "http://x", "--methods", "HEAD,PATCH"])
    assert a.methods == "HEAD,PATCH"


def test_http2_flag():
    p = build_parser()
    a = p.parse_args(["-u", "https://x", "--http2"])
    assert a.http2 is True


def test_concurrency_flag():
    p = build_parser()
    a = p.parse_args(["-u", "https://x", "--concurrency", "4"])
    assert a.concurrency == 4


def test_rate_limit_flag():
    p = build_parser()
    a = p.parse_args(["-u", "https://x", "--rate-limit", "2.5"])
    assert a.rate_limit == 2.5


def test_timeout_and_retries_flags():
    p = build_parser()
    a = p.parse_args(["-u", "https://x", "--timeout", "8", "--retries", "2"])
    assert a.timeout == 8
    assert a.retries == 2


def test_deadline_output_file_and_redact_flags(tmp_path):
    p = build_parser()
    out = tmp_path / "result.json"
    a = p.parse_args(
        [
            "-u",
            "https://x",
            "--deadline",
            "12.5",
            "--output-file",
            str(out),
            "--redact",
        ]
    )
    assert a.deadline == 12.5
    assert a.output_file == str(out)
    assert a.redact is True


def test_safe_mode_applies_defaults():
    p = build_parser()
    a = p.parse_args(["-u", "https://x", "--safe-mode", "--concurrency", "10"])
    apply_safe_mode(a)
    assert a.require_scope is True
    assert a.dry_run is True
    assert a.concurrency == 2
    assert a.rate_limit == 2.0


def test_safe_mode_force_run_keeps_live_scan():
    p = build_parser()
    a = p.parse_args(["-u", "https://x", "--safe-mode", "--force-run"])
    apply_safe_mode(a)
    assert a.dry_run is False


def test_profile_and_aggressive_flags():
    p = build_parser()
    a = p.parse_args(["-u", "https://x", "--profile", "safe", "--aggressive"])
    assert a.profile == "safe"
    assert a.aggressive is True


def test_only_and_skip_flags():
    p = build_parser()
    a = p.parse_args(["-u", "https://x", "--only", "nmf,get_ip", "--skip", "get_ip"])
    assert a.only == "nmf,get_ip"
    assert a.skip == "get_ip"


def test_load_list_file(tmp_path):
    file = tmp_path / "items.txt"
    file.write_text("# comment\nX-Test\n\n/abc\n", encoding="utf-8")
    assert load_list_file(str(file)) == ["X-Test", "/abc"]


def test_build_summary():
    findings = [
        {"category": "url_payload", "status_code": 200},
        {"category": "url_payload", "status_code": 302, "possible_false_positive": True},
        {"category": "wayback", "snapshot_url": "https://archive.org/x"},
        {"category": "error", "error": "boom"},
    ]
    summary = build_summary(findings, True)
    assert summary["total_findings"] == 4
    assert summary["by_category"]["url_payload"] == 2
    assert summary["status_hits"] == 2
    assert summary["possible_false_positives"] == 1
    assert summary["errors"] == 1
    assert summary["hit"] is True


def test_parse_csv_list():
    assert parse_csv_list("a,b, c ,,") == ["a", "b", "c"]


def test_resolve_profile_aggressive_merge():
    profile = resolve_profile("safe", True)
    assert "PATCH" in profile["methods"]
    assert profile["http2"] is True
    assert int(profile["concurrency"]) >= 4


def test_resolve_enabled_probes():
    p = build_parser()
    enabled = resolve_enabled_probes("nmf,get_ip", "get_ip", p)
    assert enabled == {"nmf"}


def test_render_text_summary():
    summary = {
        "total_findings": 4,
        "status_hits": 2,
        "possible_false_positives": 1,
        "errors": 1,
        "hit": True,
    }
    line = render_text_summary(summary)
    assert "findings=4" in line
    assert "status_hits=2" in line
    assert "possible_fp=1" in line
    assert "errors=1" in line
    assert "hit=true" in line


@pytest.mark.parametrize(
    "argv",
    [
        ["-u", "http://x", "--delay", "-1"],
        ["-u", "http://x", "--fp-bytes", "0"],
        ["-u", "http://x", "--fp-threshold", "-1"],
        ["-u", "http://x", "--concurrency", "0"],
        ["-u", "http://x", "--rate-limit", "-1"],
        ["-u", "http://x", "--timeout", "0"],
        ["-u", "http://x", "--retries", "-1"],
        ["-u", "http://x", "--max-requests", "-1"],
        ["-u", "http://x", "--deadline", "-1"],
    ],
)
def test_validate_runtime_args_rejects_invalid_values(argv):
    parser = build_parser()
    args = parser.parse_args(argv)
    with pytest.raises(SystemExit) as exc:
        validate_runtime_args(args, parser)
    assert exc.value.code == 2
