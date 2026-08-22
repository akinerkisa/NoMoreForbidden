
from types import SimpleNamespace

from requests.exceptions import RequestException

import nomoreforbidden.probes as probes
from nomoreforbidden.context import RunContext, build_session
from nomoreforbidden.probes import _build_path_variants, nmf
from nomoreforbidden.request_utils import (
    content_digest as _content_digest,
)
from nomoreforbidden.request_utils import (
    fp_signals as _fp_signals,
)
from nomoreforbidden.request_utils import (
    req_kwargs as _req_kwargs,
)
from nomoreforbidden.request_utils import (
    request_with_retries,
    response_metadata,
)


def test_req_kwargs_defaults():
    s = build_session(None, None, {})
    ctx = RunContext(
        session=s, verbose=False, output_format="text", ip="127.0.0.1"
    )
    k = _req_kwargs(ctx)
    assert k["verify"] is False
    assert k["timeout"] == 5


def test_req_kwargs_merge():
    s = build_session(None, None, {})
    ctx = RunContext(
        session=s, verbose=False, output_format="text", ip="127.0.0.1"
    )
    k = _req_kwargs(ctx, {"allow_redirects": False})
    assert k["verify"] is False
    assert k["timeout"] == 5
    assert k["allow_redirects"] is False


def test_cookie_overrides_header_cookie():
    s = build_session(
        None,
        "from_flag=1",
        {"Cookie": "from_header=0"},
    )
    assert s.headers.get("Cookie") == "from_flag=1"


def test_run_context_structured():
    s = build_session(None, None, {})
    ctx = RunContext(
        session=s, verbose=False, output_format="json", ip="127.0.0.1"
    )
    assert ctx.structured is True
    ctx.record(a=1)
    assert ctx.findings == [{"a": 1}]
    assert ctx.schema_version == "1.0"


def test_content_digest_uses_prefix_only():
    digest1 = _content_digest(b"abcdef", 3)
    digest2 = _content_digest(b"abcXYZ", 3)
    assert digest1 == digest2


def test_fp_signals_score_same_prefix_as_possible_fp():
    ctx = RunContext(
        session=build_session(None, None, {}),
        verbose=False,
        output_format="json",
        ip="127.0.0.1",
        fp_bytes=4,
    )
    baseline = SimpleNamespace(content=b"abcdef", headers={})
    candidate = SimpleNamespace(content=b"abcdeg", headers={})
    maybe_fp, signals = _fp_signals(ctx, baseline, candidate)
    assert maybe_fp is True
    assert signals["same_length"] is True
    assert signals["same_digest"] is True
    assert signals["fp_threshold"] == 40
    assert signals["fp_decision"] == "possible_false_positive"
    assert signals["confidence"] == "medium"

    different = SimpleNamespace(content=b"zzz", headers={})
    maybe_fp_2, signals_2 = _fp_signals(ctx, baseline, different)
    assert maybe_fp_2 is False
    assert signals_2["same_length"] is False
    assert signals_2["fp_decision"] == "likely_valid"
    assert signals_2["confidence"] == "low"


def test_fp_signals_detects_forbidden_markers_even_without_digest_match():
    ctx = RunContext(
        session=build_session(None, None, {}),
        verbose=False,
        output_format="json",
        ip="127.0.0.1",
        fp_bytes=16,
    )
    baseline = SimpleNamespace(
        content=b"<html><title>Home</title><body>Welcome</body></html>",
        headers={},
    )
    candidate = SimpleNamespace(
        content=(
            b"<html><title>Restricted Preview</title>"
            b"<body>This is not a successful bypass. Access denied.</body></html>"
        ),
        headers={},
    )
    maybe_fp, signals = _fp_signals(ctx, baseline, candidate)
    assert maybe_fp is True
    assert "deny_markers" in signals["fp_reasons"]
    assert "access denied" in signals["deny_markers"]


def test_fp_signals_respects_custom_threshold():
    ctx = RunContext(
        session=build_session(None, None, {}),
        verbose=False,
        output_format="json",
        ip="127.0.0.1",
        fp_bytes=4,
        fp_threshold=80,
    )
    baseline = SimpleNamespace(content=b"abcdef", headers={})
    candidate = SimpleNamespace(content=b"abcdeg", headers={})
    maybe_fp, signals = _fp_signals(ctx, baseline, candidate)
    assert maybe_fp is False
    assert signals["fp_score"] == 60
    assert signals["fp_threshold"] == 80
    assert signals["fp_decision"] == "likely_valid"


def test_fp_signals_detects_json_deny_payloads():
    ctx = RunContext(
        session=build_session(None, None, {}),
        verbose=False,
        output_format="json",
        ip="127.0.0.1",
        fp_threshold=30,
    )
    baseline = SimpleNamespace(
        content=b'{"status":"ok","message":"welcome"}',
        headers={"Content-Type": "application/json"},
    )
    candidate = SimpleNamespace(
        content=b'{"error":"forbidden","message":"access denied"}',
        headers={"Content-Type": "application/json"},
    )
    maybe_fp, signals = _fp_signals(ctx, baseline, candidate)
    assert maybe_fp is True
    assert signals["baseline_content_type_family"] == "json"
    assert signals["candidate_content_type_family"] == "json"
    assert signals["same_json_shape"] is False
    assert "forbidden" in signals["json_deny_markers"]
    assert signals["fp_decision"] == "possible_false_positive"
    assert signals["confidence"] == "high"


def test_fp_signals_tracks_content_type_family_difference():
    ctx = RunContext(
        session=build_session(None, None, {}),
        verbose=False,
        output_format="json",
        ip="127.0.0.1",
    )
    baseline = SimpleNamespace(
        content=b"<html><title>Forbidden</title><body>forbidden</body></html>",
        headers={"Content-Type": "text/html"},
    )
    candidate = SimpleNamespace(
        content=b'{"error":"forbidden","message":"access denied"}',
        headers={"Content-Type": "application/json"},
    )
    maybe_fp, signals = _fp_signals(ctx, baseline, candidate)
    assert maybe_fp is True
    assert signals["same_content_type_family"] is False
    assert signals["candidate_content_type_family"] == "json"


def test_fp_signals_detects_root_fallback_html_response():
    ctx = RunContext(
        session=build_session(None, None, {}),
        verbose=False,
        output_format="json",
        ip="127.0.0.1",
        fp_threshold=40,
    )
    baseline = SimpleNamespace(
        content=b"<html><title>403 Forbidden</title><body>Forbidden</body></html>",
        headers={"Content-Type": "text/html"},
        url="http://example.com/protected",
    )
    candidate = SimpleNamespace(
        content=b"<html><title>Vulnerable Web App</title><body>Forbidden Home</body></html>",
        headers={"Content-Type": "text/html"},
        url="http://example.com/",
    )
    maybe_fp, signals = _fp_signals(ctx, baseline, candidate)
    assert maybe_fp is True
    assert signals["root_fallback"] is True
    assert signals["title_mismatch"] is True
    assert "root_fallback" in signals["fp_reasons"]
    assert "root_title_mismatch" in signals["fp_reasons"]


def test_fp_signals_detects_json_deny_markers():
    ctx = RunContext(
        session=build_session(None, None, {}),
        verbose=False,
        output_format="json",
        ip="127.0.0.1",
        fp_threshold=30,
    )
    baseline = SimpleNamespace(
        content=b'{"message":"welcome","status":"ok"}',
        headers={"Content-Type": "application/json"},
    )
    candidate = SimpleNamespace(
        content=b'{"error":"forbidden","message":"access denied"}',
        headers={"Content-Type": "application/json"},
    )
    maybe_fp, signals = _fp_signals(ctx, baseline, candidate)
    assert maybe_fp is True
    assert signals["baseline_content_type_family"] == "json"
    assert signals["candidate_content_type_family"] == "json"
    assert signals["same_content_type_family"] is True
    assert "json_deny_markers" in signals["fp_reasons"]
    assert "forbidden" in signals["json_deny_markers"]


def test_fp_signals_marks_json_shape_match():
    ctx = RunContext(
        session=build_session(None, None, {}),
        verbose=False,
        output_format="json",
        ip="127.0.0.1",
        fp_threshold=100,
    )
    baseline = SimpleNamespace(
        content=b'{"message":"ok","status":"ok"}',
        headers={"Content-Type": "application/json"},
    )
    candidate = SimpleNamespace(
        content=b'{"message":"blocked","status":"forbidden"}',
        headers={"Content-Type": "application/json"},
    )
    maybe_fp, signals = _fp_signals(ctx, baseline, candidate)
    assert maybe_fp is False
    assert signals["same_json_shape"] is True
    assert signals["same_json_text"] is False


def test_build_path_variants_contains_expected_entries():
    variants = _build_path_variants("https://example.com", "/admin")
    assert "https://example.com//admin" in variants
    assert "https://example.com/admin/." in variants
    assert "https://example.com/admin;/" in variants


def test_nmf_ip_header_loop_uses_context_session():
    class DummySession:
        def __init__(self):
            self.request_methods = []
            self.get_calls = []
            self.request_calls = []

        def get(self, url, **kwargs):
            self.get_calls.append((url, kwargs))
            return SimpleNamespace(status_code=404, content=b"body", headers={})

        def post(self, url, **kwargs):
            return SimpleNamespace(status_code=404, content=b"body", headers={})

        def request(self, method, url, **kwargs):
            self.request_methods.append(method)
            self.request_calls.append((method, url, kwargs))
            return SimpleNamespace(status_code=404, content=b"body", headers={})

    session = DummySession()

    ctx = RunContext(
        session=session,
        verbose=False,
        output_format="json",
        ip="127.0.0.1",
        extra_payloads=["/custom-payload"],
        extra_ip_headers=["X-Test-IP"],
        extra_methods=["HEAD", "OPTIONS"],
    )

    nmf("http://example.com/test", ctx)

    assert isinstance(ctx.findings, list)
    assert session.request_methods.count("HEAD") >= 1
    assert session.request_methods.count("OPTIONS") >= 1
    assert session.request_methods.count("GET") >= 1
    assert any(
        kwargs.get("headers", {}).get("X-HTTP-Method-Override") == "HEAD"
        for _, _, kwargs in session.request_calls
    )
    assert any(
        kwargs.get("headers", {}).get("X-Host") == "example.com"
        for _, _, kwargs in session.request_calls
    )
    assert any(
        kwargs.get("headers", {}).get("Accept") == "application/json"
        for _, _, kwargs in session.request_calls
    )


def test_resolve_fp_baseline_target():
    class DummySession:
        def request(self, method, url, **kwargs):
            if url.endswith("/test"):
                return SimpleNamespace(status_code=403, content=b"target", headers={})
            return SimpleNamespace(status_code=200, content=b"root", headers={})

    ctx = RunContext(
        session=DummySession(),
        verbose=False,
        output_format="json",
        ip="127.0.0.1",
        fp_baseline="target",
    )
    baseline = probes._resolve_fp_baseline(
        ctx, "http://example.com/test", "http://example.com"
    )
    assert baseline.content == b"target"


def test_resolve_fp_baseline_root():
    class DummySession:
        def request(self, method, url, **kwargs):
            if url == "http://example.com":
                return SimpleNamespace(status_code=200, content=b"root", headers={})
            return SimpleNamespace(status_code=403, content=b"target", headers={})

    ctx = RunContext(
        session=DummySession(),
        verbose=False,
        output_format="json",
        ip="127.0.0.1",
        fp_baseline="root",
    )
    baseline = probes._resolve_fp_baseline(
        ctx, "http://example.com/test", "http://example.com"
    )
    assert baseline.content == b"root"


def test_resolve_fp_baseline_auto_prefers_target_error():
    class DummySession:
        def request(self, method, url, **kwargs):
            if url.endswith("/test"):
                return SimpleNamespace(status_code=403, content=b"target", headers={})
            return SimpleNamespace(status_code=200, content=b"root", headers={})

    ctx = RunContext(
        session=DummySession(),
        verbose=False,
        output_format="json",
        ip="127.0.0.1",
        fp_baseline="auto",
    )
    baseline = probes._resolve_fp_baseline(
        ctx, "http://example.com/test", "http://example.com"
    )
    assert baseline.content == b"target"


def test_resolve_fp_baseline_auto_falls_back_to_root():
    class DummySession:
        def request(self, method, url, **kwargs):
            if url.endswith("/test"):
                return SimpleNamespace(status_code=200, content=b"ok", headers={})
            return SimpleNamespace(status_code=200, content=b"root", headers={})

    ctx = RunContext(
        session=DummySession(),
        verbose=False,
        output_format="json",
        ip="127.0.0.1",
        fp_baseline="auto",
    )
    baseline = probes._resolve_fp_baseline(
        ctx, "http://example.com/test", "http://example.com"
    )
    assert baseline.content == b"root"


def test_after_request_sets_last_request_at():
    ctx = RunContext(
        session=build_session(None, None, {}),
        verbose=False,
        output_format="text",
        ip="127.0.0.1",
        rate_limit=5.0,
    )
    assert ctx._last_request_at == 0.0
    ctx.after_request()
    assert ctx._last_request_at > 0.0
    assert ctx.request_count == 1


def test_response_metadata_extracts_headers():
    redirect = SimpleNamespace(
        status_code=302,
        headers={"Location": "/403"},
        url="https://example.com/start",
    )
    response = SimpleNamespace(
        headers={
            "Content-Type": "application/json",
            "Location": "/next",
            "Server": "nginx",
            "ETag": "abc",
            "Content-Length": "12",
        },
        url="https://example.com/final",
        history=[redirect],
    )
    meta = response_metadata(response)
    assert meta["content_type"] == "application/json"
    assert meta["location"] == "/next"
    assert meta["server"] == "nginx"
    assert meta["etag"] == "abc"
    assert meta["content_length_header"] == "12"
    assert meta["body_preview"] == ""
    assert meta["final_url"] == "https://example.com/final"
    assert meta["redirect_chain"] == [
        {
            "status_code": 302,
            "location": "/403",
            "url": "https://example.com/start",
        }
    ]


def test_response_metadata_includes_body_preview():
    response = SimpleNamespace(
        headers={"Content-Type": "text/plain"},
        url="https://example.com/x",
        history=[],
        content=b"forbidden body preview example",
    )
    meta = response_metadata(response)
    assert meta["body_preview"] == "forbidden body preview example"


def test_request_with_retries_retries_once():
    class FlakySession:
        def __init__(self):
            self.calls = 0

        def request(self, method, url, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise RequestException("boom")
            return SimpleNamespace(status_code=200, headers={}, content=b"ok")

    ctx = RunContext(
        session=FlakySession(),
        verbose=False,
        output_format="text",
        ip="127.0.0.1",
        retries=1,
    )
    response = request_with_retries(ctx, "GET", "https://example.com")
    assert response.status_code == 200
    assert ctx.session.calls == 2


def test_request_with_retries_respects_deadline():
    class SlowFailSession:
        def request(self, method, url, **kwargs):
            raise RequestException("boom")

    ctx = RunContext(
        session=SlowFailSession(),
        verbose=False,
        output_format="text",
        ip="127.0.0.1",
        retries=2,
        deadline_sec=0.01,
    )
    ctx._started_at -= 1.0
    try:
        request_with_retries(ctx, "GET", "https://example.com")
        assert False
    except TimeoutError:
        assert True
