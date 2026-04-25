"""HTTP version probe tests."""

import nomoreforbidden.http_version as hv
from nomoreforbidden.context import RunContext, build_session
from nomoreforbidden.http_version import probe_http2, probe_http_version, run_http_version_checks


def test_probe_invalid_url_no_host():
    status, err = probe_http_version("http:///nohost", 11)
    assert status is None
    assert err is not None
    assert "host" in err.lower()


def test_probe_http2_requires_https():
    status, err = probe_http2("http://example.com")
    assert status is None
    assert "https" in err.lower()


def test_run_http_version_checks_records_http2(monkeypatch):
    def fake_probe_http_version(url, version, timeout=5.0):
        return 404, None

    def fake_probe_http2(url, timeout=5.0):
        return 200, None

    monkeypatch.setattr(hv, "probe_http_version", fake_probe_http_version)
    monkeypatch.setattr(hv, "probe_http2", fake_probe_http2)

    ctx = RunContext(
        session=build_session(None, None, {}),
        verbose=False,
        output_format="json",
        ip="127.0.0.1",
        enable_http2=True,
    )
    run_http_version_checks("https://example.com/test", False, ctx)

    http2_rows = [row for row in ctx.findings if row.get("label") == "HTTP/2"]
    assert len(http2_rows) == 1
    assert http2_rows[0]["status_code"] == 200
    assert ctx.has_hit is True
