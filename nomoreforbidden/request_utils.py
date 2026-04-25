
from __future__ import annotations

import hashlib
import json
import re
import time
from urllib.parse import urlparse

from requests import Response
from requests.exceptions import RequestException

from nomoreforbidden.context import RunContext

DEFAULT_TIMEOUT = 5
DENY_MARKERS = (
    "forbidden",
    "access denied",
    "request blocked",
    "restricted",
    "unauthorized",
    "not a successful bypass",
)
JSON_DENY_KEYS = ("error", "message", "detail", "reason", "status")
BODY_PREVIEW_LIMIT = 160


def req_kwargs(ctx: RunContext, extra: dict | None = None) -> dict:
    timeout = ctx.timeout_sec or DEFAULT_TIMEOUT
    left = ctx.seconds_left()
    if left is not None:
        timeout = max(0.1, min(timeout, left))
    kw: dict = {"verify": False, "timeout": timeout}
    if extra:
        kw.update(extra)
    return kw


def response_metadata(response: Response) -> dict[str, object]:
    headers = response.headers
    history = getattr(response, "history", []) or []
    preview = _decoded_text(response)[:BODY_PREVIEW_LIMIT]
    return {
        "content_type": headers.get("Content-Type"),
        "location": headers.get("Location"),
        "server": headers.get("Server"),
        "etag": headers.get("ETag"),
        "content_length_header": headers.get("Content-Length"),
        "body_preview": preview,
        "final_url": getattr(response, "url", None),
        "redirect_chain": [
            {
                "status_code": item.status_code,
                "location": item.headers.get("Location"),
                "url": getattr(item, "url", None),
            }
            for item in history
        ],
    }


def request_with_retries(
    ctx: RunContext, method: str, url: str, **extra: object
) -> Response:
    attempts = max(1, ctx.retries + 1)
    last_error: RequestException | None = None
    for attempt in range(attempts):
        ctx.ensure_runtime()
        try:
            response = ctx.session.request(method, url, **req_kwargs(ctx, dict(extra)))
            ctx.after_request()
            return response
        except RequestException as exc:
            last_error = exc
            if attempt == attempts - 1:
                raise
            ctx.after_request()
            backoff = min(2.0, 0.25 * (2**attempt))
            left = ctx.seconds_left()
            if left is not None:
                if left <= 0:
                    raise TimeoutError("Global deadline exceeded") from exc
                backoff = min(backoff, left)
            if backoff > 0:
                time.sleep(backoff)
    assert last_error is not None
    raise last_error


def session_get(ctx: RunContext, url: str, **extra: object) -> Response:
    return request_with_retries(ctx, "GET", url, **extra)


def session_post(ctx: RunContext, url: str, **extra: object) -> Response:
    return request_with_retries(ctx, "POST", url, **extra)


def session_request(ctx: RunContext, method: str, url: str, **extra: object) -> Response:
    return request_with_retries(ctx, method, url, **extra)


def content_digest(content: bytes, fp_bytes: int) -> str:
    sample = content[: max(0, fp_bytes)]
    return hashlib.sha256(sample).hexdigest()


def _decoded_text(response: Response) -> str:
    content = getattr(response, "content", b"") or b""
    if isinstance(content, str):
        return content
    return content.decode("utf-8", errors="ignore")


def _normalized_text(response: Response) -> str:
    text = _decoded_text(response).lower()
    text = re.sub(r"\d+", "0", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _extract_title(text: str) -> str:
    match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip().lower()


def _deny_marker_hits(text: str) -> list[str]:
    return [marker for marker in DENY_MARKERS if marker in text]


def _content_type_family(response: Response) -> str:
    content_type = getattr(response, "headers", {}).get("Content-Type", "") or ""
    value = content_type.lower()
    if "json" in value:
        return "json"
    if "html" in value:
        return "html"
    if value.startswith("text/"):
        return "text"
    return "other"


def _json_payload(response: Response) -> object | None:
    try:
        return json.loads(_decoded_text(response))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _json_text(payload: object | None) -> str:
    if isinstance(payload, dict):
        values: list[str] = []
        for key in JSON_DENY_KEYS:
            value = payload.get(key)
            if value is not None:
                values.append(str(value))
        return " ".join(values).lower()
    if isinstance(payload, list):
        return " ".join(str(item) for item in payload).lower()
    if payload is None:
        return ""
    return str(payload).lower()


def _confidence_from_score(score: int, threshold: int) -> str:
    if score <= 0:
        return "low"
    if score >= max(threshold + 20, threshold * 2):
        return "high"
    if score >= threshold:
        return "medium"
    return "low"


def fp_signals(
    ctx: RunContext, baseline: Response, candidate: Response
) -> tuple[bool, dict[str, object]]:
    baseline_len = len(baseline.content)
    candidate_len = len(candidate.content)
    baseline_digest = content_digest(baseline.content, ctx.fp_bytes)
    candidate_digest = content_digest(candidate.content, ctx.fp_bytes)
    baseline_text = _normalized_text(baseline)
    candidate_text = _normalized_text(candidate)
    baseline_title = _extract_title(_decoded_text(baseline))
    candidate_title = _extract_title(_decoded_text(candidate))
    deny_markers = _deny_marker_hits(candidate_text)
    deny_title_markers = _deny_marker_hits(candidate_title)
    location = getattr(candidate, "headers", {}).get("Location", "") or ""
    final_url = getattr(candidate, "url", "") or ""
    parsed_final = urlparse(final_url) if final_url else None
    root_fallback = bool(parsed_final and parsed_final.path in ("", "/"))
    title_mismatch = bool(
        baseline_title and candidate_title and baseline_title != candidate_title
    )
    baseline_content_type_family = _content_type_family(baseline)
    candidate_content_type_family = _content_type_family(candidate)
    same_content_type_family = (
        baseline_content_type_family == candidate_content_type_family
    )
    baseline_json = (
        _json_payload(baseline) if baseline_content_type_family == "json" else None
    )
    candidate_json = (
        _json_payload(candidate) if candidate_content_type_family == "json" else None
    )
    baseline_json_text = _json_text(baseline_json)
    candidate_json_text = _json_text(candidate_json)
    same_json_shape = (
        isinstance(baseline_json, dict)
        and isinstance(candidate_json, dict)
        and set(baseline_json.keys()) == set(candidate_json.keys())
    )
    same_json_text = bool(baseline_json_text) and baseline_json_text == candidate_json_text
    json_deny_markers = _deny_marker_hits(candidate_json_text)
    same_length = baseline_len == candidate_len
    same_digest = baseline_digest == candidate_digest
    same_normalized_text = bool(baseline_text) and baseline_text == candidate_text
    score = 0
    reasons: list[str] = []

    if same_length:
        score += 20
        reasons.append("same_length")
    if same_digest:
        score += 35
        reasons.append("same_digest")
    if same_content_type_family:
        score += 5
        reasons.append("same_content_type_family")
    if same_normalized_text:
        score += 30
        reasons.append("same_normalized_text")
    if baseline_title and candidate_title and baseline_title == candidate_title:
        score += 15
        reasons.append("same_title")
    if deny_markers:
        score += 30
        reasons.append("deny_markers")
    if deny_title_markers:
        score += 15
        reasons.append("deny_title_markers")
    if "/403" in location or "forbidden" in location.lower():
        score += 25
        reasons.append("deny_redirect")
    if root_fallback:
        score += 20
        reasons.append("root_fallback")
    if root_fallback and title_mismatch:
        score += 15
        reasons.append("root_title_mismatch")
    if candidate_content_type_family == "json":
        if same_json_shape:
            score += 10
            reasons.append("same_json_shape")
        if same_json_text:
            score += 20
            reasons.append("same_json_text")
        if json_deny_markers:
            score += 35
            reasons.append("json_deny_markers")

    signals = {
        "baseline_length": baseline_len,
        "candidate_length": candidate_len,
        "baseline_digest": baseline_digest,
        "candidate_digest": candidate_digest,
        "digest_bytes": ctx.fp_bytes,
        "same_length": same_length,
        "same_digest": same_digest,
        "same_normalized_text": same_normalized_text,
        "baseline_content_type_family": baseline_content_type_family,
        "candidate_content_type_family": candidate_content_type_family,
        "same_content_type_family": same_content_type_family,
        "baseline_title": baseline_title,
        "candidate_title": candidate_title,
        "title_mismatch": title_mismatch,
        "deny_markers": deny_markers,
        "deny_title_markers": deny_title_markers,
        "root_fallback": root_fallback,
        "same_json_shape": same_json_shape,
        "same_json_text": same_json_text,
        "json_deny_markers": json_deny_markers,
        "fp_score": score,
        "fp_threshold": ctx.fp_threshold,
        "fp_decision": "possible_false_positive"
        if score >= ctx.fp_threshold
        else "likely_valid",
        "confidence": _confidence_from_score(score, ctx.fp_threshold),
        "fp_reasons": reasons,
    }
    return score >= ctx.fp_threshold, signals
