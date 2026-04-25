"""Oturum, çıktı biçimi ve bulgu toplama."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Literal

import requests

OutputFormat = Literal["text", "json", "csv"]
FpBaselineMode = Literal["auto", "target", "root"]


@dataclass
class RunContext:
    """requests.Session + isteğe bağlı yapılandırılmış çıktı (json/csv)."""

    session: requests.Session
    verbose: bool
    output_format: OutputFormat
    ip: str
    delay_sec: float = 0.0
    rate_limit: float = 0.0
    timeout_sec: float = 5.0
    retries: int = 0
    deadline_sec: float = 0.0
    fp_bytes: int = 64
    fp_threshold: int = 40
    fp_baseline: FpBaselineMode = "auto"
    enable_http2: bool = False
    extra_payloads: list[str] = field(default_factory=list)
    extra_ip_headers: list[str] = field(default_factory=list)
    extra_methods: list[str] = field(default_factory=list)
    aggressive: bool = False
    profile: str = "default"
    enabled_probes: set[str] = field(default_factory=set)
    concurrency: int = 1
    findings: list[dict[str, Any]] = field(default_factory=list)
    has_hit: bool = False
    schema_version: str = "1.0"
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _last_request_at: float = field(default=0.0, init=False, repr=False)
    _started_at: float = field(default_factory=time.monotonic, init=False, repr=False)

    @property
    def structured(self) -> bool:
        """json veya csv: insan çıktısı yok, bulgular toplanır."""
        return self.output_format in ("json", "csv")

    def record(self, **row: Any) -> None:
        if self.structured:
            with self._lock:
                self.findings.append(dict(row))

    def register_hit(self) -> None:
        """Çıkış kodu 0 için anlamlı sinyal (bypass / erişim ipucu)."""
        with self._lock:
            self.has_hit = True

    def after_request(self) -> None:
        with self._lock:
            now = time.monotonic()
            min_interval = 0.0
            if self.rate_limit > 0:
                min_interval = 1.0 / self.rate_limit
            wait_time = max(self.delay_sec, min_interval)
            elapsed = now - self._last_request_at if self._last_request_at else None
            if wait_time > 0 and elapsed is not None and elapsed < wait_time:
                time.sleep(wait_time - elapsed)
                now = time.monotonic()
            self._last_request_at = now

    def deadline_exceeded(self) -> bool:
        if self.deadline_sec <= 0:
            return False
        return (time.monotonic() - self._started_at) >= self.deadline_sec

    def seconds_left(self) -> float | None:
        if self.deadline_sec <= 0:
            return None
        return max(0.0, self.deadline_sec - (time.monotonic() - self._started_at))

    def ensure_runtime(self) -> None:
        if self.deadline_exceeded():
            raise TimeoutError("Global deadline exceeded")


def build_session(
    proxy: str | None,
    cookie: str | None,
    extra_headers: dict[str, str],
) -> requests.Session:
    s = requests.Session()
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})
    s.headers.update({"User-Agent": "NoMoreForbidden/0.4"})
    s.headers.update(extra_headers)
    if cookie:
        s.headers["Cookie"] = cookie
    return s
