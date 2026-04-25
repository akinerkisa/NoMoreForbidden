"""renikApp (yerel) ile uçtan uca smoke test.

Önce 127.0.0.1:5000 yanıt veriyorsa mevcut sunucu kullanılır; aksi halde
``renikApp/run_dev.py`` ile geçici süreç başlatılır (Flask kurulu olmalı).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RENIK = os.environ.get("RENIKAPP_URL", "http://127.0.0.1:5000").rstrip("/")


def _renik_reachable() -> bool:
    try:
        urllib.request.urlopen(f"{RENIK}/", timeout=2)
        return True
    except (urllib.error.URLError, OSError, TimeoutError):
        return False


@pytest.fixture(scope="module")
def renik_server() -> None:
    if _renik_reachable():
        yield
        return
    renik_dir = ROOT / "renikApp"
    proc = subprocess.Popen(
        [sys.executable, str(renik_dir / "run_dev.py")],
        cwd=str(renik_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    for _ in range(30):
        if _renik_reachable():
            break
        time.sleep(0.2)
    else:
        err = b""
        if proc.stderr:
            err = proc.stderr.read(4000)
        proc.terminate()
        pytest.skip(f"renikApp başlatılamadı: {err.decode(errors='replace')!r}")
    yield
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("renik_server")]


@pytest.mark.parametrize(
    "path",
    [
        "/403/secret",
        "/403/original-url-only",
        "/403/method-override-only",
        "/403/header-combo-only",
    ],
)
def test_renik_403_real_bypass_paths(path: str) -> None:
    url = f"{RENIK}{path}"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "nmf.py"),
            "-u",
            url,
            "--only",
            "nmf",
            "--json",
            "--timeout",
            "8",
            "-ip",
            "127.0.0.1",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    data = json.loads(proc.stdout)
    assert data.get("hit") is True


def test_renik_fake_200_flags_possible_fp() -> None:
    url = f"{RENIK}/403/fake-200"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "nmf.py"),
            "-u",
            url,
            "--only",
            "nmf",
            "--json",
            "--timeout",
            "8",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    data = json.loads(proc.stdout)
    assert data.get("hit") is True
    summary = data.get("summary") or {}
    assert int(summary.get("possible_false_positives", 0)) >= 1
