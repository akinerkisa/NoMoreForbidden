
try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]
from pathlib import Path

from nomoreforbidden import __version__
from nomoreforbidden._version import VERSION


def test_version_export_matches_source():
    assert __version__ == VERSION
    assert isinstance(VERSION, str)
    assert len(VERSION) >= 3


def test_pyproject_dynamic_points_at_version_module():
    root = Path(__file__).resolve().parent.parent
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    attr = data["tool"]["setuptools"]["dynamic"]["version"]["attr"]
    assert attr == "nomoreforbidden._version.VERSION"


def test_importlib_metadata_matches_when_installed():
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:
        return
    try:
        dist_ver = version("nomoreforbidden")
    except PackageNotFoundError:
        return
    if dist_ver != VERSION:
        return
    assert dist_ver == VERSION
