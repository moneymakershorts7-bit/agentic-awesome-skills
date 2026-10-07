"""
sec-userspace standalone runner.

Provides a self-contained execution environment for sec-userspace,
supporting AI tool discovery and built-in interactive client.
"""
import pathlib as _pathlib

def _read_version() -> str:
    """Read version from VERSION file."""
    try:
        vf = _pathlib.Path(__file__).resolve().parent.parent.parent.parent / "VERSION"
        if vf.exists():
            return vf.read_text(encoding='utf-8').strip()
    except OSError:
        pass
    return "1.0.0"

__version__ = _read_version()
