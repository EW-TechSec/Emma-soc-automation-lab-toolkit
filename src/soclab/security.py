"""Security guards shared by every module.

Any file path built from outside input (a log name, an alert's hostname, an MCP tool
argument) must go through safe_path() before it is opened.
"""

from __future__ import annotations

from pathlib import Path


class PathTraversalError(PermissionError):
    """Raised when a requested path would escape its allowed base directory."""


def safe_path(base: str | Path, user_input: str | Path) -> Path:
    """Resolve user_input inside base, refusing anything that escapes it.

    resolve() collapses "../" segments and follows symlinks, so the containment
    check runs on the real on-disk location, not on how the string looks.
    """
    raw = str(user_input)
    if "\x00" in raw:
        # Null bytes have truncated paths in C-backed APIs; never legitimate here.
        raise PathTraversalError("Null byte in path")

    root = Path(base).resolve()
    target = (root / raw).resolve()  # an absolute user_input replaces root entirely
    if not target.is_relative_to(root):
        raise PathTraversalError(f"Path escapes {root}: {raw!r}")
    return target
