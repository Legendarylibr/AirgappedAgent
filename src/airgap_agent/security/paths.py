from __future__ import annotations

from pathlib import Path

from airgap_agent.security.errors import SandboxError


def resolve_workspace_path(workspace_root: Path, user_path: str) -> Path:
    """Resolve a path inside the workspace; reject traversal and symlinks."""
    if not user_path or user_path.strip() == "":
        user_path = "."

    root = workspace_root.resolve()
    relative = Path(user_path)
    if relative.is_absolute():
        raise SandboxError("absolute paths are not allowed")
    if ".." in relative.parts:
        raise SandboxError(f"path escapes workspace: {user_path}")

    candidate = root / relative
    if candidate.is_symlink():
        raise SandboxError(f"symlinks are not allowed: {user_path}")

    target = candidate.resolve(strict=False)
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise SandboxError(f"path escapes workspace: {user_path}") from exc

    if target.is_symlink():
        raise SandboxError(f"symlinks are not allowed: {user_path}")
    return target


def read_file_bounded(path: Path, max_bytes: int) -> str:
    size = path.stat().st_size
    if size > max_bytes:
        raise SandboxError(f"file exceeds max size ({size} > {max_bytes} bytes)")
    return path.read_bytes()[:max_bytes].decode("utf-8", errors="replace")
