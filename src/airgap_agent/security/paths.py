from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

from airgap_agent.security.errors import SandboxError

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


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

    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise SandboxError(f"symlinks are not allowed: {user_path}")

    target = (root / relative).resolve(strict=False)
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise SandboxError(f"path escapes workspace: {user_path}") from exc

    if target.is_symlink():
        raise SandboxError(f"symlinks are not allowed: {user_path}")
    return target


def read_file_bounded(path: Path, max_bytes: int) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW)
    except OSError as exc:
        raise SandboxError(f"failed to open file safely: {exc}") from exc

    try:
        file_stat = os.fstat(fd)
        if file_stat.st_size > max_bytes:
            raise SandboxError(f"file exceeds max size ({file_stat.st_size} > {max_bytes} bytes)")
        return os.read(fd, max_bytes).decode("utf-8", errors="replace")
    finally:
        os.close(fd)


def write_file_bounded(path: Path, content: str, max_bytes: int) -> None:
    encoded = content.encode("utf-8")
    if len(encoded) > max_bytes:
        raise SandboxError(f"write exceeds max size ({len(encoded)} > {max_bytes} bytes)")

    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink():
        raise SandboxError(f"symlinks are not allowed: {parent}")

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW
    try:
        dir_fd = os.open(parent, flags)
    except OSError as exc:
        raise SandboxError(f"failed to open parent directory safely: {exc}") from exc

    tmp_name = f".{path.name}.{secrets.token_hex(8)}.tmp"
    try:
        try:
            existing = os.lstat(path.name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(existing.st_mode):
                raise SandboxError(f"symlinks are not allowed: {path.name}")

        tmp_fd = os.open(
            tmp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
            0o600,
            dir_fd=dir_fd,
        )
        try:
            os.write(tmp_fd, encoded)
            os.fsync(tmp_fd)
        finally:
            os.close(tmp_fd)

        os.replace(tmp_name, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        os.fsync(dir_fd)
    except OSError as exc:
        raise SandboxError(f"failed to write file safely: {exc}") from exc
    finally:
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        os.close(dir_fd)
