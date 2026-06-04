from __future__ import annotations

from enum import StrEnum


class Capability(StrEnum):
    FS_READ = "fs.read"
    FS_LIST = "fs.list"
    FS_SEARCH = "fs.search"
    FS_WRITE = "fs.write"
    PY_EXEC = "py.exec"
