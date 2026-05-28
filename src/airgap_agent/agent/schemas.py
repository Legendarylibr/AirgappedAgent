from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field, field_validator

_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_PATH_LEN = 4096
_MAX_SOURCE_LEN = 64_000
_MAX_QUERY_LEN = 512


class ReadFileArgs(BaseModel):
    path: str = Field(min_length=1, max_length=_MAX_PATH_LEN)

    @field_validator("path")
    @classmethod
    def path_chars(cls, v: str) -> str:
        if "\x00" in v:
            raise ValueError("invalid path")
        return v


class ListDirectoryArgs(BaseModel):
    path: str = Field(default=".", max_length=_MAX_PATH_LEN)


class SearchTextArgs(BaseModel):
    path: str = Field(default=".", max_length=_MAX_PATH_LEN)
    query: str = Field(min_length=1, max_length=_MAX_QUERY_LEN)


class RunPythonArgs(BaseModel):
    source: str = Field(min_length=1, max_length=_MAX_SOURCE_LEN)


def validate_tool_arguments(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if not _TOOL_NAME_RE.match(tool):
        raise ValueError(f"invalid tool name: {tool}")
    models: dict[str, type[BaseModel]] = {
        "read_file": ReadFileArgs,
        "list_directory": ListDirectoryArgs,
        "search_text": SearchTextArgs,
        "run_python": RunPythonArgs,
    }
    model = models.get(tool)
    if model is None:
        raise ValueError(f"unknown tool: {tool}")
    return model.model_validate(arguments).model_dump()
