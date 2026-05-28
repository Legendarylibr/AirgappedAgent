from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class HuggingFaceHubUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class HfDownloadResult:
    repo_id: str
    revision: str | None
    local_dir: Path
    resolved_commit: str | None
    downloaded_paths: list[Path]


def _require_hub():
    try:
        from huggingface_hub import HfApi, snapshot_download  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise HuggingFaceHubUnavailable(
            "huggingface_hub not installed. Install with: pip install 'airgap-agent[hf]'"
        ) from exc
    return HfApi, snapshot_download


def hf_snapshot_download(
    *,
    repo_id: str,
    local_dir: Path,
    revision: str | None = None,
    allow_patterns: Iterable[str] | None = None,
) -> HfDownloadResult:
    """
    Connected-host only. Downloads selected artifacts into local_dir.

    The airgapped host should never run this. Instead, generate+sign the bundle
    and transfer (models + MANIFEST + signatures + trust public keys).
    """
    HfApi, snapshot_download = _require_hub()
    local_dir = local_dir.resolve()
    local_dir.mkdir(parents=True, exist_ok=True)

    allow = list(allow_patterns or [])
    snapshot_path = snapshot_download(
        repo_id=repo_id,
        revision=revision,
        local_dir=str(local_dir),
        local_dir_use_symlinks=False,
        allow_patterns=allow if allow else None,
    )

    api = HfApi()
    resolved_commit: str | None = None
    try:
        info = api.repo_info(repo_id=repo_id, revision=revision)
        resolved_commit = getattr(info, "sha", None)
    except Exception:
        resolved_commit = None

    downloaded: list[Path] = []
    for p in Path(snapshot_path).rglob("*"):
        if p.is_file():
            downloaded.append(p)

    _write_hf_source_metadata(local_dir, repo_id=repo_id, revision=revision, commit=resolved_commit)
    return HfDownloadResult(
        repo_id=repo_id,
        revision=revision,
        local_dir=local_dir,
        resolved_commit=resolved_commit,
        downloaded_paths=downloaded,
    )


def _write_hf_source_metadata(local_dir: Path, *, repo_id: str, revision: str | None, commit: str | None) -> None:
    """
    Records provenance into the bundle so third parties can verify the exact upstream reference
    (plus our manifest+signature for integrity/authenticity).
    """
    path = local_dir / "HF_SOURCE.json"
    payload = {"repo_id": repo_id, "revision": revision, "resolved_commit": commit}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

