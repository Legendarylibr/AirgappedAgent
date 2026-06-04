from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from airgap_agent.config import BundleSettings, TrustSettings
from airgap_agent.crypto.sign import (
    load_envelope,
    sha256_file,
    sign_file,
    verify_envelope,
    write_envelope,
)


@dataclass
class BundleVerification:
    ok: bool
    checked: int
    errors: list[str] = field(default_factory=list)
    signature_ok: bool | None = None


def _resolve_bundle_manifest_path(models_dir: Path, rel: str) -> Path:
    relative = Path(rel)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"path escapes bundle: {rel}")

    candidate = models_dir
    for part in relative.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError(f"symlinks are not allowed in bundle manifest: {rel}")

    target = candidate.resolve(strict=False)
    target.relative_to(models_dir)
    return target


def write_manifest(models_dir: Path, manifest_name: str = "MANIFEST.sha256") -> Path:
    models_dir = models_dir.resolve()
    lines: list[str] = []
    for path in sorted(models_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name in (manifest_name, "MANIFEST.sig.json"):
            continue
        if path.suffix == ".json" and path.name.endswith(".sig.json"):
            continue
        digest = sha256_file(path)
        rel = path.relative_to(models_dir)
        lines.append(f"{digest}  {rel}")
    manifest = models_dir / manifest_name
    manifest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return manifest


def sign_manifest(
    models_dir: Path,
    private_key_path: Path,
    key_id: str,
    *,
    manifest_name: str = "MANIFEST.sha256",
    signature_name: str = "MANIFEST.sig.json",
) -> Path:
    models_dir = models_dir.resolve()
    manifest = write_manifest(models_dir, manifest_name)
    envelope = sign_file(manifest, private_key_path, key_id)
    sig_path = models_dir / signature_name
    write_envelope(envelope, sig_path)
    return sig_path


def verify_manifest_signature(
    models_dir: Path,
    trust: TrustSettings,
    *,
    manifest_name: str = "MANIFEST.sha256",
    signature_name: str = "MANIFEST.sig.json",
) -> tuple[bool, list[str]]:
    models_dir = models_dir.resolve()
    manifest = models_dir / manifest_name
    sig_path = models_dir / signature_name
    errors: list[str] = []

    if not sig_path.exists():
        return False, [f"signature missing: {sig_path}"]
    if not manifest.exists():
        return False, [f"manifest missing: {manifest}"]

    envelope = load_envelope(sig_path)
    ok, ver_errors = verify_envelope(envelope, manifest, trust.public_keys_dir)
    errors.extend(ver_errors)
    return ok, errors


def verify_bundle(
    settings: BundleSettings, trust: TrustSettings | None = None
) -> BundleVerification:
    models_dir = settings.models_dir.resolve()
    manifest = models_dir / settings.manifest_name
    errors: list[str] = []
    checked = 0
    signature_ok: bool | None = None

    if not models_dir.exists():
        return BundleVerification(ok=False, checked=0, errors=[f"models dir missing: {models_dir}"])

    if not manifest.exists():
        return BundleVerification(ok=False, checked=0, errors=[f"manifest missing: {manifest}"])

    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            digest, rel = line.split(maxsplit=1)
        except ValueError:
            errors.append(f"invalid manifest line: {line}")
            continue
        rel = rel.strip()
        try:
            target = _resolve_bundle_manifest_path(models_dir, rel)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not target.is_file():
            errors.append(f"missing file: {rel}")
            continue
        actual = sha256_file(target)
        checked += 1
        if actual != digest:
            errors.append(f"hash mismatch: {rel}")

    if trust and trust.require_signed_manifest:
        sig_ok, sig_errors = verify_manifest_signature(
            models_dir,
            trust,
            manifest_name=settings.manifest_name,
            signature_name=settings.signature_name,
        )
        signature_ok = sig_ok
        errors.extend(sig_errors)

    return BundleVerification(
        ok=len(errors) == 0,
        checked=checked,
        errors=errors,
        signature_ok=signature_ok,
    )


def verify_signed_artifact(
    artifact: Path,
    trust: TrustSettings,
    *,
    signature_path: Path | None = None,
) -> tuple[bool, list[str]]:
    artifact = artifact.resolve()
    sig_path = signature_path or (artifact.parent / f"{artifact.name}.sig.json")
    if not sig_path.exists():
        return False, [f"signature missing: {sig_path}"]
    envelope = load_envelope(sig_path)
    return verify_envelope(envelope, artifact, trust.public_keys_dir)
