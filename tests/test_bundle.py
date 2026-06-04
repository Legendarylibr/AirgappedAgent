from pathlib import Path

from airgap_agent.config import BundleSettings
from airgap_agent.deployment.bundle import verify_bundle, write_manifest


def test_manifest_roundtrip(tmp_path: Path) -> None:
    models = tmp_path / "models"
    models.mkdir()
    (models / "a.gguf").write_bytes(b"fake-weights-a")
    (models / "subdir").mkdir()
    (models / "subdir" / "b.gguf").write_bytes(b"fake-weights-b")

    write_manifest(models)
    settings = BundleSettings(models_dir=models)
    result = verify_bundle(settings)
    assert result.ok
    assert result.checked == 2


def test_tamper_detected(tmp_path: Path) -> None:
    models = tmp_path / "models"
    models.mkdir()
    f = models / "model.gguf"
    f.write_bytes(b"v1")
    write_manifest(models)
    f.write_bytes(b"v2-tampered")
    result = verify_bundle(BundleSettings(models_dir=models))
    assert not result.ok
    assert result.errors


def test_manifest_rejects_path_escape(tmp_path: Path) -> None:
    models = tmp_path / "models"
    models.mkdir()
    outside = tmp_path / "outside.gguf"
    outside.write_bytes(b"outside")
    manifest = models / "MANIFEST.sha256"
    manifest.write_text(
        "0" * 64 + "  ../outside.gguf\n",
        encoding="utf-8",
    )

    result = verify_bundle(BundleSettings(models_dir=models))
    assert not result.ok
    assert any("escapes bundle" in err for err in result.errors)


def test_manifest_rejects_symlink_entry(tmp_path: Path) -> None:
    models = tmp_path / "models"
    models.mkdir()
    target = models / "target.gguf"
    target.write_bytes(b"weights")
    (models / "link.gguf").symlink_to(target)
    manifest = models / "MANIFEST.sha256"
    manifest.write_text(
        "0" * 64 + "  link.gguf\n",
        encoding="utf-8",
    )

    result = verify_bundle(BundleSettings(models_dir=models))
    assert not result.ok
    assert any("symlinks are not allowed" in err for err in result.errors)
