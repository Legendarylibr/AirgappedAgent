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
