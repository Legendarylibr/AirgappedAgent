import json
import os
from pathlib import Path

from airgap_agent.config import AuditSettings, BundleSettings, TrustSettings
from airgap_agent.crypto import generate_keypair, verify_audit_chain
from airgap_agent.crypto.encrypt import open_line, parse_key_material
from airgap_agent.deployment.bundle import sign_manifest, verify_bundle
from airgap_agent.security import AuditLogger
from airgap_agent.security.policy import PolicyEngine


def test_ed25519_manifest_sign_verify(tmp_path: Path) -> None:
    models = tmp_path / "models"
    models.mkdir()
    (models / "w.gguf").write_bytes(b"weights")

    private, public = generate_keypair(tmp_path, "test")
    sign_manifest(models, private, "test")

    trust = TrustSettings(public_keys_dir=tmp_path / "trust", require_signed_manifest=True)
    result = verify_bundle(BundleSettings(models_dir=models), trust)
    assert result.ok
    assert result.signature_ok is True

    (models / "w.gguf").write_bytes(b"tampered")
    tampered = verify_bundle(BundleSettings(models_dir=models), trust)
    assert not tampered.ok


def test_policy_signature_required(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: '1'\ndefaults:\n  effect: deny\nrules: []\n")
    trust = TrustSettings(public_keys_dir=tmp_path / "trust", require_signed_policy=True)

    try:
        PolicyEngine(policy, trust)
        raise AssertionError("expected unsigned policy to fail")
    except PermissionError:
        pass

    private, _ = generate_keypair(tmp_path, "pol")
    from airgap_agent.crypto.sign import sign_file, write_envelope

    write_envelope(sign_file(policy, private, "pol"), policy.parent / "policy.yaml.sig.json")
    engine = PolicyEngine(policy, trust)
    assert engine.evaluate("tool.invoke", {"tool_name": "read_file"}).effect == "deny"


def test_audit_hash_chain(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    audit = AuditLogger(AuditSettings(enabled=True, log_path=log, hash_chain=True))
    audit.emit("one", x=1)
    audit.emit("two", x=2)

    lines = log.read_text().splitlines()
    ok, count, errors = verify_audit_chain(lines)
    assert ok, errors
    assert count == 2

    records = [json.loads(ln) for ln in lines]
    assert records[1]["audit_prev_hash"] == records[0]["audit_entry_hash"]


def test_audit_encryption_roundtrip(tmp_path: Path) -> None:
    key_hex = "ab" * 32
    os.environ["AIRGAP_AUDIT_ENCRYPTION_KEY"] = key_hex
    log = tmp_path / "enc.jsonl"
    audit = AuditLogger(
        AuditSettings(
            enabled=True,
            log_path=log,
            hash_chain=True,
            encrypt_at_rest=True,
            encryption_key_env="AIRGAP_AUDIT_ENCRYPTION_KEY",
        )
    )
    audit.emit("secret", token="redacted")
    sealed = log.read_text().strip()
    assert sealed.startswith("ENC1:")

    key = parse_key_material(key_hex)
    plain = open_line(key, sealed)
    record = json.loads(plain)
    assert record["event"] == "secret"
    assert "audit_entry_hash" in record
