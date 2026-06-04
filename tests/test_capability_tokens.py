from airgap_agent.security.capability_tokens import (
    mint_capability_token,
    parse_hmac_key,
    verify_capability_token,
)


def test_mint_and_verify_roundtrip() -> None:
    key = b"super-secret-key-super-secret-key-super"
    token = mint_capability_token(
        key,
        caps=["fs.read"],
        ttl_seconds=60,
        budgets={"max_total_read_bytes_per_run": 123},
        method="POST",
        path="/v1/agent/run",
        now=1_700_000_000,
    )
    claims = verify_capability_token(key, token, now=1_700_000_010)
    assert "fs.read" in claims.caps
    assert claims.budgets["max_total_read_bytes_per_run"] == 123
    assert claims.method == "POST"
    assert claims.path == "/v1/agent/run"


def test_expired_rejected() -> None:
    key = b"k" * 32
    token = mint_capability_token(key, caps=["fs.read"], ttl_seconds=1, budgets={}, now=10)
    try:
        verify_capability_token(key, token, now=20)
        raise AssertionError("expected expired token to be rejected")
    except ValueError as exc:
        assert "expired" in str(exc)


def test_parse_hmac_key_hex() -> None:
    raw = "ab" * 32
    key = parse_hmac_key(raw)
    assert len(key) == 32
