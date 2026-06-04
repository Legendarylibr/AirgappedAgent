import pytest

from airgap_agent.config import InferenceSettings


@pytest.mark.parametrize(
    "base_url",
    [
        "http://127.0.0.1:8080/v1",
        "http://localhost:8080/v1",
        "http://[::1]:8080/v1",
    ],
)
def test_inference_base_url_accepts_loopback(base_url: str) -> None:
    assert InferenceSettings(base_url=base_url).base_url == base_url


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost.evil/v1",
        "http://127.0.0.1.evil/v1",
        "http://10.0.0.1:8080/v1",
        "ftp://127.0.0.1/v1",
    ],
)
def test_inference_base_url_rejects_non_loopback(base_url: str) -> None:
    with pytest.raises(ValueError, match="inference.base_url"):
        InferenceSettings(base_url=base_url)
