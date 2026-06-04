import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from airgap_agent.security.replay_cache import ReplayNonceCache


def test_replay_cache_rejects_duplicate(tmp_path: Path) -> None:
    path = tmp_path / "nonces.json"
    cache = ReplayNonceCache(path, max_entries=100)
    exp = int(time.time()) + 60
    assert cache.accept("nonce-a", exp) is True
    assert cache.accept("nonce-a", exp) is False


def test_replay_cache_persists(tmp_path: Path) -> None:
    path = tmp_path / "nonces.json"
    exp = int(time.time()) + 60
    ReplayNonceCache(path, max_entries=100).accept("nonce-b", exp)
    reloaded = ReplayNonceCache(path, max_entries=100)
    assert reloaded.accept("nonce-b", exp) is False


def test_replay_cache_accept_is_thread_safe(tmp_path: Path) -> None:
    path = tmp_path / "nonces.json"
    cache = ReplayNonceCache(path, max_entries=100)
    exp = int(time.time()) + 60
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: cache.accept("nonce-c", exp), range(32)))

    assert results.count(True) == 1
    assert results.count(False) == 31
