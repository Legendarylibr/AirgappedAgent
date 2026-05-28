from airgap_agent.agent.session import SessionStore
from airgap_agent.inference.base import ChatMessage


def test_session_create_append_and_ttl() -> None:
    store = SessionStore(max_sessions=2, max_messages=10, ttl_seconds=3600)
    sid = store.create()
    assert store.get_history(sid) == []
    store.append(sid, [ChatMessage(role="user", content="hi")])
    hist = store.get_history(sid)
    assert hist is not None
    assert len(hist) == 1
    assert store.delete(sid)
    assert store.get_history(sid) is None
