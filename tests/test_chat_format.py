from airgap_agent.inference.base import ChatMessage
from airgap_agent.inference.chat_format import format_chat_prompt


def test_llama3_template_includes_roles() -> None:
    prompt = format_chat_prompt(
        [
            ChatMessage(role="system", content="sys"),
            ChatMessage(role="user", content="task"),
        ],
        "llama3",
    )
    assert "<|begin_of_text|>" in prompt
    assert "sys" in prompt
    assert "task" in prompt
