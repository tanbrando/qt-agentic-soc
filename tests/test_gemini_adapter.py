"""
Unit tests for synchronous GeminiSOCAnalystLLM adapter, thought_signature preservation,
and graceful fallback behavior.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from server.src.agent.gemini_llm import GeminiSOCAnalystLLM
from server.src.agent.state import AIMessage, HumanMessage, SystemMessage, ToolMessage
from server.src.agent.tools import CheckIPReputationArgs


def test_gemini_llm_initialization_without_key_and_placeholder():
    with patch.dict("os.environ", {}, clear=True):
        llm = GeminiSOCAnalystLLM(api_key=None)
        assert llm.is_configured() is False
        assert llm.model == "gemini-2.5-flash-lite"

        llm_ph = GeminiSOCAnalystLLM(api_key="your_gemini_api_key_here")
        assert llm_ph.is_configured() is False


def test_gemini_llm_fallback_on_missing_key():
    with patch.dict("os.environ", {}, clear=True):
        llm = GeminiSOCAnalystLLM(api_key=None)
        messages = [
            SystemMessage(content="You are a SOC analyst."),
            HumanMessage(content="Incident with attacker IP 203.0.113.195"),
        ]
        resp = llm.invoke(messages)
        assert isinstance(resp, AIMessage)
        assert len(resp.tool_calls) > 0
        assert resp.tool_calls[0]["name"] == "check_ip_reputation"
        assert resp.tool_calls[0]["args"]["ip"] == "203.0.113.195"


def test_gemini_llm_tool_binding():
    class DummyTool:
        name = "check_ip_reputation"
        description = "Check IP reputation"
        args_schema = CheckIPReputationArgs

    llm = GeminiSOCAnalystLLM(api_key="test-key-123")
    bound = llm.bind_tools([DummyTool()])
    declarations = bound._convert_tools_to_declarations()
    assert len(declarations) == 1
    assert declarations[0].name == "check_ip_reputation"
    assert "ip" in declarations[0].parameters.properties


def test_gemini_llm_thought_signature_and_fallback_formatting():
    llm = GeminiSOCAnalystLLM(api_key="test-key-123")
    sentinel_content = MagicMock(name="genai_content_with_thought_sig")

    # 1. Gemini turn with genai_content followed by ToolMessage preserves function_response
    msgs_gemini = [
        SystemMessage(content="Sys"),
        HumanMessage(content="Check 1.2.3.4"),
        AIMessage(content="", tool_calls=[{"id": "1", "name": "check_ip_reputation", "args": {"ip": "1.2.3.4"}}], additional_kwargs={"genai_content": sentinel_content}),
        ToolMessage(content='{"score": 90}', tool_call_id="1", name="check_ip_reputation"),
    ]
    sys_inst, contents = llm._format_conversation(msgs_gemini)
    assert sys_inst == "Sys"
    assert contents[1] is sentinel_content
    assert contents[2].parts[0].function_response is not None

    # 2. Fallback turn WITHOUT genai_content serializes as plain text (no synthetic function_call)
    msgs_fallback = [
        HumanMessage(content="Check 1.2.3.4"),
        AIMessage(content="Checking...", tool_calls=[{"id": "1", "name": "check_ip_reputation", "args": {"ip": "1.2.3.4"}}]),
        ToolMessage(content='{"score": 90}', tool_call_id="1", name="check_ip_reputation"),
    ]
    _, fb_contents = llm._format_conversation(msgs_fallback)
    assert fb_contents[1].role == "model"
    assert fb_contents[1].parts[0].function_call is None
    assert "Observation [check_ip_reputation]" in fb_contents[2].parts[0].text


def test_gemini_llm_exception_fallback():
    llm = GeminiSOCAnalystLLM(api_key="test-key-123")
    llm._client = MagicMock()
    llm._client.models.generate_content.side_effect = RuntimeError("429 RESOURCE_EXHAUSTED")

    resp = llm.invoke(
        [
            SystemMessage(content="SOC prompt"),
            HumanMessage(content="Attacker IP 203.0.113.195 detected"),
        ]
    )
    assert isinstance(resp, AIMessage)
    assert resp.tool_calls[0]["name"] == "check_ip_reputation"

