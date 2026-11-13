"""
Synchronous Google Gemini LLM Adapter and Rule-Guided Heuristic Fallback LLM
for the Agentic SOC LangGraph Investigation Workflow.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Sequence
from uuid import uuid4

from server.src.agent.state import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

logger = logging.getLogger("agentic_soc.agent.gemini_llm")

_PLACEHOLDER_PREFIXES = ("your_", "CHANGE_ME")

try:
    from google import genai
    from google.genai import types as genai_types

    GENAI_AVAILABLE = True
except ImportError:
    genai = None  # type: ignore
    genai_types = None  # type: ignore
    GENAI_AVAILABLE = False


class RuleGuidedSOCAnalystLLM:
    """
    Deterministic, offline-capable synchronous Tool-Calling LLM emulator
    adhering to LangChain ChatModel contracts (`invoke` / `bind_tools`).
    Used automatically when GEMINI_API_KEY is unconfigured or free-tier quota is hit.
    """

    def __init__(self, tools: Optional[Sequence[Any]] = None) -> None:
        self.tools = list(tools or [])

    def bind_tools(self, tools: Sequence[Any]) -> RuleGuidedSOCAnalystLLM:
        return RuleGuidedSOCAnalystLLM(tools=tools)

    def invoke(self, messages: List[BaseMessage]) -> AIMessage:
        """Inspects messages and selects the next investigative tool call or conclusion."""
        executed_tool_names = {
            getattr(msg, "name", None)
            for msg in messages
            if isinstance(msg, ToolMessage) or getattr(msg, "name", None)
        }

        initial_context = " ".join(
            getattr(m, "content", "") for m in messages if isinstance(m, HumanMessage)
        ).strip()
        if not initial_context:
            initial_context = " ".join(getattr(m, "content", "") for m in messages)

        # Extract candidate IPs from initial case context
        ip_candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", initial_context)
        target_ips = [
            ip
            for ip in dict.fromkeys(ip_candidates)
            if ip not in ("0.0.0.0", "255.255.255.0", "127.0.0.1")
        ]

        # Extract target username if present in ECS group_key JSON
        user_match = re.search(r'"(?:user\.name|user|username)"\s*:\s*"([^"]+)"', initial_context)
        target_user = user_match.group(1) if user_match else None

        # Step A: Check IP reputation if external/observed IP is present
        if "check_ip_reputation" not in executed_tool_names and target_ips:
            attacker_ip = target_ips[0]
            return AIMessage(
                content=f"Identified observable source IP {attacker_ip}. Querying Threat Intelligence...",
                tool_calls=[
                    {
                        "id": f"call_rep_{uuid4().hex[:6]}",
                        "name": "check_ip_reputation",
                        "args": {"ip": attacker_ip},
                    }
                ],
            )

        # Step B: Search corroborating ECS logs
        if "search_logs" not in executed_tool_names:
            query_filter: Dict[str, Any] = {}
            if target_ips:
                query_filter["src_ip"] = target_ips[0]
            elif target_user:
                query_filter["user"] = target_user

            return AIMessage(
                content="Querying normalized ECS logs for corroborating timeline events...",
                tool_calls=[
                    {
                        "id": f"call_logs_{uuid4().hex[:6]}",
                        "name": "search_logs",
                        "args": {"query_filter": query_filter, "limit": 20},
                    }
                ],
            )

        # Step C: If a user account is involved, inspect user activity history
        if (
            "get_user_activity_history" not in executed_tool_names
            and target_user
            and any(getattr(t, "name", "") == "get_user_activity_history" for t in self.tools)
        ):
            return AIMessage(
                content=f"Correlating post-auth activity history for user '{target_user}'...",
                tool_calls=[
                    {
                        "id": f"call_usr_{uuid4().hex[:6]}",
                        "name": "get_user_activity_history",
                        "args": {"user_name": target_user, "limit": 15},
                    }
                ],
            )

        # Step D: Ready to conclude
        return AIMessage(
            content=(
                "Corroborating ECS telemetry and Threat Intelligence enrichment complete. "
                "Proceeding to verdict synthesis and containment recommendations."
            ),
            tool_calls=[],
        )


class GeminiSOCAnalystLLM:
    """
    Synchronous Google Gemini adapter using `google.genai` SDK (`gemini-2.5-flash-lite` default).
    Preserves encrypted `thought_signature` across multi-turn tool-calling loops and
    degrades seamlessly to `RuleGuidedSOCAnalystLLM` on quota/network errors.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-2.5-flash-lite",
        tools: Optional[Sequence[Any]] = None,
        temperature: float = 0.1,
    ) -> None:
        raw_key = api_key if api_key is not None else os.getenv("GEMINI_API_KEY", "")
        cleaned_key = raw_key.strip()
        if cleaned_key.startswith(_PLACEHOLDER_PREFIXES):
            cleaned_key = ""
        self.api_key = cleaned_key

        env_model = os.getenv("GEMINI_MODEL", "").strip()
        self.model = env_model or model
        self.tools = list(tools or [])
        self.temperature = temperature
        self.fallback_llm = RuleGuidedSOCAnalystLLM(tools=self.tools)

        self._client: Optional[Any] = None
        if GENAI_AVAILABLE and self.api_key:
            try:
                self._client = genai.Client(api_key=self.api_key)
            except Exception as exc:
                logger.warning("Failed to initialize google.genai Client: %s", exc)
                self._client = None

    def bind_tools(self, tools: Sequence[Any]) -> GeminiSOCAnalystLLM:
        """Returns a new GeminiSOCAnalystLLM bound to the specified tool list."""
        return GeminiSOCAnalystLLM(
            api_key=self.api_key,
            model=self.model,
            tools=tools,
            temperature=self.temperature,
        )

    def is_configured(self) -> bool:
        """Returns True when `google.genai` is importable and a non-placeholder API key is set."""
        return GENAI_AVAILABLE and bool(self.api_key) and self._client is not None

    def _convert_tools_to_declarations(self) -> List[Any]:
        """Converts investigation tools with Pydantic args_schema to Gemini FunctionDeclarations."""
        if not GENAI_AVAILABLE or not self.tools:
            return []

        declarations: List[Any] = []
        for tool in self.tools:
            name = getattr(tool, "name", str(tool))
            description = getattr(tool, "description", f"SOC Investigation tool: {name}")
            args_schema = getattr(tool, "args_schema", None)

            props: Dict[str, Any] = {}
            required: List[str] = []
            if args_schema and hasattr(args_schema, "model_json_schema"):
                schema_dict = args_schema.model_json_schema()
                props = schema_dict.get("properties", {})
                required = schema_dict.get("required", [])

            clean_props: Dict[str, Any] = {}
            for k, v in props.items():
                raw_type = str(v.get("type", "string")).upper()
                prop_def: Dict[str, Any] = {
                    "type": raw_type if raw_type in ("STRING", "INTEGER", "NUMBER", "BOOLEAN", "ARRAY", "OBJECT") else "STRING",
                    "description": v.get("description", k),
                }
                if prop_def["type"] == "ARRAY":
                    items_type = str((v.get("items") or {}).get("type", "string")).upper()
                    prop_def["items"] = {"type": items_type}
                clean_props[k] = prop_def

            declarations.append(
                genai_types.FunctionDeclaration(
                    name=name,
                    description=description,
                    parameters={
                        "type": "OBJECT",
                        "properties": clean_props,
                        "required": required,
                    },
                )
            )
        return declarations

    def _format_conversation(self, messages: List[BaseMessage]) -> tuple[Optional[str], List[Any]]:
        """
        Formats conversation history for Gemini API:
        - Preserves `genai_content` on Gemini-originated turns so `thought_signature` stays intact.
        - Serializes fallback/emulator turns as plain text observations so Gemini never rejects
          synthetic `functionCall` parts missing a `thought_signature`.
        """
        system_instruction: Optional[str] = None
        contents: List[Any] = []
        last_ai_had_genai_content = False

        for msg in messages:
            if isinstance(msg, SystemMessage):
                system_instruction = msg.content
            elif isinstance(msg, HumanMessage):
                contents.append(
                    genai_types.Content(
                        role="user",
                        parts=[genai_types.Part.from_text(text=msg.content)],
                    )
                )
            elif isinstance(msg, AIMessage):
                cached_content = getattr(msg, "additional_kwargs", {}).get("genai_content")
                if cached_content is not None:
                    contents.append(cached_content)
                    last_ai_had_genai_content = True
                else:
                    last_ai_had_genai_content = False
                    tool_calls = getattr(msg, "tool_calls", [])
                    tc_text = ""
                    if tool_calls:
                        names = ", ".join(tc.get("name", "tool") for tc in tool_calls)
                        tc_text = f"\n[Action: invoking {names}]"
                    contents.append(
                        genai_types.Content(
                            role="model",
                            parts=[genai_types.Part.from_text(text=(msg.content or "") + tc_text)],
                        )
                    )
            elif isinstance(msg, ToolMessage):
                name = getattr(msg, "name", "tool_result")
                content = getattr(msg, "content", "")
                if last_ai_had_genai_content:
                    try:
                        res_data = json.loads(content)
                    except Exception:
                        res_data = {"output": content}
                    resp_part = genai_types.Part.from_function_response(
                        name=name,
                        response={"result": res_data},
                    )
                    contents.append(genai_types.Content(role="user", parts=[resp_part]))
                else:
                    contents.append(
                        genai_types.Content(
                            role="user",
                            parts=[genai_types.Part.from_text(text=f"Observation [{name}]:\n{content}")],
                        )
                    )

        return system_instruction, contents

    def _parse_response(self, response: Any) -> AIMessage:
        tool_calls: List[Dict[str, Any]] = []
        text_chunks: List[str] = []

        if getattr(response, "function_calls", None):
            for fc in response.function_calls:
                tool_calls.append(
                    {
                        "id": f"call_{fc.name}_{uuid4().hex[:6]}",
                        "name": fc.name,
                        "args": dict(fc.args) if getattr(fc, "args", None) else {},
                    }
                )

        if getattr(response, "candidates", None):
            for cand in response.candidates:
                if cand.content and cand.content.parts:
                    for part in cand.content.parts:
                        if getattr(part, "text", None):
                            text_chunks.append(part.text)
        elif hasattr(response, "text") and not tool_calls:
            try:
                if response.text:
                    text_chunks.append(response.text)
            except Exception:
                pass

        raw_content = response.candidates[0].content if getattr(response, "candidates", None) else None
        additional_kwargs: Dict[str, Any] = {"genai_content": raw_content} if raw_content is not None else {}

        return AIMessage(
            content="\n".join(text_chunks).strip(),
            tool_calls=tool_calls,
            additional_kwargs=additional_kwargs,
        )

    def invoke(self, messages: List[BaseMessage]) -> AIMessage:
        """Executes synchronous Gemini inference with graceful fallback on errors/quotas."""
        if not self.is_configured():
            logger.info("Gemini API not configured. Using RuleGuidedSOCAnalystLLM fallback.")
            return self.fallback_llm.invoke(messages)

        system_instruction, contents = self._format_conversation(messages)
        if not contents:
            return self.fallback_llm.invoke(messages)

        declarations = self._convert_tools_to_declarations()
        tools_config = [genai_types.Tool(function_declarations=declarations)] if declarations else None
        config = genai_types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=self.temperature,
            tools=tools_config,
        )

        try:
            response = self._client.models.generate_content(
                model=self.model,
                contents=contents,
                config=config,
            )
            ai_msg = self._parse_response(response)
            logger.info(
                "Gemini generated response (model=%s, tool_calls=%d, text_len=%d)",
                self.model,
                len(ai_msg.tool_calls),
                len(ai_msg.content),
            )
            return ai_msg
        except Exception as exc:
            err_str = str(exc)
            if ("503" in err_str or "UNAVAILABLE" in err_str) and self.model != "gemini-2.5-flash-lite":
                logger.warning(
                    "Gemini 503 spike on '%s'. Retrying once with 'gemini-2.5-flash-lite'...",
                    self.model,
                )
                try:
                    time.sleep(1.0)
                    retry_resp = self._client.models.generate_content(
                        model="gemini-2.5-flash-lite",
                        contents=contents,
                        config=config,
                    )
                    return self._parse_response(retry_resp)
                except Exception as retry_exc:
                    logger.warning("Retry with gemini-2.5-flash-lite failed: %s", retry_exc)

            logger.warning(
                "Gemini API request failed (%s: %s). Degrading seamlessly to RuleGuidedSOCAnalystLLM.",
                type(exc).__name__,
                exc,
            )
            return self.fallback_llm.invoke(messages)

