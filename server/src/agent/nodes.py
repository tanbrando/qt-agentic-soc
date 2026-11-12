"""
Synchronous LangGraph Node Implementations for the SOC Investigation Workflow.
Deconstructs graph execution into isolated, single-responsibility node functions.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, List, Optional, Sequence

from server.src.agent.prompts import (
    SOC_ANALYST_SYSTEM_PROMPT,
    format_case_intro,
    wrap_untrusted_log,
)
from server.src.agent.state import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    InvestigationState,
    SystemMessage,
    ToolMessage,
)
from server.src.agent.triage import (
    build_investigation_markdown_report,
    evaluate_forensic_evidence,
)
from server.src.common.schemas import ArtifactType, Case
from server.src.repositories.base import IAlertRepository

logger = logging.getLogger("agentic_soc.agent.nodes")


def extract_artifact_from_tool_result(
    func_name: str,
    result: Any,
    existing_artifacts: List[Dict[str, Any]],
) -> None:
    """
    Inspects tool execution outputs and automatically registers discovered security observables (IoCs).
    """
    if func_name == "check_ip_reputation" and isinstance(result, dict):
        ip_val = result.get("ip")
        score = result.get("reputation_score")
        vendor = result.get("vendor") or result.get("reputation_vendor")
        if ip_val:
            existing_values = {a.get("value") for a in existing_artifacts}
            if ip_val not in existing_values:
                existing_artifacts.append(
                    {
                        "artifact_type": ArtifactType.IP.value,
                        "value": str(ip_val),
                        "reputation_score": float(score) if score is not None else 0.0,
                        "reputation_vendor": vendor,
                        "metadata": result.get("details", {}),
                    }
                )
    elif func_name == "get_user_activity_history" and isinstance(result, list):
        existing_values = {(a.get("artifact_type"), a.get("value")) for a in existing_artifacts}
        for item in result:
            if isinstance(item, dict):
                uname = (item.get("user") or {}).get("name")
                if uname and (ArtifactType.USER.value, uname) not in existing_values:
                    existing_artifacts.append(
                        {
                            "artifact_type": ArtifactType.USER.value,
                            "value": str(uname),
                            "reputation_score": None,
                            "reputation_vendor": "ECSTelemetry",
                            "metadata": {"source": "get_user_activity_history"},
                        }
                    )
                    existing_values.add((ArtifactType.USER.value, uname))


def make_load_case_context_node(alert_repo: Optional[IAlertRepository] = None) -> Callable:
    """Node 1: Normalizes Case details and initializes the prompt context."""

    def load_case_context(state: InvestigationState) -> Dict[str, Any]:
        case_obj: Optional[Case] = state.get("case_obj")
        case_id = state.get("case_id")

        if case_obj is None and alert_repo is not None and case_id is not None:
            try:
                case_obj = alert_repo.get_case(int(case_id))
            except Exception as exc:
                logger.error("Error retrieving case %s: %s", case_id, exc)

        if case_obj is None:
            case_info: Dict[str, Any] = {
                "case_id": case_id,
                "case_key": "unknown",
                "title": "Unknown Case",
                "level": "medium",
                "source_ip": None,
                "hostname": "unknown",
                "alerts": [],
            }
            intro_msg = f"Case {case_id} could not be retrieved."
        else:
            hostnames = sorted(
                {
                    str(a.group_key.get("host.name"))
                    for a in case_obj.alerts
                    if a.group_key.get("host.name")
                }
            )
            case_info = {
                "case_id": case_obj.id,
                "case_key": case_obj.case_key,
                "title": case_obj.title or f"Security Incident ({case_obj.case_key})",
                "level": case_obj.level.value,
                "status": case_obj.status.value,
                "source_ip": case_obj.source_ip,
                "hostname": ", ".join(hostnames) if hostnames else "unknown",
                "alert_count": len(case_obj.alerts),
                "alerts": [
                    {
                        "alert_id": a.id,
                        "rule_id": a.rule_id,
                        "title": a.title,
                        "level": a.level.value,
                        "group_key": a.group_key,
                        "event_count": a.event_count,
                        "event_uids": list(a.event_uids),
                    }
                    for a in case_obj.alerts
                ],
            }
            intro_msg = format_case_intro(case_info)

        messages = [
            SystemMessage(content=SOC_ANALYST_SYSTEM_PROMPT),
            HumanMessage(content=intro_msg),
        ]

        return {
            "case_data": case_info,
            "messages": messages,
            "evidence_logs": state.get("evidence_logs") or [],
            "artifacts": state.get("artifacts") or [],
            "iteration_count": 0,
        }

    return load_case_context


def make_agent_reasoning_node(llm: Any, tools: Sequence[Any]) -> Callable:
    """Node 2: Runs synchronous LLM inference with bound tools."""
    bound_llm = llm.bind_tools(tools) if hasattr(llm, "bind_tools") else llm

    def agent_reasoning(state: InvestigationState) -> Dict[str, Any]:
        messages = state.get("messages", [])
        iter_count = state.get("iteration_count", 0) + 1

        try:
            if hasattr(bound_llm, "invoke"):
                ai_response = bound_llm.invoke(messages)
            else:
                ai_response = bound_llm(messages)
        except Exception as exc:
            logger.error("LLM reasoning invocation error: %s", exc)
            ai_response = AIMessage(
                content=f"Error during LLM reasoning: {exc}. Proceeding to synthesis."
            )

        if not isinstance(ai_response, BaseMessage):
            content = getattr(ai_response, "content", str(ai_response))
            tool_calls = getattr(ai_response, "tool_calls", [])
            ai_response = AIMessage(content=content, tool_calls=tool_calls)

        return {
            "messages": [ai_response],
            "iteration_count": iter_count,
        }

    return agent_reasoning


def make_tool_execution_node(tools: Sequence[Any]) -> Callable:
    """Node 3: Executes tool calls synchronously, wraps outputs against prompt injection, and collects IoCs."""
    tool_map = {getattr(tool, "name", str(tool)): tool for tool in tools}

    def tool_execution(state: InvestigationState) -> Dict[str, Any]:
        messages = state.get("messages", [])
        if not messages:
            return {}

        last_message = messages[-1]
        tool_calls = getattr(last_message, "tool_calls", [])
        if not tool_calls and hasattr(last_message, "additional_kwargs"):
            tool_calls = last_message.additional_kwargs.get("tool_calls", [])

        tool_messages: List[BaseMessage] = []
        new_artifacts: List[Dict[str, Any]] = list(state.get("artifacts", []))
        new_evidence_logs: List[Dict[str, Any]] = list(state.get("evidence_logs", []))

        for tc in tool_calls:
            call_id = tc.get("id", f"call_{len(tool_messages)}")
            func_name = tc.get("name") or tc.get("function", {}).get("name")
            args = tc.get("args") or tc.get("function", {}).get("arguments", {})

            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {"input": args}

            tool_instance = tool_map.get(func_name)
            if not tool_instance:
                res_str = json.dumps({"error": f"Tool '{func_name}' not found"})
            else:
                try:
                    if hasattr(tool_instance, "invoke"):
                        result = tool_instance.invoke(args)
                    else:
                        result = tool_instance(**args)

                    extract_artifact_from_tool_result(func_name, result, new_artifacts)

                    if func_name in ("search_logs", "search_events_by_uids", "get_user_activity_history") and isinstance(result, list):
                        existing_uids = {(e.get("event") or {}).get("id") for e in new_evidence_logs}
                        for ev in result:
                            if isinstance(ev, dict):
                                uid = (ev.get("event") or {}).get("id")
                                if not uid or uid not in existing_uids:
                                    new_evidence_logs.append(ev)
                                    if uid:
                                        existing_uids.add(uid)

                    res_str = (
                        json.dumps(result, indent=2, default=str)
                        if isinstance(result, (dict, list))
                        else str(result)
                    )
                except Exception as exc:
                    logger.error("Error executing tool %s: %s", func_name, exc)
                    res_str = json.dumps({"error": str(exc)})

            tool_messages.append(
                ToolMessage(
                    content=wrap_untrusted_log(res_str),
                    tool_call_id=call_id,
                    name=func_name or "unknown_tool",
                )
            )

        return {
            "messages": tool_messages,
            "artifacts": new_artifacts,
            "evidence_logs": new_evidence_logs,
        }

    return tool_execution


def make_synthesize_verdict_node() -> Callable:
    """Node 4: Synthesizes final verdict, confidence, AI narrative, and Markdown executive report."""

    def synthesize_verdict(state: InvestigationState) -> Dict[str, Any]:
        case_data = state.get("case_data", {})
        artifacts = state.get("artifacts", [])
        evidence_logs = state.get("evidence_logs", [])
        alerts = case_data.get("alerts", [])
        messages = state.get("messages", [])

        # Extract final reasoning note from AI (excluding tool-invocation messages)
        llm_analysis = ""
        for msg in reversed(messages):
            if isinstance(msg, AIMessage) and not getattr(msg, "tool_calls", None):
                content = (getattr(msg, "content", "") or "").strip()
                if content and not content.startswith("Corroborating ECS telemetry"):
                    llm_analysis = content
                break

        triage_decision = evaluate_forensic_evidence(
            alerts=alerts,
            artifacts=artifacts,
            evidence_logs=evidence_logs,
            case_source_ip=case_data.get("source_ip"),
        )

        title = case_data.get("title", "Security Incident")
        case_id = case_data.get("case_id", "N/A")
        level = case_data.get("level", "medium")
        hostname = case_data.get("hostname", "unknown")
        evidence_count = len(evidence_logs) or sum(len(a.get("event_uids", [])) for a in alerts)

        markdown_report = build_investigation_markdown_report(
            case_id=case_id,
            title=title,
            level=level,
            hostname=hostname,
            triage=triage_decision,
            artifacts=artifacts,
            alert_count=len(alerts),
            evidence_count=evidence_count,
            llm_analysis=llm_analysis,
        )

        return {
            "verdict": triage_decision.verdict.value,
            "confidence": triage_decision.confidence,
            "llm_analysis": llm_analysis,
            "summary_markdown": markdown_report,
            "recommended_actions": triage_decision.recommended_actions,
        }

    return synthesize_verdict

