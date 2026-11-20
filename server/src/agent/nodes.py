"""
Synchronous LangGraph Node Implementations for the SOC Investigation Workflow.
Deconstructs graph execution into isolated, single-responsibility node functions.
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
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
    StructuredSynthesisResult,
    SystemMessage,
    ToolMessage,
)
from server.src.agent.triage import (
    TriageDecision,
    build_investigation_markdown_report,
    evaluate_forensic_evidence,
    is_ip_private_or_local,
)
from server.src.common.schemas import AgentVerdict, ArtifactType, Case
from server.src.repositories.base import IAlertRepository

logger = logging.getLogger("agentic_soc.agent.nodes")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append_trace_step(
    existing_steps: Optional[List[Dict[str, Any]]],
    *,
    node: str,
    title: str,
    summary: str,
    duration_ms: float,
    status: str = "completed",
    details: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    steps = list(existing_steps or [])
    steps.append(
        {
            "step": len(steps) + 1,
            "node": node,
            "title": title,
            "status": status,
            "timestamp": _utc_now_iso(),
            "duration_ms": round(max(0.0, duration_ms), 2),
            "summary": summary,
            "details": details or {},
        }
    )
    return steps


def _summarize_tool_output(func_name: Optional[str], result: Any) -> str:
    if isinstance(result, dict):
        if "error" in result:
            return f"Error: {result['error']}"
        if func_name == "check_ip_reputation":
            ip = result.get("ip", "?")
            score = result.get("reputation_score", "N/A")
            vendor = result.get("vendor") or result.get("reputation_vendor") or "ThreatIntel"
            return f"IP {ip} → Score {score}/100 ({vendor})"
        return f"Dict keys: {', '.join(list(result.keys())[:5])}"
    if isinstance(result, list):
        return f"Returned {len(result)} ECS record(s)"
    text = str(result)
    return text[:140] + ("..." if len(text) > 140 else "")


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
        t0 = time.perf_counter()
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

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        trace_steps = _append_trace_step(
            state.get("trace_steps"),
            node="load_case_context",
            title="Load Case & Alert Context",
            summary=(
                f"Case #{case_info.get('case_id')} ({case_info.get('level', 'medium').upper()}) · "
                f"Source IP: {case_info.get('source_ip') or 'N/A'} · "
                f"{len(case_info.get('alerts', []))} correlated alert(s)"
            ),
            duration_ms=elapsed_ms,
            details={
                "case_key": case_info.get("case_key"),
                "hostname": case_info.get("hostname"),
                "source_ip": case_info.get("source_ip"),
                "alert_rules": [a.get("rule_id") for a in case_info.get("alerts", [])],
            },
        )

        return {
            "case_data": case_info,
            "messages": messages,
            "evidence_logs": state.get("evidence_logs") or [],
            "artifacts": state.get("artifacts") or [],
            "iteration_count": 0,
            "trace_steps": trace_steps,
        }

    return load_case_context


def make_agent_reasoning_node(llm: Any, tools: Sequence[Any]) -> Callable:
    """Node 2: Runs synchronous LLM inference with bound tools."""
    bound_llm = llm.bind_tools(tools) if hasattr(llm, "bind_tools") else llm

    def agent_reasoning(state: InvestigationState) -> Dict[str, Any]:
        t0 = time.perf_counter()
        messages = state.get("messages", [])
        iter_count = state.get("iteration_count", 0) + 1
        step_status = "completed"

        try:
            if hasattr(bound_llm, "invoke"):
                ai_response = bound_llm.invoke(messages)
            else:
                ai_response = bound_llm(messages)
        except Exception as exc:
            logger.error("LLM reasoning invocation error: %s", exc)
            step_status = "error"
            ai_response = AIMessage(
                content=f"Error during LLM reasoning: {exc}. Proceeding to synthesis."
            )

        if not isinstance(ai_response, BaseMessage):
            content = getattr(ai_response, "content", str(ai_response))
            tool_calls = getattr(ai_response, "tool_calls", [])
            ai_response = AIMessage(content=content, tool_calls=tool_calls)

        tool_calls = getattr(ai_response, "tool_calls", None) or []
        if not tool_calls and hasattr(ai_response, "additional_kwargs"):
            tool_calls = ai_response.additional_kwargs.get("tool_calls", []) or []

        planned_tools = [
            {
                "name": tc.get("name") or (tc.get("function") or {}).get("name") or "unknown",
                "args": tc.get("args") or (tc.get("function") or {}).get("arguments") or {},
            }
            for tc in tool_calls
        ]
        content_preview = (getattr(ai_response, "content", "") or "").strip()
        if planned_tools:
            tool_names = ", ".join(t["name"] for t in planned_tools)
            summary = f"Iteration #{iter_count}: Planned {len(planned_tools)} tool call(s) → {tool_names}"
        else:
            summary = f"Iteration #{iter_count}: Reasoning complete, routing to Verdict Synthesis"

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        trace_steps = _append_trace_step(
            state.get("trace_steps"),
            node="agent_reasoning",
            title=f"AI Reasoning (Iteration {iter_count})",
            summary=summary,
            duration_ms=elapsed_ms,
            status=step_status,
            details={
                "iteration": iter_count,
                "llm_class": type(llm).__name__,
                "thought": content_preview[:600],
                "planned_tool_calls": planned_tools,
            },
        )

        return {
            "messages": [ai_response],
            "iteration_count": iter_count,
            "trace_steps": trace_steps,
        }

    return agent_reasoning


def make_tool_execution_node(tools: Sequence[Any]) -> Callable:
    """Node 3: Executes tool calls synchronously, wraps outputs against prompt injection, and collects IoCs."""
    tool_map = {getattr(tool, "name", str(tool)): tool for tool in tools}

    def tool_execution(state: InvestigationState) -> Dict[str, Any]:
        t0 = time.perf_counter()
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
        tool_traces: List[Dict[str, Any]] = []

        for tc in tool_calls:
            tc_t0 = time.perf_counter()
            call_id = tc.get("id", f"call_{len(tool_messages)}")
            func_name = tc.get("name") or tc.get("function", {}).get("name")
            args = tc.get("args") or tc.get("function", {}).get("arguments", {})

            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {"input": args}

            tool_instance = tool_map.get(func_name)
            tc_status = "completed"
            if not tool_instance:
                tc_status = "error"
                result: Any = {"error": f"Tool '{func_name}' not found"}
                res_str = json.dumps(result)
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
                    tc_status = "error"
                    result = {"error": str(exc)}
                    res_str = json.dumps(result)

            tool_traces.append(
                {
                    "tool": func_name or "unknown_tool",
                    "args": args,
                    "status": tc_status,
                    "duration_ms": round((time.perf_counter() - tc_t0) * 1000.0, 2),
                    "output_summary": _summarize_tool_output(func_name, result),
                }
            )

            tool_messages.append(
                ToolMessage(
                    content=wrap_untrusted_log(res_str),
                    tool_call_id=call_id,
                    name=func_name or "unknown_tool",
                )
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        executed_names = ", ".join(t["tool"] for t in tool_traces) or "none"
        trace_steps = _append_trace_step(
            state.get("trace_steps"),
            node="tool_execution",
            title=f"Execute {len(tool_traces)} Tool(s)",
            summary=f"Executed: {executed_names} · Collected {len(new_evidence_logs)} log(s), {len(new_artifacts)} IoC(s)",
            duration_ms=elapsed_ms,
            details={
                "tools": tool_traces,
                "total_evidence_logs": len(new_evidence_logs),
                "total_artifacts": len(new_artifacts),
            },
        )

        return {
            "messages": tool_messages,
            "artifacts": new_artifacts,
            "evidence_logs": new_evidence_logs,
            "trace_steps": trace_steps,
        }

    return tool_execution


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)


def _parse_structured_llm_output(content: str) -> Optional[StructuredSynthesisResult]:
    """
    Extracts and validates a StructuredSynthesisResult JSON block from the LLM's final message.
    Returns None if no valid structured JSON payload is present.
    """
    if not content or "verdict" not in content:
        return None

    candidates: List[str] = []
    for match in _JSON_FENCE_RE.finditer(content):
        candidates.append(match.group(1))

    if not candidates:
        start = content.rfind("{")
        end = content.rfind("}")
        if start != -1 and end > start:
            candidates.append(content[start : end + 1])

    for raw_json in reversed(candidates):
        try:
            data = json.loads(raw_json)
            if isinstance(data, dict) and "verdict" in data:
                return StructuredSynthesisResult.model_validate(data)
        except Exception:
            continue
    return None


def make_synthesize_verdict_node() -> Callable:
    """Node 4: Synthesizes final verdict, confidence, AI narrative, and Markdown executive report."""

    def synthesize_verdict(state: InvestigationState) -> Dict[str, Any]:
        t0 = time.perf_counter()
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

        baseline_decision = evaluate_forensic_evidence(
            alerts=alerts,
            artifacts=artifacts,
            evidence_logs=evidence_logs,
            case_source_ip=case_data.get("source_ip"),
        )

        max_rep_score = max(
            (float(art.get("reputation_score") or 0.0) for art in artifacts),
            default=0.0,
        )
        rule_ids = {str(a.get("rule_id") or "").lower() for a in alerts}
        strong_malicious_evidence = (
            "asp-bruteforce-then-success" in rule_ids
            or "asp-sudo-to-root-shell" in rule_ids
            or max_rep_score >= 80.0
        )

        structured = _parse_structured_llm_output(llm_analysis)
        verdict_source = "forensic_rules"
        guardrail_override = False

        if structured is not None:
            if (
                strong_malicious_evidence
                and baseline_decision.verdict == AgentVerdict.TRUE_POSITIVE
                and structured.verdict == AgentVerdict.FALSE_POSITIVE
            ):
                logger.warning(
                    "Guardrail override: LLM marked False Positive despite strong malicious evidence "
                    "(rules=%s, max_rep_score=%.1f).",
                    sorted(rule_ids),
                    max_rep_score,
                )
                triage_decision = baseline_decision
                verdict_source = "guardrail_override"
                guardrail_override = True
            else:
                triage_decision = TriageDecision(
                    verdict=structured.verdict,
                    confidence=float(structured.confidence),
                    executive_summary=(
                        structured.executive_summary.strip() or baseline_decision.executive_summary
                    ),
                    root_cause=structured.root_cause.strip() or baseline_decision.root_cause,
                    recommended_actions=(
                        list(structured.recommended_actions)
                        if structured.recommended_actions
                        else baseline_decision.recommended_actions
                    ),
                )
                verdict_source = "llm_structured"
        else:
            triage_decision = baseline_decision

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

        source_ip = case_data.get("source_ip")
        forensic_breakdown = {
            "verdict": triage_decision.verdict.value,
            "confidence": round(triage_decision.confidence, 4),
            "verdict_source": verdict_source,
            "guardrail_override": guardrail_override,
            "root_cause": triage_decision.root_cause,
            "executive_summary": triage_decision.executive_summary,
            "max_reputation_score": max_rep_score,
            "is_private_source_ip": is_ip_private_or_local(source_ip) if source_ip else None,
            "matched_rules": sorted({str(a.get("rule_id")) for a in alerts if a.get("rule_id")}),
            "observed_actions": sorted(
                {str((ev.get("event") or {}).get("action")) for ev in evidence_logs if (ev.get("event") or {}).get("action")}
            ),
            "alert_count": len(alerts),
            "evidence_count": evidence_count,
            "artifact_count": len(artifacts),
        }

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        trace_steps = _append_trace_step(
            state.get("trace_steps"),
            node="synthesize_verdict",
            title="Synthesize Forensic Verdict & Report",
            summary=(
                f"Verdict: {triage_decision.verdict.value} "
                f"({triage_decision.confidence * 100:.1f}% confidence) · "
                f"{evidence_count} evidence log(s)"
            ),
            duration_ms=elapsed_ms,
            details=forensic_breakdown,
        )

        return {
            "verdict": triage_decision.verdict.value,
            "confidence": triage_decision.confidence,
            "llm_analysis": llm_analysis,
            "summary_markdown": markdown_report,
            "recommended_actions": triage_decision.recommended_actions,
            "forensic_breakdown": forensic_breakdown,
            "trace_steps": trace_steps,
        }

    return synthesize_verdict

