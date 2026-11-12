"""
Synchronous Agentic Investigation Workflow & LangGraph State Machine.
Assembles the SOC incident triage state machine and provides LangGraphAgentInvestigator
and factory helpers fully aligned with the synchronous ECS v1.1 SIEM Core.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Sequence

from server.src.agent.base import (
    AbuseIPDBThreatIntelProvider,
    IAgentInvestigator,
    IThreatIntelProvider,
    MockThreatIntelProvider,
)
from server.src.agent.gemini_llm import GeminiSOCAnalystLLM, RuleGuidedSOCAnalystLLM
from server.src.agent.nodes import (
    make_agent_reasoning_node,
    make_load_case_context_node,
    make_synthesize_verdict_node,
    make_tool_execution_node,
)
from server.src.agent.state import (
    END,
    HAS_LANGGRAPH,
    START,
    InvestigationState,
    StateGraph,
    add_messages,
)
from server.src.agent.tools import (
    create_check_ip_reputation_tool,
    create_get_user_activity_tool,
    create_search_events_by_uids_tool,
    create_search_logs_tool,
)
from server.src.common.schemas import (
    AgentReportUpdate,
    AgentVerdict,
    Artifact,
    ArtifactType,
    Case,
)
from server.src.repositories.base import IAlertRepository, ILogRepository

logger = logging.getLogger("agentic_soc.agent.workflow")

_PLACEHOLDER_PREFIXES = ("your_", "CHANGE_ME")


def should_continue_reasoning(state: InvestigationState) -> str:
    """Conditional edge routing between tool execution and final verdict synthesis."""
    messages = state.get("messages", [])
    iter_count = state.get("iteration_count", 0)

    # Cost and safety ceiling against infinite tool loops
    if iter_count >= 5:
        logger.warning("Agent reached maximum reasoning iterations (%d); synthesizing.", iter_count)
        return "synthesize"

    if not messages:
        return "synthesize"

    last_msg = messages[-1]
    tool_calls = getattr(last_msg, "tool_calls", None)
    if not tool_calls and hasattr(last_msg, "additional_kwargs"):
        tool_calls = last_msg.additional_kwargs.get("tool_calls")

    if tool_calls and len(tool_calls) > 0:
        return "tools"

    return "synthesize"


class FallbackInvestigationGraph:
    """
    Synchronous fallback graph executor mirroring LangGraph StateGraph semantics
    when `langgraph` is not installed in the Python environment.
    """

    def __init__(
        self,
        load_node: Any,
        reasoning_node: Any,
        tool_node: Any,
        synthesize_node: Any,
    ) -> None:
        self.load_node = load_node
        self.reasoning_node = reasoning_node
        self.tool_node = tool_node
        self.synthesize_node = synthesize_node

    def _merge_state(self, state: Dict[str, Any], update: Dict[str, Any]) -> None:
        for k, v in update.items():
            if k == "messages":
                state["messages"] = add_messages(state.get("messages", []), v)
            else:
                state[k] = v

    def invoke(self, initial_state: Dict[str, Any]) -> Dict[str, Any]:
        state = dict(initial_state)
        self._merge_state(state, self.load_node(state))

        while True:
            self._merge_state(state, self.reasoning_node(state))
            branch = should_continue_reasoning(state)  # type: ignore[arg-type]
            if branch == "tools":
                self._merge_state(state, self.tool_node(state))
            else:
                break

        self._merge_state(state, self.synthesize_node(state))
        return state


def build_investigation_graph(
    llm: Any,
    tools: Sequence[Any],
    alert_repo: Optional[IAlertRepository] = None,
) -> Any:
    """Builds and compiles the synchronous SOC triage StateGraph."""
    load_node = make_load_case_context_node(alert_repo)
    reasoning_node = make_agent_reasoning_node(llm, tools)
    tool_node = make_tool_execution_node(tools)
    synthesize_node = make_synthesize_verdict_node()

    if HAS_LANGGRAPH:
        workflow = StateGraph(InvestigationState)
        workflow.add_node("load_case_context", load_node)
        workflow.add_node("agent_reasoning", reasoning_node)
        workflow.add_node("tool_execution", tool_node)
        workflow.add_node("synthesize_verdict", synthesize_node)

        workflow.add_edge(START, "load_case_context")
        workflow.add_edge("load_case_context", "agent_reasoning")
        workflow.add_conditional_edges(
            "agent_reasoning",
            should_continue_reasoning,
            {
                "tools": "tool_execution",
                "synthesize": "synthesize_verdict",
            },
        )
        workflow.add_edge("tool_execution", "agent_reasoning")
        workflow.add_edge("synthesize_verdict", END)

        return workflow.compile()

    logger.debug("`langgraph` package not installed; using FallbackInvestigationGraph.")
    return FallbackInvestigationGraph(
        load_node=load_node,
        reasoning_node=reasoning_node,
        tool_node=tool_node,
        synthesize_node=synthesize_node,
    )


class LangGraphAgentInvestigator(IAgentInvestigator):
    """
    Autonomous SOC Investigator powered by LangGraph StateGraph + Gemini/Rule-Guided LLM
    + Threat Intelligence tools (Synchronous).
    """

    def __init__(
        self,
        log_repository: ILogRepository,
        threat_intel: Optional[IThreatIntelProvider] = None,
        llm: Optional[Any] = None,
        alert_repository: Optional[IAlertRepository] = None,
    ) -> None:
        self.log_repo = log_repository
        self.alert_repo = alert_repository
        self.threat_intel = threat_intel or MockThreatIntelProvider()

        self.tools = [
            create_search_logs_tool(self.log_repo),
            create_check_ip_reputation_tool(self.threat_intel),
            create_get_user_activity_tool(self.log_repo),
            create_search_events_by_uids_tool(self.log_repo),
        ]

        self.llm = llm if llm is not None else RuleGuidedSOCAnalystLLM(self.tools)
        self.graph = build_investigation_graph(
            llm=self.llm,
            tools=self.tools,
            alert_repo=self.alert_repo,
        )

    def investigate_case(self, case: Case) -> AgentReportUpdate:
        """Executes the investigation workflow synchronously and returns AgentReportUpdate."""
        initial_state: Dict[str, Any] = {
            "case_id": case.id,
            "case_obj": case,
            "messages": [],
            "evidence_logs": [],
            "artifacts": [],
            "iteration_count": 0,
        }

        final_state = self.graph.invoke(initial_state)

        verdict_val = final_state.get("verdict") or AgentVerdict.INCONCLUSIVE.value
        confidence = float(final_state.get("confidence", 0.5))
        markdown = final_state.get("summary_markdown") or "# Investigation Complete\nNo summary generated."
        artifacts_raw = final_state.get("artifacts", [])

        artifacts_objs = [
            Artifact(
                artifact_type=ArtifactType(art.get("artifact_type", ArtifactType.IP.value)),
                value=str(art["value"]),
                reputation_score=art.get("reputation_score"),
                reputation_vendor=art.get("reputation_vendor"),
                metadata=art.get("metadata", {}),
            )
            for art in artifacts_raw
            if art.get("value")
        ]

        return AgentReportUpdate(
            agent_verdict=AgentVerdict(verdict_val),
            agent_confidence=confidence,
            agent_report_markdown=markdown,
            extracted_artifacts=artifacts_objs,
        )


class DefaultAgentInvestigator(LangGraphAgentInvestigator):
    """
    Deterministic default investigator alias using RuleGuidedSOCAnalystLLM
    (preserves full backward compatibility with Phase 1–5 callers & tests).
    """

    def __init__(
        self,
        log_repository: ILogRepository,
        threat_intel: Optional[IThreatIntelProvider] = None,
    ) -> None:
        super().__init__(
            log_repository=log_repository,
            threat_intel=threat_intel or MockThreatIntelProvider(),
            llm=None,
        )


def _is_real_key(val: Optional[str]) -> bool:
    if not val:
        return False
    cleaned = val.strip()
    return bool(cleaned) and not cleaned.startswith(_PLACEHOLDER_PREFIXES)


def create_investigator(
    log_repository: ILogRepository,
    alert_repository: Optional[IAlertRepository] = None,
    threat_intel: Optional[IThreatIntelProvider] = None,
    gemini_api_key: Optional[str] = None,
    abuseipdb_api_key: Optional[str] = None,
    model_name: str = "gemini-2.5-flash-lite",
    use_mock_threat_intel: bool = False,
    use_mock_llm: bool = False,
) -> LangGraphAgentInvestigator:
    """
    Factory creating a fully wired LangGraphAgentInvestigator.
    Reads API keys from arguments or environment variables (`.env`), degrading gracefully
    to offline mock providers when keys are absent, placeholders, or inside automated pytest runs.
    """
    in_pytest = bool(os.getenv("PYTEST_CURRENT_TEST"))
    if not in_pytest:
        try:
            import dotenv

            dotenv.load_dotenv()
        except ImportError:
            pass

    if threat_intel is None:
        abuse_key = abuseipdb_api_key if abuseipdb_api_key is not None else (
            None if in_pytest else os.getenv("ABUSEIPDB_API_KEY")
        )
        if not use_mock_threat_intel and _is_real_key(abuse_key):
            threat_intel = AbuseIPDBThreatIntelProvider(api_key=abuse_key)
        else:
            threat_intel = MockThreatIntelProvider()

    llm: Optional[Any] = None
    if not use_mock_llm:
        gem_key = gemini_api_key if gemini_api_key is not None else (
            None if in_pytest else os.getenv("GEMINI_API_KEY")
        )
        if _is_real_key(gem_key):
            llm = GeminiSOCAnalystLLM(api_key=gem_key, model=model_name)

    return LangGraphAgentInvestigator(
        log_repository=log_repository,
        alert_repository=alert_repository,
        threat_intel=threat_intel,
        llm=llm,
    )
