"""
Agentic Investigation Subsystem Package (Synchronous, ECS v1.1 Aligned).
"""

from server.src.agent.base import (
    AbuseIPDBThreatIntelProvider,
    IAgentInvestigator,
    IThreatIntelProvider,
    MockThreatIntelProvider,
)
from server.src.agent.gemini_llm import GeminiSOCAnalystLLM, RuleGuidedSOCAnalystLLM
from server.src.agent.nodes import (
    extract_artifact_from_tool_result,
    make_agent_reasoning_node,
    make_load_case_context_node,
    make_synthesize_verdict_node,
    make_tool_execution_node,
)
from server.src.agent.prompts import (
    SOC_ANALYST_SYSTEM_PROMPT,
    format_case_intro,
    wrap_untrusted_log,
)
from server.src.agent.state import (
    END,
    START,
    AIMessage,
    BaseMessage,
    HumanMessage,
    InvestigationState,
    StructuredSynthesisResult,
    SystemMessage,
    ToolMessage,
    add_messages,
)
from server.src.agent.tools import (
    CheckIPReputationArgs,
    GetUserActivityArgs,
    SearchEventsByUidsArgs,
    SearchLogsArgs,
    SecurityAgentTools,
    create_check_ip_reputation_tool,
    create_get_user_activity_tool,
    create_search_events_by_uids_tool,
    create_search_logs_tool,
)
from server.src.agent.triage import (
    TriageDecision,
    build_investigation_markdown_report,
    evaluate_forensic_evidence,
    is_ip_private_or_local,
)
from server.src.agent.workflow import (
    DefaultAgentInvestigator,
    FallbackInvestigationGraph,
    LangGraphAgentInvestigator,
    build_investigation_graph,
    create_investigator,
    should_continue_reasoning,
)

__all__ = [
    "IThreatIntelProvider",
    "MockThreatIntelProvider",
    "AbuseIPDBThreatIntelProvider",
    "IAgentInvestigator",
    "SOC_ANALYST_SYSTEM_PROMPT",
    "wrap_untrusted_log",
    "format_case_intro",
    "InvestigationState",
    "StructuredSynthesisResult",
    "BaseMessage",
    "SystemMessage",
    "HumanMessage",
    "AIMessage",
    "ToolMessage",
    "add_messages",
    "START",
    "END",
    "TriageDecision",
    "evaluate_forensic_evidence",
    "build_investigation_markdown_report",
    "is_ip_private_or_local",
    "make_load_case_context_node",
    "make_agent_reasoning_node",
    "make_tool_execution_node",
    "make_synthesize_verdict_node",
    "extract_artifact_from_tool_result",
    "SearchLogsArgs",
    "CheckIPReputationArgs",
    "GetUserActivityArgs",
    "SearchEventsByUidsArgs",
    "create_search_logs_tool",
    "create_check_ip_reputation_tool",
    "create_get_user_activity_tool",
    "create_search_events_by_uids_tool",
    "SecurityAgentTools",
    "should_continue_reasoning",
    "build_investigation_graph",
    "FallbackInvestigationGraph",
    "DefaultAgentInvestigator",
    "LangGraphAgentInvestigator",
    "RuleGuidedSOCAnalystLLM",
    "GeminiSOCAnalystLLM",
    "create_investigator",
]
