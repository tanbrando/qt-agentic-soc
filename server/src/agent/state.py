"""
State definitions, schemas, and LangChain/LangGraph compatibility shims
for the synchronous SOC Investigation Workflow.
"""

from __future__ import annotations

from typing import Annotated, Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field
from typing_extensions import TypedDict

from server.src.common.schemas import AgentVerdict

# ============================================================================
# LangGraph Core Integrations & Fallback Shims
# ============================================================================

try:
    from langgraph.graph import END, START, StateGraph  # type: ignore
    from langgraph.graph.message import add_messages  # type: ignore
    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False
    StateGraph = None  # type: ignore
    START = "__start__"
    END = "__end__"

    def add_messages(existing: List[Any], new: Union[List[Any], Any]) -> List[Any]:
        """Simple message accumulator fallback."""
        if not isinstance(new, list):
            new = [new]
        return list(existing) + list(new)


# ============================================================================
# LangChain Message Types & Fallback Shims
# ============================================================================

try:
    from langchain_core.messages import (  # type: ignore
        AIMessage,
        BaseMessage,
        HumanMessage,
        SystemMessage,
        ToolMessage,
    )
    HAS_LANGCHAIN_MESSAGES = True
except ImportError:
    HAS_LANGCHAIN_MESSAGES = False

    class BaseMessage:  # type: ignore
        """Lightweight BaseMessage fallback."""

        def __init__(self, content: str, **kwargs: Any) -> None:
            self.content = content
            self.additional_kwargs = kwargs.get("additional_kwargs", {})
            self.tool_calls = kwargs.get("tool_calls", [])

        def __repr__(self) -> str:
            return f"{self.__class__.__name__}(content={self.content!r})"

    class SystemMessage(BaseMessage):
        pass

    class HumanMessage(BaseMessage):
        pass

    class AIMessage(BaseMessage):
        pass

    class ToolMessage(BaseMessage):
        def __init__(self, content: str, tool_call_id: str = "", name: str = "", **kwargs: Any) -> None:
            super().__init__(content, **kwargs)
            self.tool_call_id = tool_call_id
            self.name = name


# ============================================================================
# State Definitions
# ============================================================================

class InvestigationState(TypedDict, total=False):
    """Central state container tracked across all LangGraph nodes during investigation."""

    case_id: Optional[int]
    case_obj: Any
    case_data: Dict[str, Any]
    messages: Annotated[List[BaseMessage], add_messages]
    evidence_logs: List[Dict[str, Any]]
    artifacts: List[Dict[str, Any]]
    verdict: Optional[str]
    confidence: float
    llm_analysis: str
    summary_markdown: str
    recommended_actions: List[str]
    iteration_count: int


# ============================================================================
# Structured Synthesis Result Model
# ============================================================================

class StructuredSynthesisResult(BaseModel):
    """Normalized output schema expected from the synthesis phase."""

    verdict: AgentVerdict = Field(default=AgentVerdict.INCONCLUSIVE)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    executive_summary: str = Field(default="")
    root_cause: str = Field(default="")
    artifacts: List[Dict[str, Any]] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    report_markdown: str = Field(default="")
