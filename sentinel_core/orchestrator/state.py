"""
Shared State and Evidence Store for SENTINEL Orchestrator.
Maintains state machine transitions, graph checkpoints, retry counts, and human approvals.
"""

from typing import Dict, Any, List, Optional
from typing_extensions import TypedDict


class SentinelState(TypedDict):
    """
    Typed state representation managed by LangGraph.
    Passed deterministically across all nodes.
    """
    system_doc: str
    current_step: str
    retry_counts: Dict[str, int]
    max_retries: int
    system_model: Optional[Dict[str, Any]]
    knowledge_graph_data: Optional[Dict[str, Any]]
    threat_report: Optional[Dict[str, Any]]
    mitigation_plan: Optional[Dict[str, Any]]
    execution_report: Optional[Dict[str, Any]]
    latest_verdict: Optional[Dict[str, Any]]
    verdict_history: List[Dict[str, Any]]
    evidence_store: List[Dict[str, Any]]
    reviewer_feedback: Optional[Dict[str, Any]]
    human_approval_granted: bool
    escalated_to_human: bool
    escalation_reason: Optional[str]
    flow_logs: List[str]
    fault_injection_config: Dict[str, Any]
    final_report: Optional[Dict[str, Any]]
    completed: bool
