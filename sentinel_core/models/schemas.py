"""
Strict Pydantic schemas enforcing agent contracts for SENTINEL-AI.
Every agent consumes and produces validated typed models.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator


class TrustZone(str, Enum):
    EXTERNAL_UNTRUSTED = "EXTERNAL_UNTRUSTED"
    TELEMATICS_PERIMETER = "TELEMATICS_PERIMETER"
    VEHICLE_GATEWAY = "VEHICLE_GATEWAY"
    INTERNAL_CAN_CRITICAL = "INTERNAL_CAN_CRITICAL"


class ComponentType(str, Enum):
    CLOUD_ENDPOINT = "CLOUD_ENDPOINT"
    TELEMATICS_UNIT = "TELEMATICS_UNIT"
    GATEWAY_ECU = "GATEWAY_ECU"
    CRITICAL_CONTROLLER = "CRITICAL_CONTROLLER"
    SENSOR_NODE = "SENSOR_NODE"


class Component(BaseModel):
    id: str = Field(..., description="Unique alphanumeric identifier (e.g., COMP-TCU)")
    name: str = Field(..., description="Descriptive component name")
    type: ComponentType
    trust_zone: TrustZone
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence extraction score")
    is_safety_critical: bool = Field(default=False)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class Interface(BaseModel):
    id: str = Field(..., description="Unique interface ID (e.g., IF-MQTT-WAN)")
    protocol: str = Field(..., description="e.g. MQTT, CAN_2.0B, SOME/IP, UDS")
    is_authenticated: bool = Field(default=False)
    is_encrypted: bool = Field(default=False)
    port_or_bus: str = Field(..., description="Network port or CAN channel")


class DataFlow(BaseModel):
    id: str = Field(..., description="Flow identifier (e.g., FLOW-01)")
    source_component_id: str
    target_component_id: str
    interface_id: str
    protocol: str
    payload_type: str = Field(..., description="e.g., TelemetryPayload, BrakeOverrideCommand")
    crosses_trust_boundary: bool = Field(default=False)
    confidence_score: float = Field(..., ge=0.0, le=1.0)


class TrustBoundary(BaseModel):
    id: str
    name: str
    from_zone: TrustZone
    to_zone: TrustZone
    description: str


class SystemGraphModel(BaseModel):
    """Output contract of Analyzer Agent."""
    system_name: str
    version: str
    components: List[Component]
    interfaces: List[Interface]
    data_flows: List[DataFlow]
    trust_boundaries: List[TrustBoundary]
    overall_confidence: float = Field(..., ge=0.0, le=1.0)
    source_document: str

    def get_component_ids(self) -> List[str]:
        return [c.id for c in self.components]

    def get_flow_ids(self) -> List[str]:
        return [f.id for f in self.data_flows]


# ==============================================================================
# Threat & Investigation Schemas
# ==============================================================================

class StrideCategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class ThreatEvidence(BaseModel):
    graph_nodes_cited: List[str] = Field(..., description="Node IDs in the knowledge graph")
    graph_edges_cited: List[str] = Field(..., description="Data flow IDs in the graph")
    boundary_crossed: str
    flaw_condition: str


class Threat(BaseModel):
    id: str = Field(..., description="Unique threat identifier (e.g., THREAT-001)")
    name: str
    stride_category: StrideCategory
    emb3d_id: str = Field(..., description="Standardized MITRE EMB3D ID")
    capec_id: str = Field(..., description="Standardized MITRE CAPEC ID")
    cwe_id: str = Field(..., description="Standardized MITRE CWE ID")
    base_risk_score: float = Field(..., ge=0.0, le=10.0, description="CVSS 3.1 equivalent score")
    entry_point_id: str
    target_component_id: str
    attack_path: List[str] = Field(..., description="Ordered list of node IDs traversed by the attack")
    evidence: ThreatEvidence
    explanation: str = Field(..., description="Technical narrative explanation of attack chain")


class ThreatReport(BaseModel):
    """Output contract of Investigator Agent."""
    system_name: str
    threats: List[Threat]
    max_risk_score: float
    total_attack_paths: int


# ==============================================================================
# Mitigation & Planning Schemas
# ==============================================================================

class MitigationItem(BaseModel):
    id: str = Field(..., description="Mitigation ID (e.g., MITIG-001)")
    threat_id: str
    mitigation_catalog_id: str = Field(..., description="e.g. EMB3D-M-0004")
    name: str
    description: str
    target_component_id: str
    configuration_patch: Dict[str, Any] = Field(..., description="Sandbox patch keys to apply")
    projected_risk_reduction: float = Field(..., ge=0.0, le=10.0)
    projected_final_risk: float = Field(..., ge=0.0, le=10.0)
    priority_rank: int


class MitigationPlan(BaseModel):
    """Output contract of Planner Agent."""
    plan_id: str
    items: List[MitigationItem]
    initial_system_risk: float
    projected_system_risk: float
    net_risk_reduction: float


# ==============================================================================
# Execution & Verification Schemas
# ==============================================================================

class SandboxTestExecution(BaseModel):
    test_id: str
    phase: str  # "BASELINE_EXPLOIT" or "POST_MITIGATION_VERIFICATION"
    test_target: str
    command_injected: Dict[str, Any]
    attack_succeeded: bool
    response_code: int
    raw_response: str
    execution_time_ms: float


class ExecutionReport(BaseModel):
    """Output contract of Executor Agent."""
    plan_id: str
    sandbox_environment: str = "Emulated-QEMU/CAN-Harness"
    baseline_exploit_succeeded: bool = Field(..., description="True if initial attack breached sandbox")
    patch_applied: bool = Field(..., description="True if patch applied to emulated copy")
    verification_attack_blocked: bool = Field(..., description="True if post-patch attack was blocked")
    legitimate_traffic_preserved: bool = Field(default=True, description="True if authenticated traffic continues operating")
    original_risk_score: float
    verified_risk_score: float
    risk_delta: float
    attack_path_blocked: bool
    test_traces: List[SandboxTestExecution]
    execution_summary: str


# ==============================================================================
# Reviewer & Quality Gate Schemas
# ==============================================================================

class ReviewVerdict(BaseModel):
    """Output contract of Reviewer Agent."""
    agent_reviewed: str
    status: str = Field(..., description="PASS or REJECT")
    is_valid: bool
    rejection_reason: Optional[str] = None
    rule_violations: List[str] = Field(default_factory=list)
    hard_checks_performed: List[str] = Field(default_factory=list)
    timestamp: str
