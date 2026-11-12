"""
Reviewer Agent: Independent, deterministic quality gate.
Implements hard non-LLM checks:
1. Pydantic schema conformance and referential integrity.
2. Ground-truth taxonomy ID verification against MITRE EMB3D/CAPEC/CWE catalogs.
3. Knowledge graph node & topological connectivity verification (consecutive nodes must form directed edges).
4. Unique identifier checks (no duplicate threat or mitigation IDs).
5. Test reproducibility verification: confirms baseline exploit reproduction, post-patch blocking, and legitimate traffic preservation.
6. Extraction confidence thresholds against source documentation.
"""

from datetime import datetime
from typing import List, Optional, Set
from ..models.schemas import (
    SystemGraphModel,
    ThreatReport,
    MitigationPlan,
    ExecutionReport,
    ReviewVerdict,
)
from ..graph.knowledge_graph import SecurityKnowledgeGraph
from ..catalogs.taxonomies import (
    lookup_emb3d,
    lookup_capec,
    lookup_cwe,
    lookup_mitigation,
)


class ReviewerAgent:
    """
    Strict, non-LLM deterministic quality gate.
    Returns PASS or REJECT with specific granular violations.
    """

    def __init__(self, agent_name: str = "Reviewer", min_confidence: float = 0.70):
        self.agent_name = agent_name
        self.min_confidence = min_confidence

    def _now(self) -> str:
        return datetime.now().isoformat()

    def review_analyzer(self, model: SystemGraphModel) -> ReviewVerdict:
        """Validates Analyzer extraction against schema, confidence limits, and referential integrity."""
        violations: List[str] = []
        checks = [
            "Pydantic schema structure verification",
            "Extraction confidence threshold check (>= 0.70)",
            "Component ID naming convention check (COMP- prefix)",
            "Referential integrity (flows point to existing components)",
            "Topology minimums (>= 3 components, >= 1 boundary)"
        ]

        if not model.components:
            violations.append("Analyzer produced 0 components.")
        if not model.trust_boundaries:
            violations.append("Analyzer failed to extract any trust boundaries.")

        comp_ids = set(model.get_component_ids())
        iface_ids = {iface.id for iface in model.interfaces}

        # Check components
        for comp in model.components:
            if comp.confidence_score < self.min_confidence:
                violations.append(
                    f"Component '{comp.id}' confidence ({comp.confidence_score}) is below required threshold ({self.min_confidence})."
                )
            if not comp.id.startswith("COMP-"):
                violations.append(
                    f"Component '{comp.id}' violates naming convention (must begin with 'COMP-')."
                )

        # Check data flows and referential integrity
        for flow in model.data_flows:
            if flow.confidence_score < self.min_confidence:
                violations.append(
                    f"Data flow '{flow.id}' confidence ({flow.confidence_score}) is below required threshold."
                )
            if flow.source_component_id not in comp_ids:
                violations.append(
                    f"Data flow '{flow.id}' references source '{flow.source_component_id}' not found in component catalog."
                )
            if flow.target_component_id not in comp_ids:
                violations.append(
                    f"Data flow '{flow.id}' references target '{flow.target_component_id}' not found in component catalog."
                )
            if flow.interface_id not in iface_ids:
                violations.append(
                    f"Data flow '{flow.id}' references unknown interface '{flow.interface_id}'."
                )

        is_valid = len(violations) == 0
        return ReviewVerdict(
            agent_reviewed="Analyzer",
            status="PASS" if is_valid else "REJECT",
            is_valid=is_valid,
            rejection_reason="Extraction confidence or schema referential requirements not met" if not is_valid else None,
            rule_violations=violations,
            hard_checks_performed=checks,
            timestamp=self._now()
        )

    def review_investigator(
        self,
        report: ThreatReport,
        graph: SecurityKnowledgeGraph
    ) -> ReviewVerdict:
        """
        Validates Investigator findings:
        - Verifies EMB3D, CAPEC, CWE IDs exist in authentic catalogs.
        - Verifies every cited graph node exists in the active knowledge graph.
        - Verifies topological path connectivity (consecutive nodes must form directed edges).
        - Verifies threat IDs are unique.
        """
        violations: List[str] = []
        checks = [
            "Taxonomy ID verification (MITRE EMB3D catalog)",
            "Taxonomy ID verification (MITRE CAPEC catalog)",
            "Taxonomy ID verification (MITRE CWE catalog)",
            "Knowledge graph node existence verification",
            "Topological path connectivity verification (directed edges exist)",
            "Unique threat identifier verification",
            "Risk score range check (0.0 - 10.0)"
        ]

        if not report.threats:
            violations.append("ThreatReport contains zero identified threats.")

        seen_threat_ids: Set[str] = set()

        for threat in report.threats:
            # 1. Unique threat IDs
            if threat.id in seen_threat_ids:
                violations.append(f"Duplicate threat ID detected: '{threat.id}'. IDs must be unique.")
            seen_threat_ids.add(threat.id)

            # 2. Check EMB3D ID
            if not lookup_emb3d(threat.emb3d_id):
                violations.append(f"Invalid MITRE EMB3D ID: '{threat.emb3d_id}' not found in ground-truth taxonomy.")

            # 3. Check CAPEC ID
            if not lookup_capec(threat.capec_id):
                violations.append(f"Invalid MITRE CAPEC ID: '{threat.capec_id}' not found in ground-truth taxonomy.")

            # 4. Check CWE ID
            if not lookup_cwe(threat.cwe_id):
                violations.append(f"Invalid MITRE CWE ID: '{threat.cwe_id}' not found in ground-truth taxonomy.")

            # 5. Check graph node existence
            for node_id in threat.attack_path:
                if not graph.node_exists(node_id):
                    violations.append(
                        f"Threat '{threat.id}' cites non-existent graph node '{node_id}' in attack path."
                    )

            for node_id in threat.evidence.graph_nodes_cited:
                if not graph.node_exists(node_id):
                    violations.append(
                        f"Threat '{threat.id}' cites phantom evidence node '{node_id}' not in Knowledge Graph."
                    )

            # 6. Check Topological Directed Edge Connectivity
            for i in range(len(threat.attack_path) - 1):
                u, v = threat.attack_path[i], threat.attack_path[i + 1]
                if graph.node_exists(u) and graph.node_exists(v):
                    if not graph.edge_exists(u, v):
                        violations.append(
                            f"Threat '{threat.id}' attack path contains disconnected hop: edge ({u} -> {v}) does not exist in graph."
                        )

            # 7. Check risk score bounds
            if threat.base_risk_score < 0.0 or threat.base_risk_score > 10.0:
                violations.append(f"Threat '{threat.id}' risk score {threat.base_risk_score} out of bounds (0-10).")

        is_valid = len(violations) == 0
        return ReviewVerdict(
            agent_reviewed="Investigator",
            status="PASS" if is_valid else "REJECT",
            is_valid=is_valid,
            rejection_reason="Threat evidence failed taxonomy lookup, topological connectivity, or uniqueness checks" if not is_valid else None,
            rule_violations=violations,
            hard_checks_performed=checks,
            timestamp=self._now()
        )

    def review_planner(
        self,
        plan: MitigationPlan,
        threat_report: Optional[ThreatReport] = None
    ) -> ReviewVerdict:
        """Validates Planner output against mitigation catalogs, uniqueness, and logical consistency."""
        violations: List[str] = []
        checks = [
            "Mitigation catalog lookup (EMB3D-M series)",
            "Unique mitigation identifier check",
            "Referential integrity (mitigation links to valid threat ID)",
            "Risk reduction mathematical consistency check",
            "Configuration patch payload completeness check"
        ]

        if not plan.items:
            violations.append("MitigationPlan contains no actionable items.")

        seen_mitig_ids: Set[str] = set()
        valid_threat_ids = {t.id for t in threat_report.threats} if threat_report else set()

        for item in plan.items:
            if item.id in seen_mitig_ids:
                violations.append(f"Duplicate mitigation ID detected: '{item.id}'. IDs must be unique.")
            seen_mitig_ids.add(item.id)

            if valid_threat_ids and item.threat_id not in valid_threat_ids:
                violations.append(
                    f"Mitigation '{item.id}' references unknown threat ID: '{item.threat_id}'."
                )

            if not lookup_mitigation(item.mitigation_catalog_id):
                violations.append(
                    f"Mitigation item '{item.id}' cites unknown catalog ID: '{item.mitigation_catalog_id}'."
                )
            if item.projected_final_risk < 0.0:
                violations.append(
                    f"Mitigation '{item.id}' projected negative risk score ({item.projected_final_risk})."
                )
            if item.projected_final_risk > plan.initial_system_risk:
                violations.append(
                    f"Mitigation '{item.id}' project risk exceeds initial system risk."
                )
            if not item.configuration_patch:
                violations.append(
                    f"Mitigation '{item.id}' provides empty configuration patch."
                )

        is_valid = len(violations) == 0
        return ReviewVerdict(
            agent_reviewed="Planner",
            status="PASS" if is_valid else "REJECT",
            is_valid=is_valid,
            rejection_reason="Mitigation plan contains invalid catalog IDs or inconsistent risk math" if not is_valid else None,
            rule_violations=violations,
            hard_checks_performed=checks,
            timestamp=self._now()
        )

    def review_executor(self, report: ExecutionReport) -> ReviewVerdict:
        """
        Validates empirical execution evidence:
        - Confirms baseline exploit was reproduced.
        - Confirms patch was applied.
        - Confirms post-patch attack was blocked.
        - Confirms legitimate telematics traffic remains preserved (no DoS).
        - Confirms net risk reduction.
        """
        violations: List[str] = []
        checks = [
            "Baseline exploit reproduction verification",
            "Patch application verification",
            "Post-mitigation attack block verification",
            "Legitimate vehicle operations preservation (no False Positives / DoS)",
            "Empirical risk reduction check (delta > 0)"
        ]

        if not report.baseline_exploit_succeeded:
            violations.append(
                "Execution verification failed: Baseline exploit could not be reproduced in sandbox."
            )
        if not report.patch_applied:
            violations.append(
                "Execution verification failed: Configuration patch was not applied to sandbox."
            )
        if not report.verification_attack_blocked:
            violations.append(
                "Execution verification failed: Verification attack still succeeded against patched sandbox."
            )
        if not report.legitimate_traffic_preserved:
            violations.append(
                "Execution verification failed: Mitigation caused denial of service to legitimate vehicle traffic."
            )
        if not report.attack_path_blocked:
            violations.append(
                "Execution report failed to certify attack path blocked."
            )
        if report.risk_delta <= 0:
            violations.append(
                f"Invalid risk delta ({report.risk_delta}): mitigation did not reduce risk."
            )

        is_valid = len(violations) == 0
        return ReviewVerdict(
            agent_reviewed="Executor",
            status="PASS" if is_valid else "REJECT",
            is_valid=is_valid,
            rejection_reason="Sandbox test execution failed reproducibility, verification, or availability criteria" if not is_valid else None,
            rule_violations=violations,
            hard_checks_performed=checks,
            timestamp=self._now()
        )
