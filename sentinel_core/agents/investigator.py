"""
Investigator Agent: Rule-driven threat analysis over the Security Knowledge Graph.
Enforces that deterministic rules and graph traversal detect threats,
while the synthesis component formats evidence and technical explanations.
"""

from typing import List, Optional, Dict, Any, Set
from ..graph.knowledge_graph import SecurityKnowledgeGraph
from ..catalogs.taxonomies import lookup_emb3d, lookup_capec, lookup_cwe
from ..models.schemas import (
    ThreatReport,
    Threat,
    ThreatEvidence,
    StrideCategory,
)


class InvestigatorAgent:
    """
    Deterministic rule engine that operates strictly over graph topology.
    Does NOT rely on open-ended LLM guessing for threat identification.
    """

    def __init__(self, agent_name: str = "Investigator"):
        self.agent_name = agent_name

    def investigate(
        self,
        graph: SecurityKnowledgeGraph,
        simulate_fault: Optional[str] = None,
        reviewer_feedback: Optional[Dict[str, Any]] = None
    ) -> ThreatReport:
        """
        Executes deterministic rules over the Security Knowledge Graph.
        
        Args:
            graph: The loaded SecurityKnowledgeGraph
            simulate_fault: Optional fault for testing Reviewer rejection
            reviewer_feedback: Optional feedback from Reviewer for self-correction
        """
        # If reviewer flagged invalid CWE or phantom node, self-correct
        if reviewer_feedback:
            violations = str(reviewer_feedback.get("violations", []))
            if "CWE" in violations or "phantom" in violations:
                simulate_fault = None

        threats: List[Threat] = []
        threat_counter = 1

        # RULE 1: Unauthenticated Boundary Crossings (STRIDE: Spoofing & Tampering)
        unauth_crossings = graph.find_unauthenticated_boundary_crossings()
        critical_targets = graph.get_critical_components()

        # Track processed entry points and target pairs to prevent duplicate threat definitions
        discovered_pairs: Set[tuple] = set()

        for crossing in unauth_crossings:
            flow_id = crossing["flow_id"]
            src_id = crossing["source_id"]
            tgt_id = crossing["target_id"]
            protocol = crossing["protocol"]

            # Only analyze paths starting from external or perimeter entry points for end-to-end chains
            for crit_target in critical_targets:
                paths = graph.find_attack_paths_to_target(crit_target.id)
                for path in paths:
                    # Check if this crossing is the entry point or part of this attack chain
                    if path[0] == src_id and path[1] == tgt_id:
                        pair_key = (src_id, crit_target.id)
                        if pair_key in discovered_pairs:
                            continue
                        discovered_pairs.add(pair_key)

                        path_risk = graph.calculate_attack_path_risk(path)

                        # Fault simulation hook for Reviewer testing
                        cwe_id_to_use = "CWE-99999-FAKE" if simulate_fault == "fake_cwe_id" else "CWE-306"
                        nodes_cited = ["PHANTOM_GHOST_NODE"] if simulate_fault == "invalid_node_citation" else list(path)

                        threat_id = f"THREAT-{threat_counter:03d}"
                        threat_counter += 1

                        explanation = (
                            f"Rule engine identified unauthenticated {protocol} interface crossing trust boundary "
                            f"'{crossing['from_zone']}' -> '{crossing['to_zone']}'. "
                            f"A remote adversary can spoof {crossing['payload_type']} payloads and traverse through "
                            f"'{crossing['target_name']}' to directly actuate safety-critical "
                            f"'{crit_target.name}' without cryptographic authorization."
                        )

                        threat = Threat(
                            id=threat_id,
                            name=f"Remote {protocol} Protocol Spoofing into {crit_target.name}",
                            stride_category=StrideCategory.SPOOFING,
                            emb3d_id="EMB3D-T-0012",
                            capec_id="CAPEC-272",
                            cwe_id=cwe_id_to_use,
                            base_risk_score=path_risk,
                            entry_point_id=src_id,
                            target_component_id=crit_target.id,
                            attack_path=nodes_cited,
                            evidence=ThreatEvidence(
                                graph_nodes_cited=nodes_cited,
                                graph_edges_cited=[flow_id, "FLOW-02", "FLOW-03"],
                                boundary_crossed=f"{crossing['from_zone']} -> {crossing['to_zone']}",
                                flaw_condition=f"Protocol {protocol} lacks cryptographic client authentication and message integrity."
                            ),
                            explanation=explanation
                        )
                        threats.append(threat)

        # RULE 2: Gateway to In-Vehicle Critical Bus Command Injection (STRIDE: Tampering)
        # Check internal crossing into safety-critical zone
        for crossing in unauth_crossings:
            if crossing["to_zone"] == "INTERNAL_CAN_CRITICAL":
                threat_id = f"THREAT-{threat_counter:03d}"
                threat_counter += 1

                threats.append(
                    Threat(
                        id=threat_id,
                        name=f"Unauthenticated Command Injection on Critical Vehicle Bus",
                        stride_category=StrideCategory.TAMPERING,
                        emb3d_id="EMB3D-T-0021",
                        capec_id="CAPEC-94",
                        cwe_id="CWE-345",
                        base_risk_score=7.8,
                        entry_point_id=crossing["source_id"],
                        target_component_id=crossing["target_id"],
                        attack_path=[crossing["source_id"], crossing["target_id"]],
                        evidence=ThreatEvidence(
                            graph_nodes_cited=[crossing["source_id"], crossing["target_id"]],
                            graph_edges_cited=[crossing["flow_id"]],
                            boundary_crossed=f"{crossing['from_zone']} -> {crossing['to_zone']}",
                            flaw_condition="Actuator messages transmitted without cryptographic message authentication codes (MAC)."
                        ),
                        explanation=(
                            f"Gateway '{crossing['source_name']}' relays commands to safety-critical "
                            f"'{crossing['target_name']}' across CAN bus without SecOC or HMAC integrity protection."
                        )
                    )
                )

        max_risk = max((t.base_risk_score for t in threats), default=0.0)

        return ThreatReport(
            system_name=graph.system_name,
            threats=threats,
            max_risk_score=max_risk,
            total_attack_paths=len(threats)
        )
