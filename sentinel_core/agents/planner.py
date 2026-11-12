"""
Planner Agent: Formulates prioritized mitigation strategies based on Investigator findings.
Maps threats to EMB3D/CAPEC mitigation catalog entries and computes expected risk reduction.
"""

from typing import List, Optional, Dict, Any
from ..models.schemas import ThreatReport, MitigationPlan, MitigationItem
from ..catalogs.taxonomies import lookup_mitigation


class PlannerAgent:
    """
    Synthesizes concrete mitigation configurations for the Sandbox Executor.
    Prioritizes actions by maximum risk reduction.
    """

    def __init__(self, agent_name: str = "Planner"):
        self.agent_name = agent_name

    def plan_mitigations(
        self,
        threat_report: ThreatReport,
        simulate_fault: Optional[str] = None,
        reviewer_feedback: Optional[Dict[str, Any]] = None
    ) -> MitigationPlan:
        """
        Generates actionable mitigation plan.
        
        Args:
            threat_report: Report produced by Investigator
            simulate_fault: Optional fault for Reviewer rejection testing
            reviewer_feedback: Optional feedback from Reviewer for self-correction
        """
        # If reviewer flagged invalid catalog ID or math, self-correct
        if reviewer_feedback:
            violations = str(reviewer_feedback.get("violations", []))
            if "catalog" in violations or "negative" in violations:
                simulate_fault = None

        items: List[MitigationItem] = []
        rank = 1

        for threat in threat_report.threats:
            # Map specific threats to the most effective catalog mitigation
            if threat.emb3d_id == "EMB3D-T-0012":
                cat_id = "EMB3D-M-9999-FAKE" if simulate_fault == "invalid_mitigation_id" else "EMB3D-M-0004"
                patch = {
                    "require_mtls": True,
                    "accepted_client_cn": "tcu.telematics.oem.internal",
                    "trusted_ca": "SENTINEL_ROOT_CA_2026"
                }
            elif threat.emb3d_id == "EMB3D-T-0021":
                cat_id = "EMB3D-M-0008"
                patch = {
                    "enforce_hmac": True,
                    "mac_algorithm": "AES-CMAC-128"
                }
            else:
                cat_id = "EMB3D-M-0012"
                patch = {"ingress_filtering": True}

            mitig_info = lookup_mitigation(cat_id) or {
                "name": "Mutual TLS (mTLS) with Hardware-Backed Keys",
                "description": "Enforce TLS 1.3 with client & server certificate verification.",
                "risk_reduction_factor": 0.62
            }

            reduction_factor = mitig_info.get("risk_reduction_factor", 0.62)
            projected_reduction = round(threat.base_risk_score * reduction_factor, 1)
            projected_final = round(threat.base_risk_score - projected_reduction, 1)

            if simulate_fault == "negative_risk_score":
                projected_final = -2.5

            items.append(
                MitigationItem(
                    id=f"MITIG-{rank:03d}",
                    threat_id=threat.id,
                    mitigation_catalog_id=cat_id,
                    name=mitig_info["name"],
                    description=mitig_info["description"],
                    target_component_id="COMP-GW",
                    configuration_patch=patch,
                    projected_risk_reduction=projected_reduction,
                    projected_final_risk=projected_final,
                    priority_rank=rank
                )
            )
            rank += 1

        initial_risk = threat_report.max_risk_score
        projected_system_risk = min((it.projected_final_risk for it in items), default=initial_risk)
        net_reduction = round(initial_risk - projected_system_risk, 1)

        return MitigationPlan(
            plan_id="PLAN-AUTO-01",
            items=items,
            initial_system_risk=initial_risk,
            projected_system_risk=projected_system_risk,
            net_risk_reduction=net_reduction
        )
