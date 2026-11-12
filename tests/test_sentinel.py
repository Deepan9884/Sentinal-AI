"""
Automated Test Suite for SENTINEL-AI Prototype.
Tests:
- End-to-end pipeline execution
- Hard non-LLM Reviewer checks (schemas, taxonomy catalogs, graph node references)
- Rejection feedback loops and self-correction
- Retry cap escalation to human engineer
- Sandbox test reproduction and post-mitigation attack blocking
"""

import sys
import os
import unittest

# Ensure prototype root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_core.orchestrator import SentinelOrchestrator
from sentinel_core.agents import (
    AnalyzerAgent,
    InvestigatorAgent,
    PlannerAgent,
    ExecutorAgent,
    ReviewerAgent,
)
from sentinel_core.graph import SecurityKnowledgeGraph
from sentinel_core.harness import EmulatedSubsystem
from sentinel_core.catalogs import lookup_emb3d, lookup_capec, lookup_cwe
from sentinel_core.report import generate_html_report


class TestTaxonomyCatalogs(unittest.TestCase):
    """Verifies MITRE EMB3D, CAPEC, and CWE catalogs."""

    def test_authentic_ids_exist(self):
        self.assertIsNotNone(lookup_emb3d("EMB3D-T-0012"))
        self.assertIsNotNone(lookup_capec("CAPEC-272"))
        self.assertIsNotNone(lookup_cwe("CWE-306"))

    def test_fake_id_rejected(self):
        self.assertIsNone(lookup_cwe("CWE-99999-FAKE"))
        self.assertIsNone(lookup_emb3d("EMB3D-T-9999"))


class TestSecurityKnowledgeGraph(unittest.TestCase):
    """Verifies NetworkX-based graph rules and path risk computation."""

    def setUp(self):
        self.analyzer = AnalyzerAgent()
        self.model = self.analyzer.analyze_system("Sample spec")
        self.graph = SecurityKnowledgeGraph()
        self.graph.load_system_model(self.model)

    def test_unauthenticated_boundary_detection(self):
        crossings = self.graph.find_unauthenticated_boundary_crossings()
        self.assertGreaterEqual(len(crossings), 1)
        self.assertEqual(crossings[0]["protocol"], "MQTT")

    def test_attack_path_to_brake_controller(self):
        paths = self.graph.find_attack_paths_to_target("COMP-BRAKE-CTRL")
        self.assertGreaterEqual(len(paths), 1)
        self.assertIn("COMP-BRAKE-CTRL", paths[0])

    def test_path_risk_score(self):
        paths = self.graph.find_attack_paths_to_target("COMP-BRAKE-CTRL")
        risk = self.graph.calculate_attack_path_risk(paths[0])
        self.assertEqual(risk, 8.2)


class TestReviewerHardChecks(unittest.TestCase):
    """Verifies Reviewer deterministically rejects violations."""

    def setUp(self):
        self.analyzer = AnalyzerAgent()
        self.investigator = InvestigatorAgent()
        self.reviewer = ReviewerAgent()
        self.graph = SecurityKnowledgeGraph()
        self.model = self.analyzer.analyze_system("Spec")
        self.graph.load_system_model(self.model)

    def test_reviewer_catches_fake_cwe(self):
        faulty_report = self.investigator.investigate(self.graph, simulate_fault="fake_cwe_id")
        verdict = self.reviewer.review_investigator(faulty_report, self.graph)
        self.assertFalse(verdict.is_valid)
        self.assertEqual(verdict.status, "REJECT")
        self.assertTrue(any("Invalid MITRE CWE ID" in v for v in verdict.rule_violations))

    def test_reviewer_catches_phantom_node(self):
        faulty_report = self.investigator.investigate(self.graph, simulate_fault="invalid_node_citation")
        verdict = self.reviewer.review_investigator(faulty_report, self.graph)
        self.assertFalse(verdict.is_valid)
        self.assertEqual(verdict.status, "REJECT")
        self.assertTrue(any("phantom evidence node" in v for v in verdict.rule_violations))

    def test_reviewer_catches_low_confidence_extraction(self):
        low_conf_model = self.analyzer.analyze_system("Spec", simulate_fault="low_confidence")
        verdict = self.reviewer.review_analyzer(low_conf_model)
        self.assertFalse(verdict.is_valid)
        self.assertEqual(verdict.status, "REJECT")

    def test_reviewer_catches_disconnected_attack_path(self):
        report = self.investigator.investigate(self.graph)
        # Create a disconnected jump: COMP-CLOUD directly to COMP-BRAKE-CTRL without intermediate hops
        report.threats[0].attack_path = ["COMP-CLOUD", "COMP-BRAKE-CTRL"]
        verdict = self.reviewer.review_investigator(report, self.graph)
        self.assertFalse(verdict.is_valid)
        self.assertEqual(verdict.status, "REJECT")
        self.assertTrue(any("disconnected hop" in v for v in verdict.rule_violations))

    def test_reviewer_catches_unregistered_flow_component(self):
        model = self.analyzer.analyze_system("Spec")
        # Tamper flow to reference an unknown component
        model.data_flows[0].source_component_id = "COMP-UNKNOWN-GHOST"
        verdict = self.reviewer.review_analyzer(model)
        self.assertFalse(verdict.is_valid)
        self.assertTrue(any("not found in component catalog" in v for v in verdict.rule_violations))


class TestExecutorSandbox(unittest.TestCase):
    """Verifies baseline exploit reproduction and post-mitigation attack blocking."""

    def setUp(self):
        self.sandbox = EmulatedSubsystem()
        self.planner = PlannerAgent()
        self.investigator = InvestigatorAgent()
        self.analyzer = AnalyzerAgent()
        self.graph = SecurityKnowledgeGraph()
        model = self.analyzer.analyze_system("Spec")
        self.graph.load_system_model(model)
        report = self.investigator.investigate(self.graph)
        self.plan = self.planner.plan_mitigations(report)
        self.executor = ExecutorAgent()

    def test_executor_before_and_after(self):
        exec_report = self.executor.execute_and_verify(self.plan, sandbox=self.sandbox)
        self.assertTrue(exec_report.baseline_exploit_succeeded)
        self.assertTrue(exec_report.patch_applied)
        self.assertTrue(exec_report.verification_attack_blocked)
        self.assertTrue(exec_report.legitimate_traffic_preserved)
        self.assertTrue(exec_report.attack_path_blocked)
        self.assertEqual(exec_report.original_risk_score, 8.2)
        self.assertEqual(exec_report.verified_risk_score, 3.1)
        self.assertEqual(exec_report.risk_delta, 5.1)

    def test_legitimate_traffic_preservation(self):
        # Even after patch, legitimate authorized telematics must succeed
        self.sandbox.apply_patch({"require_mtls": True, "accepted_client_cn": "tcu.telematics.oem.internal"})
        legit_test = self.sandbox.run_legitimate_test()
        self.assertEqual(legit_test.response_code, 200)
        self.assertFalse(legit_test.attack_succeeded)


class TestSentinelOrchestrationFlow(unittest.TestCase):
    """Verifies the complete deterministic state machine workflow."""

    def test_happy_path_execution(self):
        orch = SentinelOrchestrator(max_retries=2)
        final_state = orch.run(auto_approve=True)
        self.assertTrue(final_state["completed"])
        self.assertFalse(final_state["escalated_to_human"])
        self.assertIsNotNone(final_state["final_report"])
        self.assertEqual(final_state["final_report"]["initial_risk_score"], 8.2)
        self.assertEqual(final_state["final_report"]["final_verified_risk_score"], 3.1)
        self.assertEqual(len(final_state["verdict_history"]), 4)

    def test_rejection_feedback_and_self_correction(self):
        # Inject fault into Investigator that gets rejected on attempt 1, self-corrects on attempt 2
        orch = SentinelOrchestrator(max_retries=2)
        final_state = orch.run(
            auto_approve=True,
            fault_injection={"investigator": "fake_cwe_id"}
        )
        self.assertTrue(final_state["completed"])
        # Retries for Investigator should be 1
        self.assertEqual(final_state["retry_counts"]["Investigator"], 1)
        # Total verdicts should be 5 (1 reject + 4 passes)
        self.assertEqual(len(final_state["verdict_history"]), 5)
        self.assertEqual(final_state["verdict_history"][1]["status"], "REJECT")
        self.assertEqual(final_state["verdict_history"][2]["status"], "PASS")

    def test_human_approval_withheld_escalates(self):
        orch = SentinelOrchestrator(max_retries=2)
        final_state = orch.run(auto_approve=False)
        self.assertFalse(final_state["completed"])
        self.assertTrue(final_state["escalated_to_human"])
        self.assertIn("Human approval", final_state["escalation_reason"])

    def test_html_report_generation(self):
        orch = SentinelOrchestrator(max_retries=2)
        final_state = orch.run(auto_approve=True)
        html = generate_html_report(final_state)
        self.assertIn("Iso/sae 21434", html)
        self.assertIn("8.2", html)
        self.assertIn("3.1", html)
        self.assertIn("Blocked", html)


if __name__ == "__main__":
    unittest.main()
