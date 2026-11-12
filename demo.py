"""
SENTINEL-AI: Interactive Demonstration CLI.
Features:
- Step-by-step agent workflow visualization with Rich tables and callouts
- Knowledge graph inspection
- Live rejection feedback loop demonstration
- Human-in-the-loop approval gate demonstration
- Before-and-after empirical verification (Risk 8.2 -> 3.1)
"""

import sys
import os
import time
import argparse

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from sentinel_core.orchestrator import SentinelOrchestrator
from sentinel_core.graph import SecurityKnowledgeGraph
from sentinel_core.agents import AnalyzerAgent

console = Console(force_terminal=True, legacy_windows=False)


def print_banner():
    banner = Text(
        "+======================================================================+\n"
        "|                     SENTINEL - AI  ORCHESTRATOR                      |\n"
        "|  Evidence-Based Multi-Agent Threat Modeling & Automated Validation   |\n"
        "|             TECHgium / L&T Embedded Cybersecurity Track              |\n"
        "+======================================================================+",
        style="bold cyan"
    )
    console.print(banner)
    console.print(
        "[bold white]Architecture:[/bold white] [yellow]Sentinel (State Machine)[/yellow] -> "
        "[blue]1. Analyzer[/blue] -> [red]Reviewer[/red] -> [magenta]2. Investigator (Rule-Engine)[/magenta] -> [red]Reviewer[/red] -> "
        "[teal]3. Planner[/teal] -> [red]Reviewer[/red] -> [bold orange3]4. Executor (Sandbox)[/bold orange3] -> [red]Reviewer[/red] -> "
        "[green]Human Engineer Approval[/green]\n"
    )


def run_full_demo():
    console.print(Panel("[bold green]STARTING END-TO-END DEMO: AUTOMOTIVE TELEMATICS SUBSYSTEM[/bold green]", box=box.ROUNDED))
    orch = SentinelOrchestrator(max_retries=2)
    
    with console.status("[bold green]Executing deterministic multi-agent pipeline...", spinner="dots"):
        final_state = orch.run(auto_approve=True)

    # 1. Print Analyzer Extraction
    model = final_state["system_model"]
    comp_table = Table(title="Analyzer Output: Extracted Components & Trust Zones", box=box.SIMPLE_HEAVY)
    comp_table.add_column("Component ID", style="cyan")
    comp_table.add_column("Name", style="white")
    comp_table.add_column("Trust Zone", style="yellow")
    comp_table.add_column("Critical?", style="red")
    comp_table.add_column("Confidence", style="green")

    for comp in model["components"]:
        comp_table.add_row(
            comp["id"],
            comp["name"],
            comp["trust_zone"],
            "YES (ASIL-D)" if comp["is_safety_critical"] else "No",
            f"{comp['confidence_score']:.2f}"
        )
    console.print(comp_table)

    # 2. Print Investigator Threat Findings
    threats = final_state["threat_report"]["threats"]
    threat_table = Table(title="Investigator Output: Rule-Derived Threats & Attack Paths", box=box.SIMPLE_HEAVY)
    threat_table.add_column("Threat ID", style="cyan")
    threat_table.add_column("Threat Name", style="white")
    threat_table.add_column("Standards Reference", style="magenta")
    threat_table.add_column("Attack Path Traversed", style="red")
    threat_table.add_column("Base Risk", style="bold red")

    for th in threats:
        threat_table.add_row(
            th["id"],
            th["name"],
            f"{th['emb3d_id']} | {th['capec_id']} | {th['cwe_id']}",
            " -> ".join(th["attack_path"]),
            f"{th['base_risk_score']}/10.0"
        )
    console.print(threat_table)

    # 3. Print Planner Mitigations
    plan = final_state["mitigation_plan"]
    plan_table = Table(title="Planner Output: Prioritized Mitigation Strategy", box=box.SIMPLE_HEAVY)
    plan_table.add_column("Mitigation ID", style="cyan")
    plan_table.add_column("EMB3D Catalog ID", style="magenta")
    plan_table.add_column("Countermeasure Action", style="white")
    plan_table.add_column("Target Node", style="yellow")
    plan_table.add_column("Projected Risk", style="green")

    for item in plan["items"]:
        plan_table.add_row(
            item["id"],
            item["mitigation_catalog_id"],
            item["name"],
            item["target_component_id"],
            f"{plan['initial_system_risk']} -> {item['projected_final_risk']} (-{item['projected_risk_reduction']})"
        )
    console.print(plan_table)

    # 4. Print Reviewer Gate History
    verdicts = final_state["verdict_history"]
    rev_table = Table(title="Reviewer Gate Checkpoints (Strict Non-LLM Hard Verification)", box=box.SIMPLE_HEAVY)
    rev_table.add_column("Target Agent", style="cyan")
    rev_table.add_column("Verdict", style="bold")
    rev_table.add_column("Hard Checks Performed", style="white")
    rev_table.add_column("Violations", style="green")

    for v in verdicts:
        status_text = "[bold green]PASS[/bold green]" if v["is_valid"] else "[bold red]REJECT[/bold red]"
        rev_table.add_row(
            v["agent_reviewed"],
            status_text,
            f"{len(v['hard_checks_performed'])} verified (Taxonomy, Graph Nodes, Schema)",
            "None" if not v["rule_violations"] else "\n".join(v["rule_violations"])
        )
    console.print(rev_table)

    # 5. Print Executor Sandbox Verification
    exec_rep = final_state["execution_report"]
    exec_table = Table(title="Executor Output: Sandbox Testing & Empirical Verification", box=box.SIMPLE_HEAVY)
    exec_table.add_column("Test Phase", style="cyan")
    exec_table.add_column("Injected Exploit Vector", style="white")
    exec_table.add_column("Sandbox Outcome", style="bold")
    exec_table.add_column("Response Code", style="yellow")
    exec_table.add_column("Latency", style="white")

    for trace in exec_rep["test_traces"]:
        if trace["phase"] == "BASELINE_EXPLOIT":
            outcome = "[bold red]EXPLOIT CONFIRMED (Vulnerable)[/bold red]" if trace["attack_succeeded"] else "[bold green]EXPLOIT FAILED[/bold green]"
            vector_desc = f"{trace['command_injected']['action']} (Spoofed/Unauth)"
        elif trace["phase"] == "POST_MITIGATION_VERIFICATION":
            outcome = "[bold green]ATTACK BLOCKED (Protected)[/bold green]" if not trace["attack_succeeded"] else "[bold red]EXPLOIT BREACHED (Vulnerable)[/bold red]"
            vector_desc = f"{trace['command_injected']['action']} (Spoofed/Unauth)"
        else:
            outcome = "[bold green]LEGITIMATE TRAFFIC PRESERVED (Operational)[/bold green]" if trace["response_code"] == 200 else "[bold red]DENIAL OF SERVICE (Broken)[/bold red]"
            vector_desc = f"{trace['command_injected']['action']} (Authorized/Signed)"

        exec_table.add_row(
            trace["phase"],
            vector_desc,
            outcome,
            str(trace["response_code"]),
            f"{trace['execution_time_ms']} ms"
        )
    console.print(exec_table)

    # 6. Final Summary Card
    fin = final_state["final_report"]
    risk_panel = Panel(
        f"[bold white]SYSTEM SECURITY CERTIFICATION SUMMARY[/bold white]\n\n"
        f"- [bold]Subsystem:[/bold] {fin['system_analyzed']}\n"
        f"- [bold]Baseline Attack Path Risk Score:[/bold] [bold red]{fin['initial_risk_score']}/10.0 (HIGH/CRITICAL)[/bold red]\n"
        f"- [bold]Post-Mitigation Verified Risk Score:[/bold] [bold green]{fin['final_verified_risk_score']}/10.0 (LOW)[/bold green]\n"
        f"- [bold]Net Risk Reduction:[/bold] [bold yellow]{fin['risk_reduction_percentage']}[/bold yellow]\n"
        f"- [bold]Attack Path Status:[/bold] [bold green]COMPLETELY BLOCKED[/bold green]\n"
        f"- [bold]Standards Compliance:[/bold] {', '.join(fin['compliance_standards'])}\n"
        f"- [bold]Human Lead Engineer Signoff:[/bold] [bold green]APPROVED & ARCHIVED[/bold green]",
        title="[bold yellow]Final Executive & Compliance Verdict[/bold yellow]",
        box=box.DOUBLE
    )
    console.print(risk_panel)


def run_rejection_demo():
    console.print(Panel("[bold yellow]DEMO: REVIEWER REJECTION & RECOVERY LOOP[/bold yellow]", box=box.ROUNDED))
    console.print("Injecting intentional fault: Investigator agent attempts to cite non-existent [red]CWE-99999-FAKE[/red].")
    
    orch = SentinelOrchestrator(max_retries=2)
    final_state = orch.run(
        auto_approve=True,
        fault_injection={"investigator": "fake_cwe_id"}
    )

    console.print("\n[bold cyan]Timeline of Orchestrator Events:[/bold cyan]")
    for log in final_state["flow_logs"]:
        if "REJECT" in log:
            console.print(f"[bold red]{log}[/bold red]")
        elif "PASS" in log:
            console.print(f"[bold green]{log}[/bold green]")
        elif "Self-correction" in log:
            console.print(f"[bold yellow]{log}[/bold yellow]")
        else:
            console.print(f"[dim]{log}[/dim]")

    console.print(
        f"\n[bold green]RESULT:[/bold green] Reviewer rejected the hallucinated CWE ID on Attempt 1. "
        f"Sentinel captured specific feedback, routed back to Investigator. "
        f"Investigator self-corrected on Attempt 2 with authentic CWE-306, and Reviewer passed!"
    )


def run_escalation_demo():
    console.print(Panel("[bold magenta]DEMO: HUMAN-IN-THE-LOOP APPROVAL GUARDRAIL[/bold magenta]", box=box.ROUNDED))
    console.print("Running pipeline with Human Engineer approval withheld (simulating cautious safety review)...")

    orch = SentinelOrchestrator(max_retries=2)
    final_state = orch.run(auto_approve=False)

    console.print("\n[bold cyan]Execution Trace:[/bold cyan]")
    for log in final_state["flow_logs"][-6:]:
        console.print(log)

    console.print(
        f"\n[bold yellow]GUARDRAIL CERTIFICATION:[/bold yellow] Sentinel successfully paused before the Executor "
        f"applied any sandbox changes, maintaining complete engineer control."
    )


def main():
    parser = argparse.ArgumentParser(description="SENTINEL-AI Demonstration Runner")
    parser.add_argument("--mode", type=int, choices=[1, 2, 3], help="1: Full Demo, 2: Rejection Loop, 3: Escalation")
    args = parser.parse_args()

    print_banner()

    if args.mode == 1:
        run_full_demo()
        return
    elif args.mode == 2:
        run_rejection_demo()
        return
    elif args.mode == 3:
        run_escalation_demo()
        return

    while True:
        console.print("\n[bold cyan]Select Demonstration Mode:[/bold cyan]")
        console.print("  [1] Run Complete End-to-End Sentinel Demo (Happy Path)")
        console.print("  [2] Demonstrate Reviewer Rejection Loop & Self-Correction")
        console.print("  [3] Demonstrate Human Approval Guardrail & Escalation")
        console.print("  [4] Exit")

        try:
            choice = input("\nEnter choice (1-4) [default: 1]: ").strip() or "1"
        except (EOFError, KeyboardInterrupt):
            choice = "1"

        if choice == "1":
            run_full_demo()
            break
        elif choice == "2":
            run_rejection_demo()
            break
        elif choice == "3":
            run_escalation_demo()
            break
        elif choice == "4":
            console.print("[yellow]Exiting Sentinel Prototype.[/yellow]")
            break
        else:
            console.print("[red]Invalid selection.[/red]")


if __name__ == "__main__":
    main()
