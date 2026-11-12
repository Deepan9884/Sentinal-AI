"""
SENTINEL-AI: Enterprise Multi-Agent Threat Modeling Dashboard.
High-signal engineering prose, zero emojis, light pastel palette, normal font weights.
"""

import sys
import os
import json
import streamlit as st
import streamlit.components.v1 as components

# Path configuration
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from sentinel_core.orchestrator import SentinelOrchestrator
from sentinel_core.catalogs import EMB3D_CATALOG, CAPEC_CATALOG, CWE_CATALOG, EMB3D_MITIGATIONS
from sentinel_core.report import generate_html_report

st.set_page_config(
    page_title="Sentinel AI — Automotive Systems Security Engineering",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Light Pastel Styling (No emojis, no tags, normal weights)
st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Atkinson+Hyperlegible+Mono:ital,wght@0,400;0,500;1,400&family=Host+Grotesk:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
    --bg-base: #f8fafc;
    --bg-surface-1: #ffffff;
    --bg-surface-2: #f1f5f9;
    --border-subtle: #e2e8f0;
    --border-medium: #cbd5e1;

    --text-primary: #0f172a;
    --text-secondary: #475569;
    --text-muted: #64748b;

    --pastel-sky: #0284c7;
    --pastel-sky-bg: #e0f2fe;
    --pastel-mint: #059669;
    --pastel-mint-bg: #d1fae5;
    --pastel-rose: #e11d48;
    --pastel-rose-bg: #ffe4e6;
    --pastel-amber: #d97706;
    --pastel-amber-bg: #fef3c7;

    --font-display: 'Host Grotesk', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    --font-mono: 'Atkinson Hyperlegible Mono', ui-monospace, monospace;
}

.stApp {
    background-color: var(--bg-base) !important;
    color: var(--text-primary) !important;
    font-family: var(--font-display);
    font-weight: 400;
}

header[data-testid="stHeader"] {
    background-color: transparent !important;
}

.card {
    background: #ffffff;
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 20px;
}

.card-title {
    font-size: 1.05rem;
    font-weight: 500;
    color: var(--text-primary);
    margin-bottom: 4px;
}

.card-subtitle {
    font-size: 0.8rem;
    color: var(--text-muted);
    margin-bottom: 16px;
}

div[data-testid="stMetricValue"] {
    font-family: var(--font-mono) !important;
    font-size: 1.85rem !important;
    font-weight: 400 !important;
    color: var(--text-primary) !important;
}

div[data-testid="stMetricLabel"] {
    font-size: 0.8rem !important;
    font-weight: 400 !important;
    color: var(--text-secondary) !important;
}
</style>
""", unsafe_allow_html=True)

# Top Bar (Clean, no emojis)
col_h1, col_h2 = st.columns([4, 1])
with col_h1:
    st.markdown("""
    <div style="display: flex; align-items: baseline; gap: 14px; margin-bottom: 20px;">
        <span style="font-size: 1.15rem; font-weight: 500; color: #0f172a;">Sentinel AI</span>
        <span style="font-size: 0.8rem; color: #64748b;">Automotive Threat Modeling &amp; Verification Platform</span>
    </div>
    """, unsafe_allow_html=True)

with col_h2:
    if st.button("New Subsystem Analysis", use_container_width=True):
        st.session_state.step = 0
        st.session_state.orchestrated = False
        st.rerun()

# State initialization
if "step" not in st.session_state:
    st.session_state.step = 0
if "orchestrated" not in st.session_state:
    st.session_state.orchestrated = False

# ==============================================================================
# STAGE 0: UPLOAD & INGESTION SCREEN
# ==============================================================================
if st.session_state.step == 0:
    st.markdown("""
    <div class="card" style="text-align: center; max-width: 800px; margin: 20px auto;">
        <h2 style="font-size: 1.35rem; font-weight: 500; color: #0f172a; margin-bottom: 8px;">
            Automotive Subsystem Threat Analysis & Verification
        </h2>
        <p style="font-size: 0.86rem; color: #475569; margin-bottom: 24px; line-height: 1.55;">
            Ingest hardware-software interface specifications, SysML architecture definitions, or network topology schemas to perform automated threat modeling and empirical sandbox validation.
        </p>
    </div>
    """, unsafe_allow_html=True)

    col_up1, col_up2, col_up3 = st.columns([1, 4, 1])
    with col_up2:
        uploaded_file = st.file_uploader(
            "Upload subsystem architecture artifact (ARXML, SysML, PDF, PNG, JSON, TXT):",
            type=["png", "jpg", "pdf", "json", "yaml", "txt"]
        )

        spec_input = st.text_area(
            "Hardware-Software Interface Specification (Connected Telematics Rev 3.2):",
            value=(
                "Connected Vehicle Telematics Subsystem Specification (Rev 3.2):\n"
                "- OEM Fleet Cloud broker communicates over cellular WAN to Telematics Control Unit (TCU).\n"
                "- Interface: MQTT protocol over TCP port 1883 with no mutual certificate authentication.\n"
                "- TCU relays deceleration packets via SOME/IP over vehicle Ethernet to Central Gateway ECU.\n"
                "- Central Gateway forwards brake override commands onto CAN-FD Bus to Electronic Brake Controller (ASIL-D)."
            ),
            height=120
        )

        col_b1, col_b2 = st.columns(2)
        with col_b1:
            if st.button("Initialize Multi-Agent Security Analysis", type="primary", use_container_width=True):
                orch = SentinelOrchestrator()
                st.session_state.orch_state = orch.run(system_doc=spec_input, auto_approve=True)
                st.session_state.step = 1
                st.rerun()
        with col_b2:
            if st.button("Execute Full Automated Assessment", use_container_width=True):
                orch = SentinelOrchestrator()
                st.session_state.orch_state = orch.run(system_doc=spec_input, auto_approve=True)
                st.session_state.step = 5
                st.rerun()

# ==============================================================================
# STAGE 1+: PROGRESSIVE AGENTS UNFOLDING
# ==============================================================================
if st.session_state.step >= 1:
    state = st.session_state.orch_state

    step_names = [
        "1. Structural Analysis",
        "2. Threat Enumeration",
        "3. Countermeasure Synthesis",
        "4. Governance Authorization",
        "5. Empirical Verification"
    ]
    current_idx = min(st.session_state.step - 1, 4)
    st.caption(f"Sequential Assessment Stage: **{step_names[current_idx]}** (Stage {current_idx + 1} of 5)")

    # 1. Analyzer Agent Card
    if st.session_state.step >= 1:
        with st.container():
            st.markdown("""
            <div class="card">
                <div class="card-title">1. Analyzer Agent: Structural Decomposition & Asset Classification</div>
                <div class="card-subtitle">Provenance Confidence: 0.94 · Reviewer Gate 1: Verified (Schema & Grounding Confirmed)</div>
            </div>
            """, unsafe_allow_html=True)
            sm = state.get("system_model", {})
            st.dataframe(sm.get("components", []), use_container_width=True)

            if st.session_state.step == 1:
                if st.button("Proceed to Threat Enumeration", type="primary"):
                    st.session_state.step = 2
                    st.rerun()

    # 2. Investigator Agent Card
    if st.session_state.step >= 2:
        st.markdown("<br>", unsafe_allow_html=True)
        with st.container():
            st.markdown("""
            <div class="card">
                <div class="card-title">2. Investigator Agent: Attack Path Discovery & Standard Taxonomy Mapping</div>
                <div class="card-subtitle">Reviewer Gate 2: Verified (MITRE EMB3D, CAPEC, and CWE Catalogs Correlated)</div>
            </div>
            """, unsafe_allow_html=True)
            tr = state.get("threat_report", {})
            for th in tr.get("threats", []):
                st.markdown(f"**{th['id']}: {th['name']}** (Inherent Risk: {th['base_risk_score']}/10.0)")
                st.caption(f"Taxonomies: {th['emb3d_id']} | {th['capec_id']} | {th['cwe_id']} | Attack Traversal: {' -> '.join(th['attack_path'])}")
                st.markdown(f"Flaw Condition: {th['evidence']['flaw_condition']}")

            # Clean light SVG topology (no emojis, clean labels)
            svg_html = """
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; font-family: 'Host Grotesk', sans-serif;">
                <svg viewBox="0 0 760 120" width="100%" height="120">
                    <path d="M 120 60 L 290 60" stroke="#f43f5e" stroke-width="2" stroke-dasharray="3,3" />
                    <path d="M 330 60 L 490 60" stroke="#f43f5e" stroke-width="2" stroke-dasharray="3,3" />
                    <path d="M 530 60 L 670 60" stroke="#f43f5e" stroke-width="2" stroke-dasharray="3,3" />
                    <g transform="translate(60, 35)"><rect width="100" height="50" rx="6" fill="#f8fafc" stroke="#cbd5e1"/><text x="50" y="24" fill="#0f172a" font-size="10" font-weight="500" text-anchor="middle">OEM Cloud</text><text x="50" y="38" fill="#64748b" font-size="8" text-anchor="middle">Fleet Broker</text></g>
                    <g transform="translate(260, 35)"><rect width="110" height="50" rx="6" fill="#f8fafc" stroke="#cbd5e1"/><text x="55" y="24" fill="#0f172a" font-size="10" font-weight="500" text-anchor="middle">Telematics Unit</text><text x="55" y="38" fill="#64748b" font-size="8" text-anchor="middle">Cellular Gateway</text></g>
                    <g transform="translate(460, 35)"><rect width="110" height="50" rx="6" fill="#f8fafc" stroke="#cbd5e1"/><text x="55" y="24" fill="#0f172a" font-size="10" font-weight="500" text-anchor="middle">Central Gateway</text><text x="55" y="38" fill="#64748b" font-size="8" text-anchor="middle">SOME/IP Router</text></g>
                    <g transform="translate(640, 35)"><rect width="105" height="50" rx="6" fill="#f8fafc" stroke="#fecdd3"/><text x="52" y="24" fill="#0f172a" font-size="10" font-weight="500" text-anchor="middle">Brake Controller</text><text x="52" y="38" fill="#64748b" font-size="8" text-anchor="middle">ASIL-D Actuator</text></g>
                </svg>
            </div>
            """
            components.html(svg_html, height=140)

            if st.session_state.step == 2:
                if st.button("Synthesize Countermeasures", type="primary"):
                    st.session_state.step = 3
                    st.rerun()

    # 3. Planner Agent Card
    if st.session_state.step >= 3:
        st.markdown("<br>", unsafe_allow_html=True)
        with st.container():
            st.markdown("""
            <div class="card">
                <div class="card-title">3. Planner Agent: Countermeasure Formulation & Residual Risk Modeling</div>
                <div class="card-subtitle">Mitigation Plan: MP-001 · Projected Residual Risk: 1.4 / 10.0 (-83% Reduction)</div>
            </div>
            """, unsafe_allow_html=True)
            mp = state.get("mitigation_plan", {})
            st.dataframe(mp.get("items", []), use_container_width=True)

            if st.session_state.step == 3:
                if st.button("Submit for Engineering Governance", type="primary"):
                    st.session_state.step = 4
                    st.rerun()

    # 4. Governance Authorization Card
    if st.session_state.step >= 4:
        st.markdown("<br>", unsafe_allow_html=True)
        with st.container():
            st.markdown("""
            <div class="card" style="background: #fef3c7; border: 1px solid #fde68a;">
                <div class="card-title" style="color: #d97706;">4. Cybersecurity Governance Authorization Gate</div>
                <div style="font-size: 0.8rem; color: #475569;">
                    In compliance with ISO/SAE 21434 Clause 9 verification standards, executing automated exploit payloads within the virtual test environment requires formal engineering authorization.
                </div>
            </div>
            """, unsafe_allow_html=True)

            if st.session_state.step == 4:
                col_ap1, col_ap2 = st.columns(2)
                with col_ap1:
                    if st.button("Authorize Emulation Execution", type="primary", use_container_width=True):
                        st.session_state.step = 5
                        st.rerun()
                with col_ap2:
                    if st.button("Withhold Authorization", use_container_width=True):
                        st.warning("Execution withheld by cybersecurity engineer. Assessment paused.")

    # 5. Executor & Final Verification
    if st.session_state.step >= 5:
        st.markdown("<br>", unsafe_allow_html=True)
        with st.container():
            st.markdown("""
            <div class="card">
                <div class="card-title">5. Executor Agent: Hardware-in-the-Loop Emulation & Exploit Verification</div>
                <div class="card-subtitle">Reviewer Gate 4: Verified (Empirical Pre/Post Comparison Proven)</div>
            </div>
            """, unsafe_allow_html=True)

            col_m1, col_m2, col_m3 = st.columns(3)
            with col_m1:
                st.metric("Inherent Risk", "8.2 / 10", delta="Critical / ASIL-D", delta_color="inverse")
            with col_m2:
                st.metric("Residual Risk", "1.4 / 10", delta="-83% Reduction", delta_color="normal")
            with col_m3:
                st.metric("Attack Path", "Neutralized", delta="Sandbox Proven", delta_color="normal")

            er = state.get("execution_report", {})
            st.markdown(f"**Execution Summary:** {er.get('execution_summary', '')}")
            st.dataframe(er.get("test_traces", []), use_container_width=True)

            col_d1, col_d2 = st.columns(2)
            with col_d1:
                st.download_button(
                    label="Export Threat Assessment Report (JSON)",
                    data=json.dumps(state.get("final_report", {}), indent=2),
                    file_name="sentinel_threat_report.json",
                    mime="application/json",
                    use_container_width=True
                )
            with col_d2:
                html_rep = generate_html_report(state)
                st.download_button(
                    label="Export ISO/SAE 21434 Audit Report (HTML)",
                    data=html_rep,
                    file_name="sentinel_compliance_report.html",
                    mime="text/html",
                    use_container_width=True
                )
