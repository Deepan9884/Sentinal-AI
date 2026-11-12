"""
Isolated Emulated Target & Verification Sandbox for SENTINEL-AI.
Simulates an automotive telematics gateway bridging MQTT external broker to
an internal CAN-FD Brake Controller ECU.
"""

import time
from typing import Dict, Any, List, Optional
from ..models.schemas import SandboxTestExecution


class EmulatedSubsystem:
    """
    Simulated QEMU/CAN target running strictly inside an isolated memory sandbox.
    Does not interact with physical hardware or real production networks.
    """

    def __init__(self, target_id: str = "TARGET-AUTO-01"):
        self.target_id = target_id
        # Emulated Gateway Configuration
        self.gateway_config: Dict[str, Any] = {
            "require_mtls": False,
            "enforce_hmac": False,
            "allowed_ciphers": "ALL",
            "accepted_client_cn": "*",
            "port": 1883,
            "fw_version": "v1.0.4-unpatched"
        }
        # Emulated Brake Controller State
        self.brake_state: Dict[str, Any] = {
            "current_pressure_bar": 0,
            "override_engaged": False,
            "emergency_brake_tripped": False,
            "last_can_frame_id": "NONE",
            "tampering_alerts": 0
        }
        self.execution_logs: List[str] = []

    def _log(self, msg: str):
        self.execution_logs.append(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def run_exploit_test(self, test_id: str = "TEST-SPOOF-01") -> SandboxTestExecution:
        """
        Executes baseline exploit test (simulates boofuzz / custom exploit packet).
        Sends unauthenticated spoofed brake actuator message over MQTT link.
        """
        t0 = time.time()
        self._log("Initiating baseline vulnerability exploit test...")
        self._log(f"Target: Gateway [Port {self.gateway_config['port']}] -> CAN Bus 0x130 -> Brake Controller")

        payload = {
            "header": "TELEMATICS_CONTROL_PACKET",
            "client_id": "attacker_spoofed_session",
            "action": "EMERGENCY_DECELERATION_ACTUATE",
            "pressure_bar": 120,
            "hmac_signature": None,
            "client_certificate": None
        }

        # Check Gateway Ingress Rules
        if not self.gateway_config["require_mtls"]:
            self._log("[GATEWAY-INSPECTION]: TLS handshake bypass accepted (mTLS Disabled).")
            if not self.gateway_config["enforce_hmac"]:
                self._log("[GATEWAY-ROUTER]: No cryptographic MAC required. Forwarding payload to CAN Bus ID 0x130...")
                # Brake Controller accepts unauthenticated command
                self.brake_state["current_pressure_bar"] = 120
                self.brake_state["override_engaged"] = True
                self.brake_state["emergency_brake_tripped"] = True
                self.brake_state["last_can_frame_id"] = "0x130"

                elapsed = round((time.time() - t0) * 1000, 2)
                self._log("[BRAKE-ECU-CRITICAL]: CRITICAL WARNING: Actuator forced to 120 bar without authentication!")

                return SandboxTestExecution(
                    test_id=test_id,
                    phase="BASELINE_EXPLOIT",
                    test_target="COMP-BRAKE-CTRL via COMP-GW",
                    command_injected=payload,
                    attack_succeeded=True,
                    response_code=200,
                    raw_response="EXPLOIT_CONFIRMED: Remote spoofed payload breached Gateway and actuated Brake ECU.",
                    execution_time_ms=elapsed
                )

        # Fallback if somehow already secured
        elapsed = round((time.time() - t0) * 1000, 2)
        return SandboxTestExecution(
            test_id=test_id,
            phase="BASELINE_EXPLOIT",
            test_target="COMP-BRAKE-CTRL via COMP-GW",
            command_injected=payload,
            attack_succeeded=False,
            response_code=401,
            raw_response="EXPLOIT_FAILED: Gateway dropped ingress.",
            execution_time_ms=elapsed
        )

    def apply_patch(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        """
        Applies configuration patch strictly to the emulated sandbox copy.
        """
        self._log("Applying mitigation configuration patch to sandbox...")
        applied_keys = []
        for k, v in patch.items():
            if k in self.gateway_config:
                self.gateway_config[k] = v
                applied_keys.append(k)
                self._log(f"  -> Config updated: {k} = {v}")
            else:
                self.gateway_config[k] = v
                applied_keys.append(k)

        self.gateway_config["fw_version"] = "v1.1.0-mitigated-mtls"
        # Reset actuator state to safe defaults
        self.brake_state["current_pressure_bar"] = 0
        self.brake_state["override_engaged"] = False
        self.brake_state["emergency_brake_tripped"] = False
        self._log("Subsystem re-initialized in patched state.")

        return {
            "status": "SUCCESS",
            "applied_keys": applied_keys,
            "current_config": self.gateway_config
        }

    def run_verification_test(self, test_id: str = "TEST-VERIFY-01") -> SandboxTestExecution:
        """
        Re-runs the exact same exploit payload against the patched sandbox.
        Demonstrates that the attack path is physically blocked.
        """
        t0 = time.time()
        self._log("Executing post-mitigation verification test with identical attack vector...")

        payload = {
            "header": "TELEMATICS_CONTROL_PACKET",
            "client_id": "attacker_spoofed_session",
            "action": "EMERGENCY_DECELERATION_ACTUATE",
            "pressure_bar": 120,
            "hmac_signature": None,
            "client_certificate": None
        }

        # Check Gateway Ingress Rules
        if self.gateway_config["require_mtls"]:
            self._log("[GATEWAY-INSPECTION]: TLS 1.3 Handshake Failure! Peer presented no client certificate.")
            self._log("[SECURITY-EVENT]: Dropping unauthorized connection from external perimeter.")
            self.brake_state["tampering_alerts"] += 1

            elapsed = round((time.time() - t0) * 1000, 2)
            self._log("[BRAKE-ECU-PROTECTED]: Zero unauthorized frames reached CAN Bus 0x130. Brake pressure remains 0 bar.")

            return SandboxTestExecution(
                test_id=test_id,
                phase="POST_MITIGATION_VERIFICATION",
                test_target="COMP-BRAKE-CTRL via COMP-GW",
                command_injected=payload,
                attack_succeeded=False,  # Attack blocked!
                response_code=401,
                raw_response="SECURITY_BLOCK: Handshake terminated. mTLS client certificate required.",
                execution_time_ms=elapsed
            )

        elapsed = round((time.time() - t0) * 1000, 2)
        return SandboxTestExecution(
            test_id=test_id,
            phase="POST_MITIGATION_VERIFICATION",
            test_target="COMP-BRAKE-CTRL via COMP-GW",
            command_injected=payload,
            attack_succeeded=True,
            response_code=200,
            raw_response="WARNING: Patch was not active.",
            execution_time_ms=elapsed
        )

    def run_legitimate_test(self, test_id: str = "TEST-LEGITIMATE-AUTH") -> SandboxTestExecution:
        """
        Verifies that legitimate, properly authenticated telematics traffic continues to function.
        Confirms zero false positives and preserves vehicle availability.
        """
        t0 = time.time()
        self._log("Verifying legitimate authenticated telematics operation...")

        auth_payload = {
            "header": "TELEMATICS_CONTROL_PACKET",
            "client_id": "tcu.telematics.oem.internal",
            "action": "DIAGNOSTIC_TELEMETRY_SYNC",
            "client_certificate": "SHA256:4a8b...[VALID_OEM_CA_CERT]",
            "hmac_signature": "HMAC_VALID_TOKEN"
        }

        # Check authentication against configuration
        if self.gateway_config["require_mtls"]:
            if auth_payload["client_certificate"] and auth_payload["client_id"] == self.gateway_config.get("accepted_client_cn", "*"):
                self._log("[GATEWAY-INSPECTION]: Mutual TLS certificate validated. Authorized channel established.")
            elif self.gateway_config.get("accepted_client_cn") == "*":
                self._log("[GATEWAY-INSPECTION]: Mutual TLS certificate validated.")
            else:
                elapsed = round((time.time() - t0) * 1000, 2)
                return SandboxTestExecution(
                    test_id=test_id,
                    phase="POST_MITIGATION_LEGITIMATE",
                    test_target="COMP-GW",
                    command_injected=auth_payload,
                    attack_succeeded=False,
                    response_code=403,
                    raw_response="UNEXPECTED_REJECTION: Valid client was rejected.",
                    execution_time_ms=elapsed
                )

        elapsed = round((time.time() - t0) * 1000, 2)
        self._log("[GATEWAY-ROUTER]: Legitimate telemetry packet processed successfully.")
        return SandboxTestExecution(
            test_id=test_id,
            phase="POST_MITIGATION_LEGITIMATE",
            test_target="COMP-GW",
            command_injected=auth_payload,
            attack_succeeded=False,
            response_code=200,
            raw_response="SUCCESS: Legitimate authenticated telematics traffic operational.",
            execution_time_ms=elapsed
        )
