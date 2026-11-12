"""
Standardized Threat & Mitigation Taxonomies for Embedded and Automotive Cybersecurity.
Includes lookup indices for MITRE EMB3D, MITRE CAPEC, and MITRE CWE.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class TaxonomyEntry:
    id: str
    name: str
    description: str
    category: str
    stride_category: str
    default_severity: float  # CVSS v3.1 base score proxy (0.0 - 10.0)
    related_cwes: List[str]
    mitigations: List[str]


# MITRE EMB3D (Embedded Device Threat Model)
EMB3D_CATALOG: Dict[str, TaxonomyEntry] = {
    "EMB3D-T-0012": TaxonomyEntry(
        id="EMB3D-T-0012",
        name="Insecure Telematics Protocol Interface",
        description="Remote cellular/telematics interface accepts unauthenticated or cleartext telemetry messages crossing network trust boundary.",
        category="Network/Interface",
        stride_category="Spoofing",
        default_severity=8.2,
        related_cwes=["CWE-306", "CWE-319"],
        mitigations=["EMB3D-M-0004", "EMB3D-M-0008"]
    ),
    "EMB3D-T-0021": TaxonomyEntry(
        id="EMB3D-T-0021",
        name="Unauthenticated Remote Command Injection into Gateway",
        description="Central Gateway forwards unverified external commands onto internal vehicle buses (CAN/CAN-FD/LIN) without cryptographic validation.",
        category="Control Flow",
        stride_category="Tampering",
        default_severity=8.8,
        related_cwes=["CWE-306", "CWE-345"],
        mitigations=["EMB3D-M-0004", "EMB3D-M-0008", "EMB3D-M-0012"]
    ),
    "EMB3D-T-0005": TaxonomyEntry(
        id="EMB3D-T-0005",
        name="Unauthorized Firmware / Calibration Modification",
        description="Microcontroller bootloader or application flashing routines do not enforce digital signature verification (Secure Boot bypass).",
        category="Firmware/Hardware",
        stride_category="Tampering",
        default_severity=9.1,
        related_cwes=["CWE-347", "CWE-494"],
        mitigations=["EMB3D-M-0001", "EMB3D-M-0003"]
    ),
    "EMB3D-T-0033": TaxonomyEntry(
        id="EMB3D-T-0033",
        name="Exposed Diagnostic Port Over Internal Bus",
        description="UDS/OBD diagnostic services enabled without authentication session (SecurityAccess 0x27) on active operational bus.",
        category="Diagnostics",
        stride_category="Elevation of Privilege",
        default_severity=7.5,
        related_cwes=["CWE-287"],
        mitigations=["EMB3D-M-0007"]
    )
}

# EMB3D Mitigations Catalog
EMB3D_MITIGATIONS: Dict[str, Dict[str, str]] = {
    "EMB3D-M-0004": {
        "id": "EMB3D-M-0004",
        "name": "Mutual TLS (mTLS) with Hardware-Backed Keys",
        "description": "Enforce TLS 1.3 with client & server certificate verification using HSM / Secure Element private keys.",
        "risk_reduction_factor": 0.62
    },
    "EMB3D-M-0008": {
        "id": "EMB3D-M-0008",
        "name": "Cryptographic Message Authentication (SecOC / HMAC-SHA256)",
        "description": "Append freshness counter and truncated cryptographic MAC to all cross-domain control messages.",
        "risk_reduction_factor": 0.60
    },
    "EMB3D-M-0012": {
        "id": "EMB3D-M-0012",
        "name": "Gateway Ingress Filtering & Protocol Sanitization",
        "description": "Strict payload schema whitelist and stateful gateway rate limiting.",
        "risk_reduction_factor": 0.40
    }
}

# CAPEC (Common Attack Pattern Enumerations and Classifications)
CAPEC_CATALOG: Dict[str, Dict[str, str]] = {
    "CAPEC-272": {
        "id": "CAPEC-272",
        "name": "Protocol Spoofing",
        "description": "An adversary crafts fraudulent network protocol messages simulating legitimate endpoints to bypass trust boundaries.",
        "severity": "High"
    },
    "CAPEC-94": {
        "id": "CAPEC-94",
        "name": "Adversary in the Middle (AiTM)",
        "description": "Interception and alteration of network communications between components lacking end-to-end cryptographic integrity.",
        "severity": "High"
    },
    "CAPEC-21": {
        "id": "CAPEC-21",
        "name": "Exploitation of Trusted Credentials",
        "description": "Using weak or default credentials on administrative or control interfaces.",
        "severity": "Medium"
    },
    "CAPEC-115": {
        "id": "CAPEC-115",
        "name": "Authentication Bypass",
        "description": "Circumventing authentication mechanisms to access restricted controller functions.",
        "severity": "Critical"
    }
}

# CWE (Common Weakness Enumeration)
CWE_CATALOG: Dict[str, Dict[str, str]] = {
    "CWE-306": {
        "id": "CWE-306",
        "name": "Missing Authentication for Critical Function",
        "description": "The product does not authenticate user or peer identity when performing an action that requires restricted privileges.",
        "severity": "High"
    },
    "CWE-319": {
        "id": "CWE-319",
        "name": "Cleartext Transmission of Sensitive Information",
        "description": "The software transmits sensitive data or commands without encryption over an untrusted transmission channel.",
        "severity": "Medium"
    },
    "CWE-345": {
        "id": "CWE-345",
        "name": "Insufficient Verification of Data Authenticity",
        "description": "The software does not sufficiently verify that data or commands originated from an authorized source.",
        "severity": "High"
    },
    "CWE-287": {
        "id": "CWE-287",
        "name": "Improper Authentication",
        "description": "When an actor claims to have a given identity, the software does not verify or incorrectly verifies the claim.",
        "severity": "High"
    }
}


def lookup_emb3d(emb3d_id: str) -> Optional[TaxonomyEntry]:
    return EMB3D_CATALOG.get(emb3d_id)


def lookup_capec(capec_id: str) -> Optional[Dict[str, str]]:
    return CAPEC_CATALOG.get(capec_id)


def lookup_cwe(cwe_id: str) -> Optional[Dict[str, str]]:
    return CWE_CATALOG.get(cwe_id)


def lookup_mitigation(mitigation_id: str) -> Optional[Dict[str, str]]:
    return EMB3D_MITIGATIONS.get(mitigation_id)


def is_valid_taxonomy_id(id_string: str) -> bool:
    """Hard check to confirm whether a referenced security ID exists in known catalogs."""
    return (
        id_string in EMB3D_CATALOG
        or id_string in CAPEC_CATALOG
        or id_string in CWE_CATALOG
        or id_string in EMB3D_MITIGATIONS
    )
