"""Threat modeling, including Shor's algorithm quantum risk scoring.

The model articulates the high-assurance root of trust posture and assigns
a per-certificate quantum risk score. RSA and ECC are vulnerable to Shor's
algorithm on a sufficiently large fault-tolerant quantum computer, so the
score rises sharply for small RSA keys and any classical ECC curve, and
falls to zero for NIST post-quantum algorithms (ML-DSA, ML-KEM, etc.).
"""

from datetime import datetime
from typing import Dict, Any

from .config import QUANTUM_SAFE_ALGORITHMS


# Resource estimates published in the literature (Gidney & Ekera 2021,
# NIST PQC reports) — number of logical qubits required for Shor on a
# given RSA key size. Used here only as illustrative context for the UI.
SHOR_LOGICAL_QUBITS = {
    1024: 2050,
    2048: 4099,
    3072: 6147,
    4096: 8195,
}


class ThreatModel:
    """Quantum + classical threat model for the PKI estate."""

    def summary(self) -> Dict[str, Any]:
        return {
            'model': 'PKI high-assurance root of trust',
            'focus': 'TLS/SSL lifecycle, HSM-protected keys, quantum-safe readiness',
            'quantum_threat': (
                "Shor's algorithm efficiently factors integers and computes discrete "
                "logarithms on a fault-tolerant quantum computer, breaking RSA, DH, "
                "and elliptic-curve cryptography. Migrate to NIST PQC standards "
                "(ML-KEM, ML-DSA, SLH-DSA) and use HSM-protected hybrid keys."
            ),
            'classical_threats': [
                'Key compromise via exfiltrated private keys',
                'Misissued or rogue CA certificates',
                'Expired or self-signed certificates in production',
                'Weak cipher suites and deprecated TLS versions',
                'Open management ports exposed to the public internet',
            ],
            'recommendations': [
                'Generate and store all production keys inside the Entrust Shield HSM.',
                'Continuously inventory every TLS endpoint and revoke unknown ones.',
                'Renew certificates at least 45 days before expiry.',
                'Pilot hybrid X25519+ML-KEM key exchange and ML-DSA signatures.',
                'Align reports with PCI-DSS 4.0, HIPAA, ISO 27001, SOC 2, NIST 800-53.',
            ],
            'generated_at': datetime.utcnow().isoformat() + 'Z',
        }

    def score_certificate(self, algorithm: str, key_size: int) -> Dict[str, Any]:
        """Return a quantum-risk score for a single certificate.

        Score is 0 (safe) to 100 (broken today by Shor's algorithm on a
        cryptanalytically-relevant quantum computer).
        """
        alg = (algorithm or '').upper()
        size = int(key_size or 0)

        if any(safe.upper() in alg for safe in QUANTUM_SAFE_ALGORITHMS):
            classification = 'quantum-safe'
            score = 5
            rationale = f'{algorithm} is a NIST PQC algorithm and resistant to Shor.'
            mitigation = 'Maintain hybrid deployment alongside RSA/ECC for backwards compatibility.'
        elif 'RSA' in alg:
            if size < 2048:
                score, classification = 95, 'critical'
                rationale = f'RSA-{size} is below the 2048-bit floor and breakable today by classical means.'
            elif size < 3072:
                score, classification = 75, 'high'
                rationale = f'RSA-{size} is vulnerable to Shor and falls below the NIST 2030 recommendation.'
            elif size < 4096:
                score, classification = 55, 'medium'
                rationale = f'RSA-{size} meets current standards but is at risk under Shor.'
            else:
                score, classification = 45, 'medium'
                rationale = f'RSA-{size} is strong classically yet still broken by Shor.'
            mitigation = 'Plan migration to ML-DSA (Dilithium) for signatures; pilot hybrid TLS.'
        elif 'EC' in alg or 'ECDSA' in alg or 'ED25519' in alg:
            score, classification = 70, 'high'
            rationale = (
                f'{algorithm} keys are short (≈{size} bits) but Shor solves the elliptic-'
                'curve discrete-log problem in polynomial time.'
            )
            mitigation = 'Move ECDSA workloads to ML-DSA and ECDH workloads to ML-KEM.'
        elif 'DSA' in alg or 'DH' in alg:
            score, classification = 80, 'high'
            rationale = f'{algorithm} relies on discrete logarithm, broken by Shor.'
            mitigation = 'Migrate to ML-DSA / ML-KEM and decommission legacy DSA/DH.'
        else:
            score, classification = 50, 'unknown'
            rationale = f'Algorithm {algorithm} not recognized; treat as quantum-vulnerable until classified.'
            mitigation = 'Identify the algorithm and re-evaluate against NIST PQC roadmap.'

        qubits = SHOR_LOGICAL_QUBITS.get(size)
        return {
            'algorithm': algorithm,
            'key_size': size,
            'classification': classification,
            'score': score,
            'rationale': rationale,
            'mitigation': mitigation,
            'shor_logical_qubits': qubits,
        }
