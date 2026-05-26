"""Compliance mapping for certificate inventory and firewall findings."""

from typing import Dict, List

from .models import CertificateRecord, ScanResult


FRAMEWORK_CONTROLS = {
    'PCI-DSS': [
        'Req 2.3 - Encrypt all non-console administrative access using strong cryptography',
        'Req 4.1 - Use strong cryptography and security protocols (TLS 1.2+)',
        'Req 4.2 - Never send unprotected PANs across open networks',
        'Req 12.10 - Maintain incident response, including key/certificate compromise',
    ],
    'HIPAA': [
        '164.312(a)(2)(iv) - Encryption and decryption of ePHI',
        '164.312(e)(1) - Transmission security with integrity controls',
    ],
    'ISO 27001': [
        'A.10.1 - Cryptographic controls policy',
        'A.10.1.2 - Key management lifecycle',
        'A.12.6 - Technical vulnerability management',
    ],
    'SOC 2': [
        'CC6.1 - Logical access security',
        'CC6.7 - Restrict transmission of data',
        'CC7.1 - Detection of security events',
    ],
    'NIST 800-53': [
        'SC-12 - Cryptographic key establishment and management',
        'SC-13 - Cryptographic protection (validated modules)',
        'SC-17 - Public key infrastructure certificates',
    ],
}


def evaluate_certificate(cert: CertificateRecord) -> Dict[str, str]:
    """Return a per-framework pass/fail/warn verdict for one certificate."""
    verdicts = {}
    weak = cert.key_algorithm.upper() == 'RSA' and cert.key_size < 2048
    expired = cert.days_remaining <= 0
    expiring = 0 < cert.days_remaining <= 45

    for framework in FRAMEWORK_CONTROLS:
        if expired or weak:
            verdicts[framework] = 'fail'
        elif expiring:
            verdicts[framework] = 'warn'
        else:
            verdicts[framework] = 'pass'
    return verdicts


def evaluate_scan(results: List[ScanResult]) -> Dict[str, str]:
    """Compliance verdict driven by firewall posture."""
    open_high = [r for r in results if r.state == 'open' and r.intrusion_indicator]
    verdicts = {}
    for framework in FRAMEWORK_CONTROLS:
        if len(open_high) > 5:
            verdicts[framework] = 'fail'
        elif open_high:
            verdicts[framework] = 'warn'
        else:
            verdicts[framework] = 'pass'
    return verdicts


def aggregate(certificates: List[CertificateRecord], scans: List[ScanResult]) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    cert_results = [evaluate_certificate(c) for c in certificates]
    scan_verdict = evaluate_scan(scans)
    for framework, controls in FRAMEWORK_CONTROLS.items():
        statuses = [r[framework] for r in cert_results] + [scan_verdict.get(framework, 'pass')]
        if 'fail' in statuses:
            verdict = 'fail'
        elif 'warn' in statuses:
            verdict = 'warn'
        else:
            verdict = 'pass'
        out[framework] = {
            'verdict': verdict,
            'controls': controls,
            'certificate_failures': sum(1 for r in cert_results if r[framework] == 'fail'),
            'certificate_warnings': sum(1 for r in cert_results if r[framework] == 'warn'),
        }
    return out
