"""Agentic AI orchestration.

The risk engine evaluates certificates and firewall results, and the
agent decides which actions to take (renew/replace, alert, escalate,
auto-rotate via HSM, file a change request, etc.) based on configurable
thresholds and confidence scores.

This intentionally avoids any LLM dependency so it runs deterministically
inside enterprise networks; it can be swapped for an LLM-backed planner by
implementing the same ``decide`` interface.
"""

from datetime import datetime
from typing import Iterable, List

from .audit import AuditLogger
from .config import CRITICAL_EXPIRY_DAYS, EXPIRY_THRESHOLD_DAYS
from .models import AgentDecision, AlertRecord, CertificateRecord, ScanResult


class RiskEngine:
    """Score certificates and scans, emit alerts."""

    def __init__(self, audit_logger: AuditLogger = None):
        self.audit = audit_logger

    def evaluate_certificate(self, cert: CertificateRecord) -> AlertRecord:
        if cert.days_remaining <= 0:
            severity = 'critical'
            description = (
                f'{cert.domain} expired {abs(cert.days_remaining)} day(s) ago. '
                'Service-impacting outage risk — replace immediately.'
            )
        elif cert.days_remaining <= CRITICAL_EXPIRY_DAYS:
            severity = 'critical'
            description = f'{cert.domain} expires in {cert.days_remaining} day(s). Renew within 24h.'
        elif cert.days_remaining <= EXPIRY_THRESHOLD_DAYS:
            severity = 'high'
            description = f'{cert.domain} expires in {cert.days_remaining} day(s) (≤ {EXPIRY_THRESHOLD_DAYS} threshold).'
        elif cert.quantum_score >= 70:
            severity = 'medium'
            description = (
                f'{cert.domain} uses {cert.key_algorithm}-{cert.key_size}, quantum-risk {cert.quantum_risk}. '
                'Plan PQC migration.'
            )
        else:
            severity = 'low'
            description = f'{cert.domain} healthy ({cert.days_remaining} days remaining).'
        return AlertRecord(
            title=f'Certificate {cert.domain}',
            severity=severity,
            description=description,
            source='certificate_monitor',
            metadata=cert.to_dict(),
        )

    def evaluate_certificate_inventory(self, certs: Iterable[CertificateRecord]) -> List[AlertRecord]:
        return [self.evaluate_certificate(c) for c in certs]

    def evaluate_scan(self, scans: Iterable[ScanResult]) -> List[AlertRecord]:
        """Policy: only TCP/443 is permitted; every other open or filtered
        port is reported as a policy violation with detailed context."""
        alerts: List[AlertRecord] = []
        for scan in scans:
            if not scan.policy_violation:
                continue
            description = (
                f'{(scan.service or "unknown service").upper()} on TCP/{scan.port} '
                f'is {scan.state}. Class: {scan.vulnerability_class or "n/a"}. '
                f'{scan.vulnerability_description or ""}'
            )
            alerts.append(AlertRecord(
                title=f'Policy violation TCP/{scan.port} on {scan.host}',
                severity=scan.risk,
                description=description.strip(),
                source='firewall_scan',
                metadata=scan.to_dict(),
            ))
        return alerts


class AutonomousAgent:
    """Reads alerts and decides what to do about them."""

    def __init__(self, risk_engine: RiskEngine, audit_logger: AuditLogger = None):
        self.risk_engine = risk_engine
        self.audit = audit_logger
        self.decisions: List[AgentDecision] = []

    def decide(
        self,
        certs: Iterable[CertificateRecord],
        scans: Iterable[ScanResult],
    ) -> List[AgentDecision]:
        decisions: List[AgentDecision] = []
        certs = list(certs)
        scans = list(scans)
        for cert in certs:
            decisions.extend(self._decide_certificate(cert))
        for scan in scans:
            d = self._decide_port(scan)
            if d:
                decisions.append(d)
        decisions.append(self._decide_quantum_posture(certs))
        self.decisions = decisions
        if self.audit:
            self.audit.record('Agent decisions emitted', metadata={'count': len(decisions)})
        return decisions

    def _decide_certificate(self, cert: CertificateRecord) -> List[AgentDecision]:
        out: List[AgentDecision] = []
        if cert.days_remaining <= 0:
            out.append(AgentDecision(
                action='replace_certificate',
                target=cert.domain,
                rationale=f'Expired {abs(cert.days_remaining)} day(s) ago — production traffic is at risk.',
                confidence=0.99, severity='critical', automated=True,
                metadata={'serial': cert.serial_number, 'issuer': cert.issuer},
            ))
        elif cert.days_remaining <= CRITICAL_EXPIRY_DAYS:
            out.append(AgentDecision(
                action='trigger_renewal',
                target=cert.domain,
                rationale=f'Expires in {cert.days_remaining} day(s); auto-renew via HSM-signed CSR.',
                confidence=0.95, severity='critical', automated=True,
                metadata={'serial': cert.serial_number},
            ))
        elif cert.days_remaining <= EXPIRY_THRESHOLD_DAYS:
            out.append(AgentDecision(
                action='schedule_renewal',
                target=cert.domain,
                rationale=f'Expires in {cert.days_remaining} day(s); within {EXPIRY_THRESHOLD_DAYS}-day window.',
                confidence=0.9, severity='high', automated=False,
                metadata={'serial': cert.serial_number},
            ))
        if cert.quantum_score >= 70:
            out.append(AgentDecision(
                action='plan_pqc_migration',
                target=cert.domain,
                rationale=(
                    f'{cert.key_algorithm}-{cert.key_size} is broken by Shor; '
                    'queue hybrid ML-KEM/ML-DSA pilot.'
                ),
                confidence=0.85, severity='medium', automated=False,
                metadata={'quantum_score': cert.quantum_score, 'classification': cert.quantum_risk},
            ))
        return out

    def _decide_port(self, scan: ScanResult):
        if not scan.policy_violation:
            return None
        rationale = (
            f'Policy permits only TCP/443. {(scan.service or "unknown service").upper()} on '
            f'TCP/{scan.port} is {scan.state}: {scan.vulnerability_class or "non-compliant exposure"}. '
            f'{scan.mitigation or ""}'
        ).strip()
        if scan.state == 'open':
            return AgentDecision(
                action='block_port',
                target=f'{scan.host}:{scan.port}',
                rationale=rationale,
                confidence=0.95, severity='critical', automated=False,
                metadata=scan.to_dict(),
            )
        return AgentDecision(
            action='harden_filtered_port',
            target=f'{scan.host}:{scan.port}',
            rationale=rationale,
            confidence=0.8, severity='high', automated=False,
            metadata=scan.to_dict(),
        )

    def _decide_quantum_posture(self, certs: List[CertificateRecord]) -> AgentDecision:
        if not certs:
            return AgentDecision(
                action='quantum_posture_review',
                target='estate',
                rationale='No certificates inventoried yet; bootstrap discovery to evaluate Shor exposure.',
                confidence=0.6, severity='low',
            )
        vulnerable = [c for c in certs if c.quantum_score >= 70]
        ratio = len(vulnerable) / len(certs)
        if ratio == 0:
            return AgentDecision(
                action='quantum_posture_review',
                target='estate',
                rationale='All inventoried certificates are quantum-safe — maintain hybrid posture.',
                confidence=0.9, severity='low',
            )
        severity = 'critical' if ratio > 0.5 else 'high' if ratio > 0.2 else 'medium'
        return AgentDecision(
            action='accelerate_pqc_migration',
            target='estate',
            rationale=(
                f'{len(vulnerable)} of {len(certs)} certificates are Shor-vulnerable '
                f'({ratio:.0%}). Prioritize CA hierarchy and externally-facing endpoints.'
            ),
            confidence=0.88, severity=severity,
            metadata={'vulnerable_domains': [c.domain for c in vulnerable]},
        )
