"""Data models used across the agent.

Each dataclass exposes ``to_dict`` so it can be serialized to JSON for the
web UI, audit log entries, and report generators without bespoke encoders.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional, Dict, Any


def _iso(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat() + 'Z'
    return value


@dataclass
class CertificateRecord:
    name: str
    domain: str
    issuer: str
    not_before: datetime
    not_after: datetime
    days_remaining: int
    serial_number: str
    fingerprint: str
    status: str
    recommendations: str
    key_algorithm: str = 'RSA'
    key_size: int = 2048
    signature_algorithm: str = 'SHA256withRSA'
    san: List[str] = field(default_factory=list)
    source: str = 'discovery'
    quantum_risk: str = 'medium'
    quantum_score: int = 50
    compliance_tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['not_before'] = _iso(self.not_before)
        data['not_after'] = _iso(self.not_after)
        return data


@dataclass
class ScanResult:
    host: str
    port: int
    state: str
    service: Optional[str]
    product: Optional[str]
    version: Optional[str]
    risk: str
    notes: Optional[str] = None
    intrusion_indicator: bool = False
    policy_violation: bool = False
    vulnerability_class: Optional[str] = None
    vulnerability_description: Optional[str] = None
    attack_vector: Optional[str] = None
    mitigation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AlertRecord:
    title: str
    severity: str
    description: str
    source: str
    metadata: dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['created_at'] = _iso(self.created_at)
        return data


@dataclass
class AgentDecision:
    """A single decision emitted by the autonomous agent."""
    action: str
    target: str
    rationale: str
    confidence: float
    severity: str
    automated: bool = False
    metadata: dict = field(default_factory=dict)
    decided_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['decided_at'] = _iso(self.decided_at)
        return data
