"""Certificate discovery and inventory.

Loads a centralized inventory from ``data/inventory.json`` (so the system
works offline / in sandboxed environments) and can optionally probe live
TLS endpoints via the standard library. Each record is enriched with a
quantum-risk score from the threat model and compliance tags.
"""

import json
import ssl
import socket
from datetime import datetime
from typing import Iterable, List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import NameOID, ExtensionOID

from .audit import AuditLogger
from .config import EXPIRY_THRESHOLD_DAYS, CRITICAL_EXPIRY_DAYS, INVENTORY_FILE, HOSTS_FILE
from .models import CertificateRecord
from .threat_model import ThreatModel


def _not_after(cert: x509.Certificate) -> datetime:
    # cryptography>=42 prefers the UTC accessor; fall back for older builds.
    if hasattr(cert, 'not_valid_after_utc'):
        return cert.not_valid_after_utc.replace(tzinfo=None)
    return cert.not_valid_after


def _not_before(cert: x509.Certificate) -> datetime:
    if hasattr(cert, 'not_valid_before_utc'):
        return cert.not_valid_before_utc.replace(tzinfo=None)
    return cert.not_valid_before


def _public_key_info(cert: x509.Certificate):
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return 'RSA', pk.key_size
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return f'EC-{pk.curve.name}', pk.curve.key_size
    if isinstance(pk, dsa.DSAPublicKey):
        return 'DSA', pk.key_size
    return type(pk).__name__, getattr(pk, 'key_size', 0)


def _sans(cert: x509.Certificate) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return [name.value for name in ext.value]
    except x509.ExtensionNotFound:
        return []


def _recommendation(days_remaining: int) -> str:
    if days_remaining <= 0:
        return 'replace immediately'
    if days_remaining <= CRITICAL_EXPIRY_DAYS:
        return 'renew within 24h'
    if days_remaining <= EXPIRY_THRESHOLD_DAYS:
        return 'renew now'
    return 'monitor'


def _status(days_remaining: int) -> str:
    if days_remaining <= 0:
        return 'expired'
    if days_remaining <= CRITICAL_EXPIRY_DAYS:
        return 'critical'
    if days_remaining <= EXPIRY_THRESHOLD_DAYS:
        return 'expiring'
    return 'active'


class CertificateInventory:
    """Combines a JSON-backed inventory with live probing of TLS endpoints."""

    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        self.audit = audit_logger
        self.threat = ThreatModel()
        self.inventory_file = INVENTORY_FILE
        self.hosts_file = HOSTS_FILE

    # -- inventory persistence ----------------------------------------------------

    def load_inventory(self) -> List[CertificateRecord]:
        if not self.inventory_file.exists():
            return []
        try:
            raw = json.loads(self.inventory_file.read_text(encoding='utf-8'))
        except json.JSONDecodeError:
            return []
        records = [self._hydrate(item) for item in raw]
        return [self._refresh(r) for r in records]

    def save_inventory(self, records: Iterable[CertificateRecord]) -> None:
        data = [r.to_dict() for r in records]
        self.inventory_file.write_text(json.dumps(data, indent=2, default=str), encoding='utf-8')
        if self.audit:
            self.audit.record('Inventory persisted', metadata={'count': len(data)})

    def _hydrate(self, item: dict) -> CertificateRecord:
        not_before = datetime.fromisoformat(item['not_before'].rstrip('Z'))
        not_after = datetime.fromisoformat(item['not_after'].rstrip('Z'))
        return CertificateRecord(
            name=item['name'],
            domain=item['domain'],
            issuer=item['issuer'],
            not_before=not_before,
            not_after=not_after,
            days_remaining=item.get('days_remaining', 0),
            serial_number=item['serial_number'],
            fingerprint=item['fingerprint'],
            status=item.get('status', 'active'),
            recommendations=item.get('recommendations', 'monitor'),
            key_algorithm=item.get('key_algorithm', 'RSA'),
            key_size=item.get('key_size', 2048),
            signature_algorithm=item.get('signature_algorithm', 'SHA256withRSA'),
            san=item.get('san', []),
            source=item.get('source', 'inventory'),
            quantum_risk=item.get('quantum_risk', 'medium'),
            quantum_score=item.get('quantum_score', 50),
            compliance_tags=item.get('compliance_tags', []),
        )

    def _refresh(self, record: CertificateRecord) -> CertificateRecord:
        # Recompute the lifecycle fields against the current clock so the
        # inventory stays meaningful even when the JSON is months old.
        days_remaining = (record.not_after - datetime.utcnow()).days
        record.days_remaining = days_remaining
        record.status = _status(days_remaining)
        record.recommendations = _recommendation(days_remaining)
        score = self.threat.score_certificate(record.key_algorithm, record.key_size)
        record.quantum_risk = score['classification']
        record.quantum_score = score['score']
        return record

    # -- live probing -------------------------------------------------------------

    def load_hosts(self) -> List[str]:
        if self.hosts_file.exists():
            try:
                return json.loads(self.hosts_file.read_text(encoding='utf-8'))
            except json.JSONDecodeError:
                return []
        return []

    def discover_endpoints(self, hosts: Iterable[str], port: int = 443, timeout: float = 4.0) -> List[CertificateRecord]:
        records = []
        for host in hosts:
            try:
                pem = ssl.get_server_certificate((host, port), timeout=timeout)
                cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
                records.append(self._from_x509(host, cert))
                if self.audit:
                    self.audit.record('Discovered certificate', metadata={'host': host})
            except (socket.gaierror, socket.timeout, ConnectionError, ssl.SSLError, OSError) as exc:
                if self.audit:
                    self.audit.record(
                        'Certificate discovery failed', severity='warning',
                        metadata={'host': host, 'error': str(exc)},
                    )
        return records

    def _from_x509(self, host: str, cert: x509.Certificate) -> CertificateRecord:
        not_before = _not_before(cert)
        not_after = _not_after(cert)
        days_remaining = (not_after - datetime.utcnow()).days
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        fp = cert.fingerprint(hashes.SHA256()).hex().upper()
        algorithm, key_size = _public_key_info(cert)
        sig_alg = cert.signature_hash_algorithm.name.upper() + 'with' + algorithm if cert.signature_hash_algorithm else algorithm
        score = self.threat.score_certificate(algorithm, key_size)
        record = CertificateRecord(
            name=subject_cn[0].value if subject_cn else host,
            domain=host,
            issuer=issuer_cn[0].value if issuer_cn else 'Unknown',
            not_before=not_before,
            not_after=not_after,
            days_remaining=days_remaining,
            serial_number=format(cert.serial_number, 'x').upper(),
            fingerprint=':'.join(fp[i:i + 2] for i in range(0, len(fp), 2)),
            status=_status(days_remaining),
            recommendations=_recommendation(days_remaining),
            key_algorithm=algorithm,
            key_size=key_size,
            signature_algorithm=sig_alg,
            san=_sans(cert),
            source='discovery',
            quantum_risk=score['classification'],
            quantum_score=score['score'],
            compliance_tags=['PCI-DSS', 'ISO 27001'],
        )
        return record

    def merge_live_into_inventory(self, hosts: List[str]) -> List[CertificateRecord]:
        live = self.discover_endpoints(hosts)
        if not live:
            return self.load_inventory()
        existing = {rec.domain: rec for rec in self.load_inventory()}
        for rec in live:
            existing[rec.domain] = rec
        merged = list(existing.values())
        self.save_inventory(merged)
        return merged
