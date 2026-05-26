"""Network / firewall scanner with a strict 443-only exposure policy.

Policy
------
Only TCP/443 (HTTPS) is permitted to be reachable from outside the host.
Every other port that is *open* or *filtered* is flagged as a
**policy violation** and enriched with detailed vulnerability intelligence
(class, description, attack vector, mitigation, references) so the report
the user receives is actionable and audit-grade.

Closed ports are normal and are summarised but not enumerated by default
to keep the dashboard readable.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple

from .audit import AuditLogger
from .config import (
    SCAN_DEMO_LIMIT,
    SCAN_PORT_END,
    SCAN_PORT_START,
    SCAN_TIMEOUT,
    SCAN_WORKERS,
)
from .models import ScanResult
from .vuln_intel import lookup as vuln_lookup

try:
    import nmap  # type: ignore
except ImportError:
    nmap = None


# The single permitted listener.
ALLOWED_PORT = 443


def _service_for(port: int) -> Optional[str]:
    intel = vuln_lookup(port)
    svc = intel.get('service')
    if svc:
        return str(svc)
    try:
        return socket.getservbyport(port, 'tcp')
    except OSError:
        return None


class NetworkScanner:
    """Concurrent firewall scanner; enforces a 443-only exposure policy."""

    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        self.audit = audit_logger
        self.last_scan: List[ScanResult] = []
        self.last_meta: dict = {}

    # -- policy & classification -------------------------------------------------

    def classify(self, port: int, state: str) -> Tuple[str, bool, bool]:
        """Return (risk_label, intrusion_indicator, policy_violation).

        Policy: only TCP/443 may be open. Anything else that is open or
        filtered is a policy violation that must appear in the report.
        """
        if port == ALLOWED_PORT:
            if state == 'open':
                return 'low', False, False
            if state == 'closed':
                # HTTPS is the *expected* listener — closed is itself a finding,
                # though benign for an arbitrary scan target.
                return 'medium', False, False
            return 'medium', False, False
        # Any non-443 port:
        if state == 'open':
            return 'critical', True, True
        if state == 'filtered':
            return 'high', False, True
        return 'low', False, False  # closed → compliant

    def _build_result(self, host: str, port: int, state: str,
                       product: Optional[str] = None, version: Optional[str] = None,
                       notes: Optional[str] = None) -> ScanResult:
        risk, intrusion, violation = self.classify(port, state)
        if port == ALLOWED_PORT:
            return ScanResult(
                host=host, port=port, state=state,
                service='https', product=product, version=version,
                risk=risk, notes=notes or 'expected HTTPS listener (policy: only 443 allowed)',
                intrusion_indicator=intrusion, policy_violation=violation,
                vulnerability_class=None,
                vulnerability_description='HTTPS is the only permitted exposed service.',
                attack_vector=None,
                mitigation='Maintain TLS 1.2+; enforce HSTS preload; monitor cert lifecycle.',
                references=['NIST SP 800-52 r2', 'OWASP TLS Cheat Sheet'],
            )
        if state == 'closed':
            return ScanResult(
                host=host, port=port, state=state,
                service=None, product=product, version=version,
                risk=risk, notes='compliant (closed)', intrusion_indicator=intrusion,
                policy_violation=violation,
            )
        intel = vuln_lookup(port)
        return ScanResult(
            host=host, port=port, state=state,
            service=intel.get('service') or _service_for(port),
            product=product, version=version,
            risk=risk, notes=notes,
            intrusion_indicator=intrusion, policy_violation=violation,
            vulnerability_class=str(intel.get('class') or ''),
            vulnerability_description=str(intel.get('description') or ''),
            attack_vector=str(intel.get('attack_vector') or ''),
            mitigation=str(intel.get('mitigation') or ''),
            references=list(intel.get('references') or []),
        )

    # -- probing primitives ------------------------------------------------------

    def _probe(self, host: str, port: int, timeout: float) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                sock.connect((host, port))
                return 'open'
            except socket.timeout:
                return 'filtered'
            except (ConnectionRefusedError, OSError):
                return 'closed'

    def _scan_socket(self, host: str, start: int, end: int, timeout: float, workers: int) -> List[ScanResult]:
        ports = list(range(start, end + 1))
        results: List[ScanResult] = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self._probe, host, p, timeout): p for p in ports}
            for fut in as_completed(futures):
                port = futures[fut]
                state = fut.result()
                if state == 'closed' and port != ALLOWED_PORT:
                    continue  # compliant — omit from the report
                results.append(self._build_result(host, port, state, notes='socket-probe'))
        results.sort(key=lambda r: r.port)
        return results

    def _scan_nmap(self, host: str, start: int, end: int) -> List[ScanResult]:
        scanner = nmap.PortScanner()
        port_range = f'{start}-{end}'
        if self.audit:
            self.audit.record('Starting nmap scan', metadata={'host': host, 'range': port_range})
        scanner.scan(hosts=host, ports=port_range, arguments='-sV -T4 --open')
        results: List[ScanResult] = []
        if host not in scanner.all_hosts():
            return results
        host_data = scanner[host]
        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                meta = host_data[proto][port]
                state = meta.get('state', 'unknown')
                if state == 'closed' and port != ALLOWED_PORT:
                    continue
                results.append(self._build_result(
                    host, port, state,
                    product=meta.get('product') or None,
                    version=meta.get('version') or None,
                    notes='nmap',
                ))
        return results

    # -- public entry point ------------------------------------------------------

    def perform_firewall_scan(
        self,
        host: str = '127.0.0.1',
        start_port: int = SCAN_PORT_START,
        end_port: int = SCAN_PORT_END,
        timeout: float = SCAN_TIMEOUT,
        workers: int = SCAN_WORKERS,
        engine: str = 'auto',
    ) -> List[ScanResult]:
        if engine == 'auto':
            engine = 'nmap' if nmap is not None else 'socket'
        start_port = max(0, int(start_port))
        end_port = min(65535, int(end_port))
        if engine == 'socket' and (end_port - start_port) > SCAN_DEMO_LIMIT:
            end_port = start_port + SCAN_DEMO_LIMIT
        if self.audit:
            self.audit.record(
                'Firewall scan started',
                metadata={'host': host, 'start': start_port, 'end': end_port, 'engine': engine,
                          'policy': 'only TCP/443 allowed'},
            )
        t0 = time.time()
        try:
            if engine == 'nmap' and nmap is not None:
                results = self._scan_nmap(host, start_port, end_port)
            else:
                results = self._scan_socket(host, start_port, end_port, timeout, workers)
        except Exception as exc:  # pragma: no cover - defensive
            if self.audit:
                self.audit.record(
                    'Firewall scan failed', severity='error',
                    metadata={'host': host, 'error': str(exc)},
                )
            results = []
        elapsed = round(time.time() - t0, 2)
        self.last_scan = results
        violations = [r for r in results if r.policy_violation]
        self.last_meta = {
            'host': host,
            'start': start_port,
            'end': end_port,
            'engine': engine,
            'elapsed_seconds': elapsed,
            'policy': 'allow tcp/443 only',
            'total': len(results),
            'open': sum(1 for r in results if r.state == 'open'),
            'filtered': sum(1 for r in results if r.state == 'filtered'),
            'closed': sum(1 for r in results if r.state == 'closed'),
            'policy_violations': len(violations),
            'critical': sum(1 for r in violations if r.risk == 'critical'),
            'allowed_port_state': next(
                (r.state for r in results if r.port == ALLOWED_PORT),
                'not-scanned',
            ),
        }
        if self.audit:
            self.audit.record('Firewall scan completed', metadata=self.last_meta)
            for v in violations:
                self.audit.record(
                    f'Policy violation TCP/{v.port}',
                    severity='warning' if v.risk == 'high' else 'critical',
                    metadata={
                        'port': v.port, 'state': v.state, 'service': v.service,
                        'class': v.vulnerability_class,
                        'mitigation': v.mitigation,
                    },
                )
        return results

    def load_last_scan(self) -> List[ScanResult]:
        return self.last_scan

    def suspicious_findings(self) -> List[ScanResult]:
        """Everything reportable: every policy violation (i.e. anything not 443
        that is open or filtered)."""
        return [r for r in self.last_scan if r.policy_violation]
