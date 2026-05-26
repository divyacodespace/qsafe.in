"""Autonomous scheduler.

Runs daily certificate inventory + risk evaluation and weekly firewall
sweeps in a daemon thread so the Flask app can serve a live dashboard
while the agent keeps working in the background.
"""

import threading
import time

import schedule

from .ai_agent import AutonomousAgent, RiskEngine
from .audit import AuditLogger
from .config import SCHEDULE_TIMES
from .discovery import CertificateInventory
from .notifier import Notifier
from .reporting import ReportManager
from .scanner import NetworkScanner


class Scheduler:
    def __init__(
        self,
        inventory: CertificateInventory,
        scanner: NetworkScanner,
        risk_engine: RiskEngine,
        report_manager: ReportManager,
        audit: AuditLogger,
        agent: AutonomousAgent = None,
        notifier: Notifier = None,
    ):
        self.inventory = inventory
        self.scanner = scanner
        self.risk_engine = risk_engine
        self.report_manager = report_manager
        self.audit = audit
        self.agent = agent or AutonomousAgent(risk_engine, audit)
        self.notifier = notifier or Notifier(audit)
        self.worker = None
        self._stop = threading.Event()

    # -- jobs ----------------------------------------------------------------

    def daily_inventory(self):
        certs = self.inventory.load_inventory()
        alerts = self.risk_engine.evaluate_certificate_inventory(certs)
        self.report_manager.generate_certificate_expiry_report(certs)
        critical = [a for a in alerts if a.severity in ('critical', 'high')]
        if critical:
            self.notifier.send(critical)
        self.audit.record('Scheduled certificate inventory completed',
                          metadata={'count': len(certs), 'alerts': len(alerts)})

    def weekly_firewall(self):
        results = self.scanner.perform_firewall_scan('127.0.0.1')
        self.report_manager.generate_firewall_report(results)
        alerts = self.risk_engine.evaluate_scan(results)
        critical = [a for a in alerts if a.severity in ('critical', 'high')]
        if critical:
            self.notifier.send(critical)
        self.audit.record('Scheduled firewall scan completed',
                          metadata={'results': len(results), 'alerts': len(alerts)})

    def agent_cycle(self):
        certs = self.inventory.load_inventory()
        scans = self.scanner.load_last_scan()
        decisions = self.agent.decide(certs, scans)
        self.report_manager.generate_agent_decisions_report(decisions)

    # -- lifecycle -----------------------------------------------------------

    def start(self):
        schedule.every().day.at(SCHEDULE_TIMES['daily_inventory']).do(self.daily_inventory)
        schedule.every().monday.at(SCHEDULE_TIMES['weekly_firewall']).do(self.weekly_firewall)
        schedule.every(6).hours.do(self.agent_cycle)
        self.worker = threading.Thread(target=self._run, daemon=True)
        self.worker.start()
        self.audit.record('Scheduler started', metadata=SCHEDULE_TIMES)

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            schedule.run_pending()
            time.sleep(15)
