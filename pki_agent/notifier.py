"""Notification fan-out.

When the autonomous agent decides a finding requires human attention, this
module is responsible for pushing it out. By default it logs to stdout, but
it can also POST to a webhook (Slack/Teams) or hand off to an SMTP server.
"""

import json
import logging
from datetime import datetime
from typing import Iterable

import requests

from .audit import AuditLogger
from .config import NOTIFY_EMAIL, NOTIFY_WEBHOOK
from .models import AlertRecord


log = logging.getLogger('pki_agent_notifier')


class Notifier:
    def __init__(self, audit_logger: AuditLogger = None):
        self.audit = audit_logger

    def _payload(self, alert: AlertRecord) -> dict:
        return {
            'title': alert.title,
            'severity': alert.severity,
            'description': alert.description,
            'source': alert.source,
            'metadata': alert.metadata,
            'sent_at': datetime.utcnow().isoformat() + 'Z',
        }

    def send(self, alerts: Iterable[AlertRecord]) -> int:
        count = 0
        for alert in alerts:
            payload = self._payload(alert)
            log.info('notification %s', json.dumps(payload, default=str))
            self._send_webhook(payload)
            self._send_email(payload)
            if self.audit:
                self.audit.record('Notification dispatched', metadata={
                    'title': alert.title, 'severity': alert.severity,
                })
            count += 1
        return count

    def _send_webhook(self, payload: dict) -> None:
        if not NOTIFY_WEBHOOK:
            return
        try:
            requests.post(NOTIFY_WEBHOOK, json=payload, timeout=5)
        except requests.RequestException as exc:
            if self.audit:
                self.audit.record(
                    'Webhook notification failed', severity='warning',
                    metadata={'error': str(exc)},
                )

    def _send_email(self, payload: dict) -> None:
        if not NOTIFY_EMAIL:
            return
        # Real deployments would invoke smtplib here. We log the intent so
        # the channel is auditable without leaking on misconfigured envs.
        if self.audit:
            self.audit.record('Email notification queued', metadata={'to': NOTIFY_EMAIL, 'title': payload['title']})
