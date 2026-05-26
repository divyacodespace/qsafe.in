"""Structured audit logging.

Every certificate lifecycle event, scan, and agent decision is appended as a
JSON line to ``logs/audit.log`` so it can be tailed by SIEM tooling or
rendered directly in the web UI.
"""

import json
import logging
from datetime import datetime
from typing import List, Dict, Any

from .config import AUDIT_LOG


class AuditLogger:
    def __init__(self):
        self.path = AUDIT_LOG
        self.logger = logging.getLogger('pki_agent_audit')
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.FileHandler(self.path, encoding='utf-8')
            handler.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(handler)

    def record(self, action: str, severity: str = 'info', metadata: Dict[str, Any] = None) -> dict:
        payload = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'action': action,
            'severity': severity,
            'metadata': metadata or {},
        }
        self.logger.info(json.dumps(payload, default=str))
        return payload

    def tail(self, limit: int = 200) -> List[dict]:
        if not self.path.exists():
            return []
        with self.path.open('r', encoding='utf-8') as fh:
            lines = fh.readlines()
        out = []
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append({'timestamp': '', 'action': line, 'severity': 'info', 'metadata': {}})
        return list(reversed(out))
