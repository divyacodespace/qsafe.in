"""Central configuration for the PKI agentic AI system.

All tunables, paths, and integration endpoints are kept here so individual
modules stay free of hard-coded values. Environment variables override
sensible defaults to keep the system portable across dev, staging and prod.

Serverless support: when running on Vercel / AWS Lambda the project
directory is read-only, so writable artifacts (audit log, generated
reports, mutable inventory) are redirected to ``/tmp/pki_agent/...`` and
the seed data is copied over on cold start.
"""

import os
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

IS_SERVERLESS = bool(os.getenv('VERCEL') or os.getenv('AWS_LAMBDA_FUNCTION_NAME'))

# Read-only seed directories that always live alongside the source.
SEED_DATA_DIR = BASE_DIR / 'data'
SEED_REPORT_DIR = BASE_DIR / 'sample_reports'

if IS_SERVERLESS:
    _RUNTIME_ROOT = Path('/tmp/pki_agent')
    DATA_DIR = _RUNTIME_ROOT / 'data'
    REPORT_DIR = _RUNTIME_ROOT / 'sample_reports'
    LOG_DIR = _RUNTIME_ROOT / 'logs'
    for _d in (DATA_DIR, REPORT_DIR, LOG_DIR):
        _d.mkdir(parents=True, exist_ok=True)
    # Cold-start seeding so the dashboard has data the first time it loads.
    for _src_dir, _dst_dir in ((SEED_DATA_DIR, DATA_DIR), (SEED_REPORT_DIR, REPORT_DIR)):
        if _src_dir.exists():
            for _src in _src_dir.iterdir():
                _dst = _dst_dir / _src.name
                if _src.is_file() and not _dst.exists():
                    try:
                        shutil.copy2(_src, _dst)
                    except OSError:
                        pass
else:
    DATA_DIR = SEED_DATA_DIR
    REPORT_DIR = SEED_REPORT_DIR
    LOG_DIR = BASE_DIR / 'logs'
    for _d in (DATA_DIR, REPORT_DIR, LOG_DIR):
        _d.mkdir(parents=True, exist_ok=True)

AUDIT_LOG = LOG_DIR / 'audit.log'
INVENTORY_FILE = DATA_DIR / 'inventory.json'
HOSTS_FILE = DATA_DIR / 'hosts.json'

EXPIRY_THRESHOLD_DAYS = int(os.getenv('PKI_EXPIRY_DAYS', '45'))
CRITICAL_EXPIRY_DAYS = int(os.getenv('PKI_CRITICAL_DAYS', '7'))

# The single port permitted by the firewall policy. Override with
# PKI_ALLOWED_PORT to switch to e.g. HTTPS/443.
ALLOWED_PORT = int(os.getenv('PKI_ALLOWED_PORT', '403'))

SCAN_PORT_START = int(os.getenv('PKI_PORT_START', '0'))
SCAN_PORT_END = int(os.getenv('PKI_PORT_END', '65000' if not IS_SERVERLESS else '1024'))
SCAN_PORT_RANGE = (SCAN_PORT_START, SCAN_PORT_END)
SCAN_TIMEOUT = float(os.getenv('PKI_SCAN_TIMEOUT', '0.4' if not IS_SERVERLESS else '0.2'))
SCAN_WORKERS = int(os.getenv('PKI_SCAN_WORKERS', '256' if not IS_SERVERLESS else '64'))
SCAN_DEMO_LIMIT = int(os.getenv('PKI_SCAN_DEMO_LIMIT', '4096' if not IS_SERVERLESS else '1024'))
EXCLUDE_PORTS = {ALLOWED_PORT}

SCHEDULE_TIMES = {
    'daily_inventory': os.getenv('PKI_SCHEDULE_INVENTORY', '03:00'),
    'weekly_firewall': os.getenv('PKI_SCHEDULE_FIREWALL', '04:00'),
}

HSM_ENDPOINT = os.getenv('HSM_ENDPOINT', 'https://hsm.local.example')
HSM_API_KEY = os.getenv('HSM_API_KEY', '')
HSM_VENDOR = os.getenv('HSM_VENDOR', 'Entrust Shield HSM')

NOTIFY_WEBHOOK = os.getenv('PKI_NOTIFY_WEBHOOK', '')
NOTIFY_EMAIL = os.getenv('PKI_NOTIFY_EMAIL', '')

COMPLIANCE_FRAMEWORKS = ('PCI-DSS', 'HIPAA', 'ISO 27001', 'SOC 2', 'NIST 800-53')

QUANTUM_SAFE_ALGORITHMS = {
    'ML-DSA', 'ML-KEM', 'Dilithium', 'Kyber', 'Falcon', 'SPHINCS+', 'XMSS', 'LMS',
}
