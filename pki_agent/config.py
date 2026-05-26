"""Central configuration for the PKI agentic AI system.

All tunables, paths, and integration endpoints are kept here so individual
modules stay free of hard-coded values. Environment variables override
sensible defaults to keep the system portable across dev, staging and prod.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / 'data'
REPORT_DIR = BASE_DIR / 'sample_reports'
LOG_DIR = BASE_DIR / 'logs'
AUDIT_LOG = LOG_DIR / 'audit.log'
INVENTORY_FILE = DATA_DIR / 'inventory.json'
HOSTS_FILE = DATA_DIR / 'hosts.json'

for _d in (DATA_DIR, REPORT_DIR, LOG_DIR):
    _d.mkdir(parents=True, exist_ok=True)

EXPIRY_THRESHOLD_DAYS = int(os.getenv('PKI_EXPIRY_DAYS', '45'))
CRITICAL_EXPIRY_DAYS = int(os.getenv('PKI_CRITICAL_DAYS', '7'))

SCAN_PORT_START = int(os.getenv('PKI_PORT_START', '0'))
SCAN_PORT_END = int(os.getenv('PKI_PORT_END', '65000'))
SCAN_PORT_RANGE = (SCAN_PORT_START, SCAN_PORT_END)
SCAN_TIMEOUT = float(os.getenv('PKI_SCAN_TIMEOUT', '0.4'))
SCAN_WORKERS = int(os.getenv('PKI_SCAN_WORKERS', '256'))
SCAN_DEMO_LIMIT = int(os.getenv('PKI_SCAN_DEMO_LIMIT', '4096'))
EXCLUDE_PORTS = {443}

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
