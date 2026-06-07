"""Centralised configuration for the PKI Agentic system.

All tunables come from environment variables so the same codebase runs both
locally and on serverless platforms (Vercel, Lambda, etc.) without code changes.

On Vercel only /tmp is writable.  When IS_SERVERLESS is True every path that
the application writes to is remapped under TMP_BASE, and the bundled seed
files (data/inventory.json, data/hosts.json) are copied there on cold start so
the app always has something to work with.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

# ---------------------------------------------------------------------------
# Serverless detection
# ---------------------------------------------------------------------------

IS_SERVERLESS: bool = os.getenv("VERCEL", "") == "1" or os.getenv("AWS_LAMBDA_FUNCTION_NAME", "") != ""

# ---------------------------------------------------------------------------
# Base directories
# ---------------------------------------------------------------------------

# Repo root — the directory that contains this package
_REPO_ROOT = Path(__file__).parent.parent.resolve()

if IS_SERVERLESS:
    # /tmp is the only writable location on Vercel
    TMP_BASE = Path("/tmp/pki_agent")
else:
    TMP_BASE = _REPO_ROOT / ".runtime"

# Ensure writable directories exist at import time
for _d in ("logs", "data", "sample_reports"):
    (TMP_BASE / _d).mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Seed-file copy (serverless cold-start bootstrap)
# ---------------------------------------------------------------------------

def _copy_seed(src_rel: str, dst: Path) -> None:
    """Copy a bundled seed file to the writable /tmp tree if it doesn't exist."""
    if dst.exists():
        return
    src = _REPO_ROOT / src_rel
    if src.exists():
        shutil.copy2(src, dst)


if IS_SERVERLESS:
    _copy_seed("data/inventory.json", TMP_BASE / "data" / "inventory.json")
    _copy_seed("data/hosts.json",     TMP_BASE / "data" / "hosts.json")

# ---------------------------------------------------------------------------
# Resolved paths (always writable)
# ---------------------------------------------------------------------------

LOG_DIR:     Path = TMP_BASE / "logs"
REPORT_DIR:  Path = TMP_BASE / "sample_reports"
DATA_DIR:    Path = TMP_BASE / "data"

AUDIT_LOG_PATH:  Path = LOG_DIR  / "audit.log"
AUDIT_LOG:       Path = AUDIT_LOG_PATH
INVENTORY_PATH:  Path = DATA_DIR / "inventory.json"
INVENTORY_FILE:  Path = INVENTORY_PATH
HOSTS_PATH:      Path = DATA_DIR / "hosts.json"
HOSTS_FILE:      Path = HOSTS_PATH

# ---------------------------------------------------------------------------
# PKI / certificate tunables
# ---------------------------------------------------------------------------

EXPIRY_THRESHOLD_DAYS: int = int(os.getenv("PKI_EXPIRY_DAYS",    "45"))
CRITICAL_EXPIRY_DAYS:  int = int(os.getenv("PKI_CRITICAL_DAYS",   "7"))

# ---------------------------------------------------------------------------
# Firewall / port-scan tunables
# ---------------------------------------------------------------------------

# On Vercel we cap the scan range to keep the function inside the 30-second budget.
_default_port_start = "0"
_default_port_end   = "1024" if IS_SERVERLESS else "65000"
_default_timeout    = "0.2"  if IS_SERVERLESS else "0.4"
_default_workers    = "64"   if IS_SERVERLESS else "256"

SCAN_PORT_START:   int   = int(os.getenv("PKI_PORT_START",    _default_port_start))
SCAN_PORT_END:     int   = int(os.getenv("PKI_PORT_END",      _default_port_end))
SCAN_TIMEOUT:      float = float(os.getenv("PKI_SCAN_TIMEOUT", _default_timeout))
SCAN_WORKERS:      int   = int(os.getenv("PKI_SCAN_WORKERS",  _default_workers))
SCAN_DEMO_LIMIT: int = int(os.getenv("PKI_SCAN_DEMO_LIMIT", "16"))

# Only TCP/443 is permitted; every other reachable port is a policy violation.
ALLOWED_PORT: int = 443

# ---------------------------------------------------------------------------
# HSM
# ---------------------------------------------------------------------------

HSM_ENDPOINT: str = os.getenv("HSM_ENDPOINT", "https://hsm.local.example")
HSM_API_KEY:  str = os.getenv("HSM_API_KEY",  "")
HSM_VENDOR:   str = os.getenv("HSM_VENDOR",   "Entrust Shield")

# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

NOTIFY_WEBHOOK: str = os.getenv("PKI_NOTIFY_WEBHOOK", "")
NOTIFY_EMAIL: str = os.getenv("PKI_NOTIFY_EMAIL", "")

QUANTUM_SAFE_ALGORITHMS = [
    'ML-KEM',
    'ML-DSA',
    'SLH-DSA',
    'DILITHIUM',
    'KYBER',
    'FALCON',
    'SPHINCS',
]

# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

SCHEDULE_TIMES = {
    'daily_inventory': os.getenv('PKI_SCHEDULE_DAILY_INVENTORY', '04:00'),
    'weekly_firewall': os.getenv('PKI_SCHEDULE_WEEKLY_FIREWALL', '02:00'),
}

# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------

FLASK_SECRET: str = os.getenv("PKI_FLASK_SECRET", "pki-agentic-dev-key")