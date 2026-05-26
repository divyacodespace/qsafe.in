"""Vercel entrypoint.

Re-exports the Flask app so the @vercel/python builder can serve it.
Every HTTP route in :mod:`app` (Dashboard, /api/status, /ports, etc.) is
reachable through this single handler — `vercel.json` rewrites all paths
here.
"""

import os
import sys
from pathlib import Path

# Add the project root to sys.path so `import app` works regardless of
# the working directory the runtime chooses.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Force serverless mode even if the platform doesn't set VERCEL=1.
os.environ.setdefault('VERCEL', '1')

from app import app  # noqa: E402  Flask WSGI application

# @vercel/python looks for a WSGI-compatible callable named `app`.
__all__ = ['app']
