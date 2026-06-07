"""Vercel serverless entrypoint.

Vercel's @vercel/python builder imports this module and looks for a WSGI
callable named `app`.  All we do here is import the Flask application that
lives in app.py at the repo root and re-export it under that name.

The environment variable VERCEL=1 is set in vercel.json, so config.py will
automatically:
  - redirect every write to /tmp/pki_agent/
  - copy seed files (inventory.json, hosts.json) to /tmp on cold start
  - disable the background scheduler
"""

import sys
import os
from pathlib import Path

# Make the repo root importable (Vercel sets cwd to the repo root, but
# adding it explicitly makes the entrypoint robust to edge cases).
_repo_root = Path(__file__).parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

# Import the Flask app — this triggers config.py which handles /tmp setup.
from app import app  # noqa: E402  (import not at top of file)

# Vercel looks for a symbol called `app` in this module.
__all__ = ["app"]