"""
api/index.py — Vercel serverless entry point for PhishShield NG.

Vercel's @vercel/python builder looks for an `app` (WSGI) object in this file.
Flask is WSGI-compatible, so we simply create and expose the Flask app here.

Notes for Vercel deployment:
- The filesystem is read-only except /tmp. SQLite is routed to /tmp/phishing.db
  so scan history works within a single request; it resets between cold starts.
- Model artifacts (model.joblib, meta.json) must be committed to the repository
  so Vercel bundles them into the deployment package.
- Set FLASK_ENV=production in Vercel environment variables.
"""

import sys
import os
from pathlib import Path

# Add the project root to sys.path so backend imports resolve correctly
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))

# Point SQLite to /tmp on Vercel (writable) — override before app creation
# On Vercel the filesystem is read-only outside /tmp
if os.environ.get("VERCEL"):
    os.environ.setdefault("DATABASE_PATH", "/tmp/phishing.db")

# Import and create the Flask app
from backend.app import create_app  # noqa: E402

app = create_app()

app = create_app()
