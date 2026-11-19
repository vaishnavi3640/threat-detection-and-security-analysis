#!/usr/bin/env python3
"""
Start script for THREATGUARD Flask backend.
Runs from project root so threatguard module imports work correctly.
"""
import os
import sys

# Project root = one level above this script
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
THREATGUARD_DIR = os.path.join(PROJECT_ROOT, "threatguard")

sys.path.insert(0, THREATGUARD_DIR)

# Set DATABASE_URL to use threatguard's DB file by default
if not os.environ.get("DATABASE_URL"):
    db_path = os.path.join(THREATGUARD_DIR, "threatguard.db")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

# Load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    pass

from app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    print(f"🛡️  ThreatGuard API running on http://localhost:{port}")
    app.run(debug=debug, host="0.0.0.0", port=port)
