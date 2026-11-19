#!/usr/bin/env python3
"""
Start script for THREATGUARD Flask backend.
Runs from project root so threatguard module imports work correctly.
"""
import os
import sys

# Project root = one level above this script
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
THREATGUARD_DIR = os.path.join(PROJECT_ROOT, "threatguard")

# Add threatguard to path so its modules can be imported
sys.path.insert(0, THREATGUARD_DIR)
# Add backend dir to path so we can import app.py from backend/
sys.path.insert(0, BACKEND_DIR)

# Load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BACKEND_DIR, ".env"))
except ImportError:
    pass

# Keep SQLite as the zero-configuration local default, but honor DATABASE_URL
# from the environment/.env (including MySQL URLs) when it is configured.
if not os.environ.get("DATABASE_URL"):
    db_path = os.path.join(THREATGUARD_DIR, "threatguard.db")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

# Import the Flask app from backend/app.py (not threatguard/app.py)
from app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print(f"\U0001f6e1\ufe0f  ThreatGuard API running on http://localhost:{port}")
    app.run(debug=debug, host=os.environ.get("HOST", "127.0.0.1"), port=port)
