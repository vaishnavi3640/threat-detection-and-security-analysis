# startup script for the flask backend
import os
import sys

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
THREATGUARD_DIR = os.path.join(PROJECT_ROOT, "threatguard")

# add paths so python can find our modules
sys.path.insert(0, THREATGUARD_DIR)
sys.path.insert(0, BACKEND_DIR)

# default database location
if not os.environ.get("DATABASE_URL"):
    db_path = os.path.join(THREATGUARD_DIR, "threatguard.db")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

# load .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BACKEND_DIR, ".env"))
except ImportError:
    pass

from app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    print(f"ThreatGuard API running on http://localhost:{port}")
    app.run(debug=debug, host="0.0.0.0", port=port)
