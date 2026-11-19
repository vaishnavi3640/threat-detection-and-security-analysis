"""
Database engine, session factory and initialisation helpers.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from database.models import Base

# ── Resolve database path ──────────────────────────────────────────────────────
_DB_FILE = os.environ.get("DATABASE_URL", "sqlite:///threatguard.db")
# Support both "sqlite:///..." and plain file paths
if not _DB_FILE.startswith("sqlite"):
    _DB_FILE = f"sqlite:///{_DB_FILE}"

engine = create_engine(
    _DB_FILE,
    connect_args={"check_same_thread": False},  # Required for SQLite + Streamlit
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Create all tables if they do not already exist."""
    Base.metadata.create_all(bind=engine)


def get_session() -> Session:
    """Return a new SQLAlchemy session. Caller is responsible for closing it."""
    return SessionLocal()


def get_db():
    """Context-manager style session (for use with 'with' statements)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
