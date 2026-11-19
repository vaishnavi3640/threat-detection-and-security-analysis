"""
General helper utilities for THREATGUARD.
"""
import os
import re
from datetime import datetime
from urllib.parse import urlparse


def get_domain(url: str) -> str:
    """Extract the netloc (host:port) from a URL."""
    try:
        return urlparse(url).netloc or url
    except Exception:
        return url


def get_hostname(url: str) -> str:
    """Extract just the hostname (without port) from a URL."""
    try:
        return urlparse(url).hostname or url
    except Exception:
        return url


def format_datetime(dt: datetime | None) -> str:
    """Return a human-readable datetime string."""
    if dt is None:
        return "N/A"
    return dt.strftime("%d %b %Y, %H:%M:%S UTC")


def severity_color(severity: str) -> str:
    """Return a CSS hex colour for a given severity level."""
    mapping = {
        "Critical": "#FF4444",
        "High": "#FF8C00",
        "Medium": "#FFD700",
        "Low": "#00BFFF",
        "Informational": "#90EE90",
    }
    return mapping.get(severity, "#AAAAAA")


def severity_order(severity: str) -> int:
    """Return a sort key for severity (lower = more severe)."""
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    return order.get(severity, 99)


def score_color(score: float) -> str:
    """Return a colour based on numeric score."""
    if score >= 80:
        return "#00C851"   # green
    elif score >= 60:
        return "#FFD700"   # amber
    elif score >= 40:
        return "#FF8C00"   # orange
    else:
        return "#FF4444"   # red


def score_label(score: float) -> str:
    """Return a text label for a numeric score."""
    if score >= 80:
        return "Good"
    elif score >= 60:
        return "Fair"
    elif score >= 40:
        return "Poor"
    else:
        return "Critical"


def ensure_outputs_dir() -> str:
    """Create and return the outputs/ directory path."""
    out = os.path.join(os.path.dirname(os.path.dirname(__file__)), "outputs")
    os.makedirs(out, exist_ok=True)
    return out


def report_filename(url: str, scan_id: int) -> str:
    """Generate a safe filename for a PDF report."""
    domain = re.sub(r"[^a-zA-Z0-9_-]", "_", get_hostname(url))
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return f"threatguard_report_{domain}_{ts}_scan{scan_id}.pdf"


def truncate(text: str, max_len: int = 120) -> str:
    """Truncate a string to max_len characters."""
    if not text:
        return ""
    return text if len(text) <= max_len else text[:max_len - 3] + "..."
