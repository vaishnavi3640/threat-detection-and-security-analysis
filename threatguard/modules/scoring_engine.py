"""
Scoring engine for THREATGUARD.

Formulae
--------
Security Score = max(0, 100 - Σ security_penalties)
Privacy Score  = max(0, 100 - Σ privacy_penalties)
Trust Score    = (Security Score × 0.5) + (Privacy Score × 0.5)

Penalty values are taken from risk_classifier.SEVERITY_PENALTIES.
These are heuristic posture scores, not formal security guarantees.
"""
from __future__ import annotations
from modules.risk_classifier import SEVERITY_PENALTIES


def calculate_scores(findings: list[dict]) -> dict[str, float]:
    """
    Calculate Security, Privacy and Trust scores from a list of findings.

    Parameters
    ----------
    findings : list of dicts
        Each dict must contain at least 'severity' and 'category' keys.

    Returns
    -------
    dict with keys: security_score, privacy_score, trust_score
    """
    security_penalty = 0.0
    privacy_penalty = 0.0

    for f in findings:
        severity = f.get("severity", "Informational")
        category = f.get("category", "security")
        penalty = SEVERITY_PENALTIES.get(severity, 0.0)

        if category == "security":
            security_penalty += penalty
        elif category == "privacy":
            privacy_penalty += penalty

    security_score = max(0.0, 100.0 - security_penalty)
    privacy_score = max(0.0, 100.0 - privacy_penalty)
    trust_score = round((security_score * 0.5) + (privacy_score * 0.5), 1)

    return {
        "security_score": round(security_score, 1),
        "privacy_score": round(privacy_score, 1),
        "trust_score": trust_score,
    }


def get_severity_distribution(findings: list[dict]) -> dict[str, int]:
    """Count findings by severity level."""
    dist: dict[str, int] = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }
    for f in findings:
        sev = f.get("severity", "Informational")
        if sev in dist:
            dist[sev] += 1
    return dist


def get_category_distribution(findings: list[dict]) -> dict[str, int]:
    """Count findings by category."""
    dist: dict[str, int] = {"security": 0, "privacy": 0}
    for f in findings:
        cat = f.get("category", "security")
        dist[cat] = dist.get(cat, 0) + 1
    return dist


def top_recommendations(findings: list[dict], n: int = 5) -> list[dict]:
    """
    Return the top-N highest severity findings for the recommendations panel.
    Severity order: Critical > High > Medium > Low > Informational
    """
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    sorted_f = sorted(findings, key=lambda x: order.get(x.get("severity", "Informational"), 99))
    return sorted_f[:n]
