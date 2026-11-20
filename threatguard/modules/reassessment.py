"""
Reassessment module for THREATGUARD.

Compares two scans of the same website and identifies:
  - Resolved findings (present in old scan, absent in new scan)
  - New findings    (absent in old scan, present in new scan)
  - Remaining findings (present in both scans)
  - Score deltas
"""
from __future__ import annotations
from database.db import get_session
from database.models import Scan, Finding, Website


def get_scans_for_url(url: str, user_id: int | None = None) -> list[dict]:
    """
    Return all completed scans for a given URL, ordered newest first.

    Returns
    -------
    list of dicts with keys: id, scan_date, security_score, privacy_score,
        trust_score, total_findings
    """
    db = get_session()
    try:
        website_query = db.query(Website).filter(Website.website_url == url)
        if user_id is not None:
            website_query = website_query.filter(Website.user_id == user_id)
        websites = website_query.all()
        website_ids = [w.id for w in websites]
        if not website_ids:
            return []

        scans = (
            db.query(Scan)
            .filter(
                Scan.website_id.in_(website_ids),
                Scan.scan_status == "completed",
            )
            .order_by(Scan.scan_date.desc())
            .all()
        )

        return [
            {
                "id": s.id,
                "scan_date": s.scan_date,
                "security_score": s.security_score,
                "privacy_score": s.privacy_score,
                "trust_score": s.trust_score,
                "total_findings": s.total_findings,
            }
            for s in scans
        ]
    finally:
        db.close()


def get_findings_for_scan(scan_id: int) -> list[dict]:
    """Return all findings for a given scan ID."""
    db = get_session()
    try:
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        return [
            {
                "id": f.id,
                "finding_name": f.finding_name,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "evidence": f.evidence,
                "impact": f.impact,
                "recommendation": f.recommendation,
            }
            for f in findings
        ]
    finally:
        db.close()


def compare_scans(old_scan_id: int, new_scan_id: int) -> dict:
    """
    Compare two scans and return a comparison report.

    Returns
    -------
    dict with keys:
        old_scan, new_scan,
        resolved, new_findings, remaining,
        security_delta, privacy_delta, trust_delta
    """
    db = get_session()
    try:
        old_scan = db.query(Scan).filter(Scan.id == old_scan_id).first()
        new_scan = db.query(Scan).filter(Scan.id == new_scan_id).first()

        if not old_scan or not new_scan:
            return {"error": "One or both scans not found."}

        old_findings = get_findings_for_scan(old_scan_id)
        new_findings = get_findings_for_scan(new_scan_id)

        # Use finding_name as the comparison key
        old_names = {f["finding_name"] for f in old_findings}
        new_names = {f["finding_name"] for f in new_findings}

        resolved_names = old_names - new_names
        new_names_only = new_names - old_names
        remaining_names = old_names & new_names

        resolved = [f for f in old_findings if f["finding_name"] in resolved_names]
        new_only = [f for f in new_findings if f["finding_name"] in new_names_only]
        remaining = [f for f in new_findings if f["finding_name"] in remaining_names]

        return {
            "old_scan": {
                "id": old_scan.id,
                "date": old_scan.scan_date,
                "security_score": old_scan.security_score,
                "privacy_score": old_scan.privacy_score,
                "trust_score": old_scan.trust_score,
                "total_findings": old_scan.total_findings,
            },
            "new_scan": {
                "id": new_scan.id,
                "date": new_scan.scan_date,
                "security_score": new_scan.security_score,
                "privacy_score": new_scan.privacy_score,
                "trust_score": new_scan.trust_score,
                "total_findings": new_scan.total_findings,
            },
            "resolved": resolved,
            "new_findings": new_only,
            "remaining": remaining,
            "security_delta": round(new_scan.security_score - old_scan.security_score, 1),
            "privacy_delta": round(new_scan.privacy_score - old_scan.privacy_score, 1),
            "trust_delta": round(new_scan.trust_score - old_scan.trust_score, 1),
        }
    finally:
        db.close()
