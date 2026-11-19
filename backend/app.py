# Flask backend for ThreatGuard
# handles all API requests from the React frontend
from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os

# allow imports from threatguard folder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'threatguard'))

from database.db import init_db, get_session
from database.models import Website, Scan, Finding, Report
from modules.security_scanner import run_security_scan
from modules.privacy_analyzer import run_privacy_scan
from modules.scoring_engine import calculate_scores, get_severity_distribution, top_recommendations
from modules.ai_explainer import is_ai_available, explain_all_findings
from modules.report_generator import generate_pdf_report
from modules.reassessment import get_scans_for_url, compare_scans
from utils.validators import validate_url
from utils.helpers import format_datetime, severity_color, score_color, score_label, get_domain

import time

app = Flask(__name__)
CORS(app, origins=["http://localhost:3000", "http://localhost:5173"])

# create tables if they dont exist
init_db()


# ─── Health ──────────────────────────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})


# ─── Scan Website ─────────────────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True)
    url = (data or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400

    valid, result = validate_url(url)
    if not valid:
        return jsonify({"error": result}), 422

    url = result
    db = get_session()
    try:
        # Upsert website
        website = db.query(Website).filter_by(website_url=url).first()
        if not website:
            website = Website(website_url=url)
            db.add(website)
            db.commit()
            db.refresh(website)

        # Create scan record
        scan_obj = Scan(website_id=website.id, scan_status="running")
        db.add(scan_obj)
        db.commit()
        db.refresh(scan_obj)

        start = time.time()
        # Run scans
        sec_findings = run_security_scan(url)
        priv_findings = run_privacy_scan(url)
        all_findings = sec_findings + priv_findings

        scores = calculate_scores(all_findings)
        duration = time.time() - start

        # Update scan record
        scan_obj.security_score = scores["security_score"]
        scan_obj.privacy_score = scores["privacy_score"]
        scan_obj.trust_score = scores["trust_score"]
        scan_obj.scan_status = "completed"
        scan_obj.scan_duration = round(duration, 2)
        scan_obj.total_findings = len(all_findings)

        # Persist findings
        for f in all_findings:
            finding = Finding(
                scan_id=scan_obj.id,
                finding_name=f.get("finding_name", ""),
                category=f.get("category", ""),
                severity=f.get("severity", ""),
                confidence=f.get("confidence", ""),
                evidence=f.get("evidence", ""),
                impact=f.get("impact", ""),
                recommendation=f.get("recommendation", ""),
            )
            db.add(finding)

        db.commit()

        return jsonify({
            "scan_id": scan_obj.id,
            "url": url,
            "domain": get_domain(url),
            "security_score": round(scores["security_score"], 1),
            "privacy_score": round(scores["privacy_score"], 1),
            "trust_score": round(scores["trust_score"], 1),
            "total_findings": len(all_findings),
            "scan_duration": round(duration, 2),
            "scan_date": scan_obj.scan_date.isoformat(),
            "findings": all_findings,
            "severity_distribution": get_severity_distribution(all_findings),
            "top_recommendations": top_recommendations(all_findings),
        })
    except Exception as e:
        if 'scan_obj' in locals():
            scan_obj.scan_status = "failed"
            db.commit()
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


# ─── Get Scan Result ──────────────────────────────────────────────────────────
@app.route("/api/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    db = get_session()
    try:
        scan_obj = db.query(Scan).filter_by(id=scan_id).first()
        if not scan_obj:
            return jsonify({"error": "Scan not found"}), 404

        findings = db.query(Finding).filter_by(scan_id=scan_id).all()
        findings_list = [
            {
                "id": f.id,
                "finding_name": f.finding_name,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "evidence": f.evidence,
                "impact": f.impact,
                "recommendation": f.recommendation,
                "ai_explanation": f.ai_explanation,
                "severity_color": severity_color(f.severity),
            }
            for f in findings
        ]

        website = scan_obj.website
        return jsonify({
            "scan_id": scan_obj.id,
            "url": website.website_url if website else "",
            "domain": get_domain(website.website_url) if website else "",
            "security_score": scan_obj.security_score,
            "privacy_score": scan_obj.privacy_score,
            "trust_score": scan_obj.trust_score,
            "total_findings": scan_obj.total_findings,
            "scan_duration": scan_obj.scan_duration,
            "scan_date": scan_obj.scan_date.isoformat() if scan_obj.scan_date else None,
            "scan_status": scan_obj.scan_status,
            "findings": findings_list,
        })
    finally:
        db.close()


# ─── Recent Scans ─────────────────────────────────────────────────────────────
@app.route("/api/scans", methods=["GET"])
def list_scans():
    db = get_session()
    try:
        scans = (
            db.query(Scan)
            .filter_by(scan_status="completed")
            .order_by(Scan.scan_date.desc())
            .limit(50)
            .all()
        )
        result = []
        for s in scans:
            w = s.website
            result.append({
                "scan_id": s.id,
                "url": w.website_url if w else "",
                "domain": get_domain(w.website_url) if w else "",
                "security_score": round(s.security_score, 1),
                "privacy_score": round(s.privacy_score, 1),
                "trust_score": round(s.trust_score, 1),
                "total_findings": s.total_findings,
                "scan_date": s.scan_date.isoformat() if s.scan_date else None,
                "score_label": score_label(s.trust_score),
                "score_color": score_color(s.trust_score),
            })
        return jsonify(result)
    finally:
        db.close()


# ─── Dashboard Stats ──────────────────────────────────────────────────────────
@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    db = get_session()
    try:
        total_scans = db.query(Scan).filter_by(scan_status="completed").count()
        total_sites = db.query(Website).count()
        total_findings = db.query(Finding).count()

        last_scan = (
            db.query(Scan)
            .filter_by(scan_status="completed")
            .order_by(Scan.scan_date.desc())
            .first()
        )

        # Severity distribution across all findings
        all_findings = db.query(Finding).all()
        sev_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in all_findings:
            sev_dist[f.severity] = sev_dist.get(f.severity, 0) + 1

        avg_security = 0.0
        avg_privacy = 0.0
        avg_trust = 0.0
        completed = db.query(Scan).filter_by(scan_status="completed").all()
        if completed:
            avg_security = sum(s.security_score for s in completed) / len(completed)
            avg_privacy = sum(s.privacy_score for s in completed) / len(completed)
            avg_trust = sum(s.trust_score for s in completed) / len(completed)

        return jsonify({
            "total_scans": total_scans,
            "total_sites": total_sites,
            "total_findings": total_findings,
            "avg_security_score": round(avg_security, 1),
            "avg_privacy_score": round(avg_privacy, 1),
            "avg_trust_score": round(avg_trust, 1),
            "severity_distribution": sev_dist,
            "last_scan": {
                "scan_id": last_scan.id,
                "url": last_scan.website.website_url if last_scan and last_scan.website else "",
                "scan_date": last_scan.scan_date.isoformat() if last_scan and last_scan.scan_date else None,
                "trust_score": round(last_scan.trust_score, 1) if last_scan else 0,
            } if last_scan else None,
        })
    finally:
        db.close()


# ─── Findings for Scan ────────────────────────────────────────────────────────
@app.route("/api/scans/<int:scan_id>/findings", methods=["GET"])
def get_findings(scan_id):
    db = get_session()
    try:
        category = request.args.get("category")
        query = db.query(Finding).filter_by(scan_id=scan_id)
        if category:
            query = query.filter_by(category=category)
        findings = query.all()
        return jsonify([
            {
                "id": f.id,
                "finding_name": f.finding_name,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "evidence": f.evidence,
                "impact": f.impact,
                "recommendation": f.recommendation,
                "ai_explanation": f.ai_explanation,
                "severity_color": severity_color(f.severity),
            }
            for f in findings
        ])
    finally:
        db.close()


# ─── AI Explain ───────────────────────────────────────────────────────────────
@app.route("/api/scans/<int:scan_id>/explain", methods=["POST"])
def ai_explain(scan_id):
    if not is_ai_available():
        return jsonify({"error": "AI explanations unavailable (no GROQ_API_KEY set)"}), 503

    db = get_session()
    try:
        findings = db.query(Finding).filter_by(scan_id=scan_id).all()
        if not findings:
            return jsonify({"error": "No findings for this scan"}), 404

        findings_dicts = [
            {
                "finding_name": f.finding_name,
                "category": f.category,
                "severity": f.severity,
                "evidence": f.evidence,
                "impact": f.impact,
                "recommendation": f.recommendation,
            }
            for f in findings
        ]

        explained = explain_all_findings(findings_dicts)
        # Update DB
        for f, ex in zip(findings, explained):
            f.ai_explanation = ex.get("ai_explanation", "")
        db.commit()

        return jsonify(explained)
    finally:
        db.close()


# ─── Reassessment ─────────────────────────────────────────────────────────────
@app.route("/api/reassess", methods=["POST"])
def reassess():
    data = request.get_json(force=True)
    url = (data or {}).get("url", "").strip()
    scan_id_1 = (data or {}).get("scan_id_1")
    scan_id_2 = (data or {}).get("scan_id_2")

    try:
        if url:
            scans_raw = get_scans_for_url(url)
            # Serialize datetime objects
            scans = []
            for s in scans_raw:
                sd = dict(s)
                if hasattr(sd.get("scan_date"), "isoformat"):
                    sd["scan_date"] = sd["scan_date"].isoformat()
                sd["scan_id"] = sd.pop("id", sd.get("scan_id"))
                scans.append(sd)
            return jsonify({"scans": scans})
        elif scan_id_1 and scan_id_2:
            result = compare_scans(scan_id_1, scan_id_2)
            # Serialize any datetime in result
            def clean(obj):
                if isinstance(obj, dict):
                    return {k: clean(v) for k, v in obj.items()}
                if isinstance(obj, list):
                    return [clean(i) for i in obj]
                if hasattr(obj, "isoformat"):
                    return obj.isoformat()
                return obj
            return jsonify(clean(result))
        else:
            return jsonify({"error": "Provide url or both scan_id_1 and scan_id_2"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Report Generation ────────────────────────────────────────────────────────
@app.route("/api/scans/<int:scan_id>/report", methods=["POST"])
def generate_report(scan_id):
    db = get_session()
    try:
        scan_obj = db.query(Scan).filter_by(id=scan_id).first()
        if not scan_obj:
            return jsonify({"error": "Scan not found"}), 404

        findings = db.query(Finding).filter_by(scan_id=scan_id).all()
        findings_dicts = [
            {
                "finding_name": f.finding_name,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "evidence": f.evidence,
                "impact": f.impact,
                "recommendation": f.recommendation,
                "ai_explanation": f.ai_explanation or "",
            }
            for f in findings
        ]

        scores = {
            "security_score": scan_obj.security_score,
            "privacy_score": scan_obj.privacy_score,
            "trust_score": scan_obj.trust_score,
        }

        website = scan_obj.website
        url = website.website_url if website else ""
        path = generate_pdf_report(url, scores, findings_dicts, scan_id)

        # Save report record
        report = Report(scan_id=scan_id, report_path=path)
        db.add(report)
        db.commit()

        return jsonify({"report_path": path, "message": "Report generated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


# ─── History ──────────────────────────────────────────────────────────────────
@app.route("/api/history", methods=["GET"])
def history():
    db = get_session()
    try:
        websites = db.query(Website).all()
        result = []
        for w in websites:
            scans = (
                db.query(Scan)
                .filter_by(website_id=w.id, scan_status="completed")
                .order_by(Scan.scan_date.desc())
                .all()
            )
            if scans:
                result.append({
                    "url": w.website_url,
                    "domain": get_domain(w.website_url),
                    "scan_count": len(scans),
                    "last_scan": scans[0].scan_date.isoformat() if scans[0].scan_date else None,
                    "last_trust_score": round(scans[0].trust_score, 1),
                    "scans": [
                        {
                            "scan_id": s.id,
                            "scan_date": s.scan_date.isoformat() if s.scan_date else None,
                            "security_score": round(s.security_score, 1),
                            "privacy_score": round(s.privacy_score, 1),
                            "trust_score": round(s.trust_score, 1),
                            "total_findings": s.total_findings,
                        }
                        for s in scans
                    ],
                })
        return jsonify(result)
    finally:
        db.close()


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
