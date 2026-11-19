"""
ThreatGuard – Flask REST API Backend
Wraps all scanning modules and exposes JSON endpoints for the React frontend.
"""
from flask import Flask, request, jsonify, g, send_file
from flask_cors import CORS
import sys
import os
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

# Allow imports from threatguard package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'threatguard'))

from database.db import init_db, get_session
from database.models import User, Website, Scan, Finding, Report, WorkspaceSetting, WorkspaceTicket, RiskState
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
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)
CORS(app, origins=["http://localhost:3000", "http://localhost:5173"])

TOKEN_TTL_SECONDS = 12 * 60 * 60
SCAN_POOL = ThreadPoolExecutor(max_workers=max(1, int(os.environ.get("SCAN_WORKERS", "3"))))


def _token_serializer():
    return URLSafeTimedSerializer(app.secret_key, salt="threatguard-api-token-v1")


@app.before_request
def require_api_authentication():
    if not request.path.startswith("/api/") or request.path in {
        "/api/health", "/api/auth/register", "/api/auth/login"
    }:
        return None
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return jsonify({"error": "Sign in is required."}), 401
    try:
        payload = _token_serializer().loads(header[7:], max_age=TOKEN_TTL_SECONDS)
        g.user_id = int(payload["user_id"])
    except (BadSignature, SignatureExpired, KeyError, TypeError, ValueError):
        return jsonify({"error": "Your session expired. Please sign in again."}), 401
    return None


def _auth_response(user):
    return jsonify({
        "access_token": _token_serializer().dumps({"user_id": user.id}),
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL_SECONDS,
        "user": {"id": user.id, "username": user.username, "email": user.email},
    })


def _run_assessment(scan_id, url):
    """Run a scan off the request thread and persist its final status/results."""
    try:
        _run_assessment_job(scan_id, url)
    except Exception:
        app.logger.exception("Background assessment %s could not start", scan_id)
        db = get_session()
        try:
            scan_obj = db.query(Scan).filter_by(id=scan_id).first()
            if scan_obj:
                scan_obj.scan_status = "failed"
                db.commit()
        finally:
            db.close()


def _run_assessment_job(scan_id, url):
    """Worker implementation kept separate so the wrapper can mark all errors."""
    db = get_session()
    try:
        scan_obj = db.query(Scan).filter_by(id=scan_id).first()
        if not scan_obj:
            return
        scan_obj.scan_status = "running"
        db.commit()
    finally:
        db.close()

    started = time.monotonic()
    try:
        findings = run_security_scan(url) + run_privacy_scan(url)
        scores = calculate_scores(findings)
        duration = round(time.monotonic() - started, 2)
        db = get_session()
        try:
            scan_obj = db.query(Scan).filter_by(id=scan_id).first()
            if not scan_obj:
                return
            scan_obj.security_score = scores["security_score"]
            scan_obj.privacy_score = scores["privacy_score"]
            scan_obj.trust_score = scores["trust_score"]
            scan_obj.scan_status = "completed"
            scan_obj.scan_duration = duration
            scan_obj.total_findings = len(findings)
            for item in findings:
                db.add(Finding(
                    scan_id=scan_id,
                    finding_name=item.get("finding_name", "")[:256],
                    category=item.get("category", "")[:80],
                    severity=item.get("severity", "Informational")[:20],
                    confidence=item.get("confidence", "Low")[:20],
                    evidence=item.get("evidence", ""),
                    impact=item.get("impact", ""),
                    recommendation=item.get("recommendation", ""),
                ))
            db.commit()
        finally:
            db.close()
    except Exception:
        app.logger.exception("Background assessment %s failed", scan_id)
        db = get_session()
        try:
            scan_obj = db.query(Scan).filter_by(id=scan_id).first()
            if scan_obj:
                scan_obj.scan_status = "failed"
                db.commit()
        finally:
            db.close()

# Initialize DB on startup
init_db()


# ─── Health ──────────────────────────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})


@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400
    username = str(data.get("username", "")).strip().lower()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if not re.fullmatch(r"[a-z0-9_.-]{3,80}", username) or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 120:
        return jsonify({"error": "Use a username with 3–80 letters, numbers, dots, dashes, or underscores and enter a valid email."}), 400
    if not 10 <= len(password) <= 128:
        return jsonify({"error": "Password must be 10–128 characters long."}), 400
    db = get_session()
    try:
        if db.query(User).filter((User.username == username) | (User.email == email)).first():
            return jsonify({"error": "That username or email is already registered."}), 409
        user = User(username=username, email=email, password_hash=generate_password_hash(password))
        db.add(user)
        db.commit()
        db.refresh(user)
        return _auth_response(user), 201
    except IntegrityError:
        db.rollback()
        return jsonify({"error": "That username or email is already registered."}), 409
    except Exception:
        db.rollback()
        app.logger.exception("Account registration failed")
        return jsonify({"error": "Account could not be created. Please try again."}), 500
    finally:
        db.close()


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400
    identity = str(data.get("identity", "")).strip().lower()
    password = str(data.get("password", ""))
    db = get_session()
    try:
        user = db.query(User).filter((User.email == identity) | (User.username == identity)).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({"error": "Email/username or password was not recognized."}), 401
        return _auth_response(user)
    finally:
        db.close()


@app.route("/api/auth/me", methods=["GET"])
def current_account():
    db = get_session()
    try:
        user = db.query(User).filter_by(id=g.user_id).first()
        if not user:
            return jsonify({"error": "Account not found."}), 404
        return jsonify({"id": user.id, "username": user.username, "email": user.email})
    finally:
        db.close()


# ─── Scan Website ─────────────────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400
    if data.get("authorized") is not True:
        return jsonify({"error": "Confirm that you own this website or have permission to assess it."}), 403
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
        website = db.query(Website).filter_by(website_url=url, user_id=g.user_id).first()
        if not website:
            website = Website(website_url=url, user_id=g.user_id)
            db.add(website)
            db.commit()
            db.refresh(website)

        # Persist a queued record before handing the work to a background worker.
        scan_obj = Scan(website_id=website.id, scan_status="queued")
        db.add(scan_obj)
        db.commit()
        db.refresh(scan_obj)
        scan_id = scan_obj.id
        SCAN_POOL.submit(_run_assessment, scan_id, url)
        return jsonify({"scan_id": scan_id, "url": url, "scan_status": "queued", "message": "Assessment queued."}), 202
    except Exception:
        app.logger.exception("Website assessment failed")
        return jsonify({"error": "Assessment could not be queued. Please retry."}), 500
    finally:
        db.close()


# ─── Get Scan Result ──────────────────────────────────────────────────────────
@app.route("/api/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    db = get_session()
    try:
        scan_obj = db.query(Scan).join(Website).filter(Scan.id == scan_id, Website.user_id == g.user_id).first()
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
            db.query(Scan).join(Website)
            .filter(Scan.scan_status == "completed", Website.user_id == g.user_id)
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
        total_scans = db.query(Scan).join(Website).filter(Scan.scan_status == "completed", Website.user_id == g.user_id).count()
        total_sites = db.query(Website).filter_by(user_id=g.user_id).count()
        total_findings = db.query(Finding).join(Scan).join(Website).filter(Website.user_id == g.user_id).count()

        last_scan = (
            db.query(Scan).join(Website)
            .filter(Scan.scan_status == "completed", Website.user_id == g.user_id)
            .order_by(Scan.scan_date.desc())
            .first()
        )

        # Severity distribution across all findings
        all_findings = db.query(Finding).join(Scan).join(Website).filter(Website.user_id == g.user_id).all()
        sev_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in all_findings:
            sev_dist[f.severity] = sev_dist.get(f.severity, 0) + 1

        avg_security = 0.0
        avg_privacy = 0.0
        avg_trust = 0.0
        completed = db.query(Scan).join(Website).filter(Scan.scan_status == "completed", Website.user_id == g.user_id).all()
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
        owned = db.query(Scan.id).join(Website).filter(Scan.id == scan_id, Website.user_id == g.user_id).first()
        if not owned:
            return jsonify({"error": "Scan not found"}), 404
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
        owned = db.query(Scan.id).join(Website).filter(Scan.id == scan_id, Website.user_id == g.user_id).first()
        if not owned:
            return jsonify({"error": "Scan not found"}), 404
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
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400
    url = str(data.get("url", "")).strip()
    scan_id_1 = (data or {}).get("scan_id_1")
    scan_id_2 = (data or {}).get("scan_id_2")

    try:
        if url:
            db = get_session()
            try:
                owned_site = db.query(Website.id).filter_by(website_url=url, user_id=g.user_id).first()
            finally:
                db.close()
            if not owned_site:
                return jsonify({"error": "Website not found in your account."}), 404
            scans_raw = get_scans_for_url(url, user_id=g.user_id)
            # Serialize datetime objects
            scans = []
            for s in scans_raw:
                sd = dict(s)
                if hasattr(sd.get("scan_date"), "isoformat"):
                    sd["scan_date"] = sd["scan_date"].isoformat()
                sd["scan_id"] = sd.pop("id", sd.get("scan_id"))
                scans.append(sd)
            return jsonify({"scans": scans})
        elif scan_id_1 is not None and scan_id_2 is not None:
            try:
                old_id, new_id = int(scan_id_1), int(scan_id_2)
            except (TypeError, ValueError):
                return jsonify({"error": "Select two valid completed scans."}), 400
            if old_id == new_id:
                return jsonify({"error": "Choose two different scans to compare."}), 400
            db = get_session()
            try:
                selected = db.query(Scan).join(Website).filter(
                    Scan.id.in_([old_id, new_id]),
                    Website.user_id == g.user_id,
                ).all()
                owned_ids = {scan.id for scan in selected}
                if owned_ids != {old_id, new_id}:
                    return jsonify({"error": "One or both scans were not found in your account."}), 404
                if any(scan.scan_status != "completed" for scan in selected):
                    return jsonify({"error": "Both assessments must be completed before comparison."}), 409
                if len({scan.website_id for scan in selected}) != 1:
                    return jsonify({"error": "Choose two scans for the same registered website."}), 400
            finally:
                db.close()
            result = compare_scans(old_id, new_id)
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
        app.logger.exception("Reassessment request failed")
        return jsonify({"error": "The reassessment comparison could not be completed."}), 500


# ─── Report Generation ────────────────────────────────────────────────────────
@app.route("/api/scans/<int:scan_id>/report", methods=["POST"])
def generate_report(scan_id):
    db = get_session()
    try:
        scan_obj = db.query(Scan).join(Website).filter(Scan.id == scan_id, Website.user_id == g.user_id).first()
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
        path = generate_pdf_report(
            url,
            scan_id,
            scan_obj.scan_date,
            scores["security_score"],
            scores["privacy_score"],
            scores["trust_score"],
            findings_dicts,
        )

        # Save report record
        report = Report(scan_id=scan_id, report_path=path)
        db.add(report)
        db.commit()

        return jsonify({"report_path": path, "message": "Report generated successfully"})
    except Exception as e:
        app.logger.exception("Report generation failed")
        return jsonify({"error": "The report could not be generated. See the application log for details."}), 500
    finally:
        db.close()


@app.route("/api/scans/<int:scan_id>/report/download", methods=["GET"])
def download_report(scan_id):
    db = get_session()
    try:
        owned = db.query(Scan.id).join(Website).filter(
            Scan.id == scan_id, Website.user_id == g.user_id
        ).first()
        if not owned:
            return jsonify({"error": "Scan not found"}), 404
        report = db.query(Report).filter_by(scan_id=scan_id).order_by(Report.generated_at.desc()).first()
        if not report or not report.report_path or not os.path.isfile(report.report_path):
            return jsonify({"error": "Generate the report before downloading it."}), 404
        return send_file(report.report_path, as_attachment=True,
                         download_name=os.path.basename(report.report_path),
                         mimetype="application/pdf")
    finally:
        db.close()


# ─── History ──────────────────────────────────────────────────────────────────
@app.route("/api/history", methods=["GET"])
def history():
    db = get_session()
    try:
        websites = db.query(Website).filter_by(user_id=g.user_id).all()
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


@app.route("/api/settings", methods=["GET", "PUT"])
def workspace_settings():
    db = get_session()
    try:
        setting = db.query(WorkspaceSetting).filter_by(user_id=g.user_id).first()
        if not setting:
            user = db.query(User).filter_by(id=g.user_id).first()
            setting = WorkspaceSetting(user_id=g.user_id, workspace_name="My Workspace",
                                       primary_contact=user.email if user else "")
            db.add(setting)
            db.commit()
            db.refresh(setting)
        if request.method == "PUT":
            data = request.get_json(silent=True) or {}
            if "workspace_name" in data:
                value = str(data["workspace_name"]).strip()
                if not value or len(value) > 120:
                    return jsonify({"error": "Workspace name must be between 1 and 120 characters."}), 400
                setting.workspace_name = value
            if "primary_contact" in data:
                value = str(data["primary_contact"]).strip()
                if len(value) > 120:
                    return jsonify({"error": "Primary contact is too long."}), 400
                setting.primary_contact = value
            for key, field in (("email_notifications", "email_notifications"),
                               ("privacy_checks", "privacy_checks"),
                               ("owasp_references", "owasp_references")):
                if key in data:
                    setattr(setting, field, bool(data[key]))
            db.commit()
        return jsonify({"workspace_name": setting.workspace_name, "primary_contact": setting.primary_contact,
                        "email_notifications": setting.email_notifications, "privacy_checks": setting.privacy_checks,
                        "owasp_references": setting.owasp_references})
    finally:
        db.close()


@app.route("/api/tickets", methods=["GET", "POST"])
def workspace_tickets():
    db = get_session()
    try:
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            subject = str(data.get("subject", "")).strip()
            area = str(data.get("area", "Security")).strip()
            if not subject or len(subject) > 200:
                return jsonify({"error": "Ticket subject must be between 1 and 200 characters."}), 400
            if area not in {"Security", "Privacy", "Other"}:
                return jsonify({"error": "Choose Security, Privacy, or Other for the ticket area."}), 400
            user = db.query(User).filter_by(id=g.user_id).first()
            now = datetime.utcnow()
            ticket = WorkspaceTicket(user_id=g.user_id, subject=subject, area=area,
                                     owner=user.username if user else "Workspace", created_at=now, updated_at=now)
            db.add(ticket)
            db.commit()
            db.refresh(ticket)
        else:
            ticket = None
        if ticket is None:
            tickets = db.query(WorkspaceTicket).filter_by(user_id=g.user_id).order_by(WorkspaceTicket.created_at.desc()).all()
            return jsonify([{"id": f"WS-{item.id}", "ticket_id": item.id, "subject": item.subject,
                             "area": item.area, "owner": item.owner, "status": item.status,
                             "updated": item.updated_at.isoformat() if item.updated_at else None} for item in tickets])
        return jsonify({"id": f"WS-{ticket.id}", "ticket_id": ticket.id, "subject": ticket.subject,
                        "area": ticket.area, "owner": ticket.owner, "status": ticket.status,
                        "updated": ticket.updated_at.isoformat() if ticket.updated_at else None}), 201
    finally:
        db.close()


@app.route("/api/tickets/<int:ticket_id>", methods=["PATCH"])
def update_workspace_ticket(ticket_id):
    data = request.get_json(silent=True) or {}
    status = str(data.get("status", ""))
    if status not in {"Open", "In progress", "Resolved"}:
        return jsonify({"error": "Ticket status must be Open, In progress, or Resolved."}), 400
    db = get_session()
    try:
        ticket = db.query(WorkspaceTicket).filter_by(id=ticket_id, user_id=g.user_id).first()
        if not ticket:
            return jsonify({"error": "Ticket not found."}), 404
        ticket.status = status
        ticket.updated_at = datetime.utcnow()
        db.commit()
        return jsonify({"id": f"WS-{ticket.id}", "ticket_id": ticket.id, "subject": ticket.subject,
                        "area": ticket.area, "owner": ticket.owner, "status": ticket.status,
                        "updated": ticket.updated_at.isoformat()})
    finally:
        db.close()


@app.route("/api/risk-states", methods=["GET", "PUT"])
def risk_states():
    db = get_session()
    try:
        if request.method == "GET":
            rows = db.query(RiskState).filter_by(user_id=g.user_id).all()
            return jsonify({str(row.finding_id): row.status for row in rows})
        data = request.get_json(silent=True) or {}
        try:
            finding_id = int(data.get("finding_id"))
        except (TypeError, ValueError):
            return jsonify({"error": "A valid finding_id is required."}), 400
        status = str(data.get("status", ""))
        if status not in {"Open", "Review", "Accepted", "Resolved"}:
            return jsonify({"error": "Choose Open, Review, Accepted, or Resolved."}), 400
        owned = db.query(Finding.id).join(Scan).join(Website).filter(
            Finding.id == finding_id, Website.user_id == g.user_id
        ).first()
        if not owned:
            return jsonify({"error": "Finding not found."}), 404
        state = db.query(RiskState).filter_by(user_id=g.user_id, finding_id=finding_id).first()
        if not state:
            state = RiskState(user_id=g.user_id, finding_id=finding_id)
            db.add(state)
        state.status = status
        state.updated_at = datetime.utcnow()
        db.commit()
        return jsonify({"finding_id": finding_id, "status": state.status,
                        "updated_at": state.updated_at.isoformat()})
    finally:
        db.close()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1", host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")))
