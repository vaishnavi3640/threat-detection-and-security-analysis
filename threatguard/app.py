"""
THREATGUARD – Threat Detection and Privacy Analysis System
Main Streamlit application entry point.
"""
import os
import sys
import time
from datetime import datetime

# ── Path setup so imports work from project root ───────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

# Load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import streamlit as st

# ── Page config (must be first Streamlit call) ─────────────────────────────────
st.set_page_config(
    page_title="THREATGUARD – Security Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Internal imports ───────────────────────────────────────────────────────────
from database.db import init_db, get_session
from database.models import Website, Scan, Finding, Report
from modules.security_scanner import run_security_scan
from modules.privacy_analyzer import run_privacy_scan
from modules.scoring_engine import calculate_scores, get_severity_distribution, top_recommendations
from modules.ai_explainer import is_ai_available, explain_all_findings, explain_finding
from modules.report_generator import generate_pdf_report
from modules.reassessment import get_scans_for_url, compare_scans, get_findings_for_scan
from utils.validators import validate_url
from utils.helpers import (
    format_datetime, severity_color, score_color, score_label,
    get_domain, severity_order,
)

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

# ── Initialise DB ──────────────────────────────────────────────────────────────
init_db()

# ═══════════════════════════════════════════════════════════════════════════════
# CSS STYLES
# ═══════════════════════════════════════════════════════════════════════════════
def inject_css():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    /* ── Global ── */
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    .stApp {
        background: #0A1628;
        color: #E2E8F0;
    }

    /* ── Sidebar ── */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0D1B2A 0%, #0A1628 100%);
        border-right: 1px solid #1E3A5F;
    }
    [data-testid="stSidebar"] .stMarkdown h1,
    [data-testid="stSidebar"] .stMarkdown h2,
    [data-testid="stSidebar"] .stMarkdown h3 {
        color: #1E90FF;
    }

    /* ── Metric cards ── */
    [data-testid="metric-container"] {
        background: linear-gradient(135deg, #0D1B2A, #132236);
        border: 1px solid #1E3A5F;
        border-radius: 12px;
        padding: 16px;
    }
    [data-testid="metric-container"] [data-testid="stMetricValue"] {
        color: #1E90FF;
        font-size: 2rem;
        font-weight: 700;
    }
    [data-testid="metric-container"] [data-testid="stMetricLabel"] {
        color: #94A3B8;
        font-size: 0.85rem;
    }

    /* ── Cards ── */
    .tg-card {
        background: linear-gradient(135deg, #0D1B2A, #132236);
        border: 1px solid #1E3A5F;
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 16px;
    }
    .tg-card h3 {
        color: #1E90FF;
        margin-bottom: 8px;
        font-size: 1rem;
        font-weight: 600;
    }

    /* ── Score circles ── */
    .score-circle {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        width: 120px;
        height: 120px;
        border-radius: 50%;
        border: 4px solid;
        margin: auto;
        font-size: 1.8rem;
        font-weight: 700;
    }
    .score-label {
        font-size: 0.75rem;
        color: #94A3B8;
        text-align: center;
        margin-top: 8px;
    }

    /* ── Severity badges ── */
    .badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-critical { background: #FF4444; color: white; }
    .badge-high     { background: #FF8C00; color: white; }
    .badge-medium   { background: #FFD700; color: #1a1a1a; }
    .badge-low      { background: #1E90FF; color: white; }
    .badge-info     { background: #90EE90; color: #1a1a1a; }

    /* ── Page title ── */
    .page-title {
        font-size: 1.8rem;
        font-weight: 700;
        color: #E2E8F0;
        margin-bottom: 4px;
    }
    .page-subtitle {
        color: #64748B;
        font-size: 0.95rem;
        margin-bottom: 24px;
    }

    /* ── Finding rows ── */
    .finding-row {
        background: #0D1B2A;
        border: 1px solid #1E3A5F;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 10px;
    }
    .finding-name {
        font-size: 0.95rem;
        font-weight: 600;
        color: #E2E8F0;
        margin-bottom: 4px;
    }
    .finding-evidence {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
        color: #94A3B8;
        background: #060E1A;
        border-radius: 4px;
        padding: 6px 10px;
        margin: 6px 0;
        word-break: break-all;
    }
    .finding-impact {
        font-size: 0.82rem;
        color: #A0AEC0;
        margin-top: 4px;
    }

    /* ── Info box ── */
    .info-box {
        background: rgba(30, 144, 255, 0.08);
        border-left: 3px solid #1E90FF;
        border-radius: 4px;
        padding: 10px 16px;
        margin: 8px 0;
        font-size: 0.85rem;
        color: #A0AEC0;
    }

    /* ── Warning box ── */
    .warn-box {
        background: rgba(255, 140, 0, 0.08);
        border-left: 3px solid #FF8C00;
        border-radius: 4px;
        padding: 10px 16px;
        margin: 8px 0;
        font-size: 0.85rem;
        color: #A0AEC0;
    }

    /* ── Success box ── */
    .success-box {
        background: rgba(0, 200, 81, 0.08);
        border-left: 3px solid #00C851;
        border-radius: 4px;
        padding: 10px 16px;
        margin: 8px 0;
        font-size: 0.85rem;
        color: #A0AEC0;
    }

    /* ── Button overrides ── */
    .stButton > button {
        background: linear-gradient(135deg, #1E90FF, #0066CC);
        color: white;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        padding: 10px 24px;
        transition: all 0.2s;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #2496FF, #0070DD);
        transform: translateY(-1px);
        box-shadow: 0 4px 15px rgba(30, 144, 255, 0.3);
    }

    /* ── Input fields ── */
    .stTextInput > div > div > input {
        background: #0D1B2A;
        border: 1px solid #1E3A5F;
        border-radius: 8px;
        color: #E2E8F0;
    }
    .stTextInput > div > div > input:focus {
        border-color: #1E90FF;
        box-shadow: 0 0 0 3px rgba(30, 144, 255, 0.15);
    }

    /* ── Tabs ── */
    [data-testid="stTabs"] [role="tab"] {
        color: #64748B;
        font-weight: 500;
    }
    [data-testid="stTabs"] [role="tab"][aria-selected="true"] {
        color: #1E90FF;
        border-bottom: 2px solid #1E90FF;
    }

    /* ── Expander ── */
    .streamlit-expanderHeader {
        background: #0D1B2A;
        border: 1px solid #1E3A5F;
        border-radius: 8px;
        color: #E2E8F0;
    }

    /* ── Divider ── */
    hr {
        border-color: #1E3A5F;
        margin: 16px 0;
    }

    /* ── Hide default header ── */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* ── Scrollbar ── */
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: #0A1628; }
    ::-webkit-scrollbar-thumb { background: #1E3A5F; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #1E90FF; }
    </style>
    """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR NAVIGATION
# ═══════════════════════════════════════════════════════════════════════════════
def render_sidebar():
    with st.sidebar:
        st.markdown("""
        <div style="text-align:center; padding: 16px 0 24px 0;">
            <div style="font-size:2.5rem;">🛡️</div>
            <div style="font-size:1.3rem; font-weight:700; color:#1E90FF; letter-spacing:2px;">THREATGUARD</div>
            <div style="font-size:0.7rem; color:#4A5568; letter-spacing:1px; margin-top:2px;">
                THREAT DETECTION & PRIVACY ANALYSIS
            </div>
        </div>
        <hr style="border-color:#1E3A5F; margin:0 0 16px 0;">
        """, unsafe_allow_html=True)

        pages = {
            "🏠  Dashboard": "Dashboard",
            "🔍  Scan Website": "Scan Website",
            "🔒  Security Analysis": "Security Analysis",
            "🔏  Privacy Analysis": "Privacy Analysis",
            "⚠️  Weaknesses": "Weaknesses",
            "🤖  AI Explanation": "AI Explanation",
            "📄  Reports": "Reports",
            "🔄  Reassessment": "Reassessment",
        }

        if "page" not in st.session_state:
            st.session_state.page = "Dashboard"

        for label, page_name in pages.items():
            is_active = st.session_state.page == page_name
            btn_style = "primary" if is_active else "secondary"
            if st.button(label, key=f"nav_{page_name}", use_container_width=True):
                st.session_state.page = page_name
                st.rerun()

        st.markdown("<hr style='border-color:#1E3A5F; margin:16px 0;'>", unsafe_allow_html=True)

        # AI status indicator
        ai_ok = is_ai_available()
        ai_indicator = "🟢 AI Active" if ai_ok else "🔴 AI Offline"
        ai_note = "Groq API connected" if ai_ok else "Set GROQ_API_KEY in .env"
        st.markdown(f"""
        <div class="tg-card" style="padding:12px 16px;">
            <div style="font-size:0.8rem; font-weight:600; color:#94A3B8;">{ai_indicator}</div>
            <div style="font-size:0.72rem; color:#4A5568;">{ai_note}</div>
        </div>
        """, unsafe_allow_html=True)

        # Last scan info
        if "last_scan_url" in st.session_state:
            st.markdown(f"""
            <div class="tg-card" style="padding:12px 16px;">
                <div style="font-size:0.72rem; color:#4A5568;">Last scanned</div>
                <div style="font-size:0.8rem; color:#1E90FF; word-break:break-all;">{st.session_state.last_scan_url}</div>
            </div>
            """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER: SCORE GAUGE CHART
# ═══════════════════════════════════════════════════════════════════════════════
def score_gauge(value: float, title: str) -> go.Figure:
    color = score_color(value)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": title, "font": {"size": 14, "color": "#94A3B8"}},
        number={"font": {"size": 36, "color": color}, "suffix": ""},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#1E3A5F",
                     "tickfont": {"color": "#4A5568", "size": 10}},
            "bar": {"color": color, "thickness": 0.3},
            "bgcolor": "#0D1B2A",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 40], "color": "#1A0A0A"},
                {"range": [40, 60], "color": "#1A1500"},
                {"range": [60, 80], "color": "#0A1500"},
                {"range": [80, 100], "color": "#0A1A0A"},
            ],
            "threshold": {
                "line": {"color": color, "width": 3},
                "thickness": 0.75,
                "value": value,
            },
        },
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"family": "Inter"},
        margin=dict(t=40, b=0, l=20, r=20),
        height=200,
    )
    return fig


def severity_donut(dist: dict) -> go.Figure:
    labels = list(dist.keys())
    values = list(dist.values())
    colors_list = [severity_color(s) for s in labels]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.6,
        marker=dict(colors=colors_list, line=dict(color="#0A1628", width=2)),
        textfont=dict(color="white", size=11),
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"family": "Inter", "color": "#E2E8F0"},
        showlegend=True,
        legend=dict(
            font=dict(color="#94A3B8", size=11),
            bgcolor="rgba(0,0,0,0)",
        ),
        margin=dict(t=20, b=20, l=20, r=20),
        height=280,
    )
    return fig


def badge_html(severity: str) -> str:
    cls = {
        "Critical": "badge-critical",
        "High": "badge-high",
        "Medium": "badge-medium",
        "Low": "badge-low",
        "Informational": "badge-info",
    }.get(severity, "badge-info")
    return f'<span class="badge {cls}">{severity}</span>'


# ═══════════════════════════════════════════════════════════════════════════════
# DB HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
def save_scan_to_db(url: str, findings: list[dict], scores: dict) -> int:
    db = get_session()
    try:
        # Upsert website
        website = db.query(Website).filter(Website.website_url == url).first()
        if not website:
            website = Website(website_url=url)
            db.add(website)
            db.flush()

        # Create scan record
        scan = Scan(
            website_id=website.id,
            scan_date=datetime.utcnow(),
            security_score=scores["security_score"],
            privacy_score=scores["privacy_score"],
            trust_score=scores["trust_score"],
            scan_status="completed",
            total_findings=len(findings),
        )
        db.add(scan)
        db.flush()

        # Save findings
        for f in findings:
            finding = Finding(
                scan_id=scan.id,
                finding_name=f.get("finding_name", "Unknown"),
                category=f.get("category", "security"),
                severity=f.get("severity", "Informational"),
                confidence=f.get("confidence", "Low"),
                evidence=f.get("evidence", ""),
                impact=f.get("impact", ""),
                recommendation=f.get("recommendation", ""),
                ai_explanation=f.get("ai_explanation", ""),
            )
            db.add(finding)

        db.commit()
        return scan.id
    except Exception as e:
        db.rollback()
        st.error(f"Database error: {e}")
        return -1
    finally:
        db.close()


def get_recent_scans(limit: int = 10) -> list[dict]:
    db = get_session()
    try:
        scans = (
            db.query(Scan, Website)
            .join(Website, Scan.website_id == Website.id)
            .filter(Scan.scan_status == "completed")
            .order_by(Scan.scan_date.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": s.id,
                "url": w.website_url,
                "date": s.scan_date,
                "security_score": s.security_score,
                "privacy_score": s.privacy_score,
                "trust_score": s.trust_score,
                "total_findings": s.total_findings,
            }
            for s, w in scans
        ]
    finally:
        db.close()


def get_all_stats() -> dict:
    db = get_session()
    try:
        total_sites = db.query(Website).count()
        total_scans = db.query(Scan).filter(Scan.scan_status == "completed").count()
        total_findings = db.query(Finding).count()

        last_scan = (
            db.query(Scan)
            .filter(Scan.scan_status == "completed")
            .order_by(Scan.scan_date.desc())
            .first()
        )
        avg_security = avg_privacy = avg_trust = 0.0
        if total_scans > 0:
            from sqlalchemy import func
            row = db.query(
                func.avg(Scan.security_score),
                func.avg(Scan.privacy_score),
                func.avg(Scan.trust_score),
            ).filter(Scan.scan_status == "completed").first()
            if row:
                avg_security = round(row[0] or 0, 1)
                avg_privacy = round(row[1] or 0, 1)
                avg_trust = round(row[2] or 0, 1)

        return {
            "total_sites": total_sites,
            "total_scans": total_scans,
            "total_findings": total_findings,
            "avg_security": avg_security,
            "avg_privacy": avg_privacy,
            "avg_trust": avg_trust,
        }
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
def page_dashboard():
    st.markdown('<div class="page-title">🏠 Dashboard</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Security posture overview across all scanned websites</div>', unsafe_allow_html=True)

    stats = get_all_stats()
    recent = get_recent_scans(10)

    # ── Top metrics ────────────────────────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("🌐 Sites Scanned", stats["total_sites"])
    c2.metric("🔍 Total Scans", stats["total_scans"])
    c3.metric("⚠️ Total Findings", stats["total_findings"])
    c4.metric("🔒 Avg Security", f"{stats['avg_security']:.0f}")
    c5.metric("🔏 Avg Privacy", f"{stats['avg_privacy']:.0f}")

    st.markdown("---")

    if not recent:
        st.markdown("""
        <div class="info-box">
            No scans yet. Go to <b>Scan Website</b> to run your first security assessment.
        </div>
        """, unsafe_allow_html=True)
        return

    # ── Score gauges for most recent scan ─────────────────────────────────────
    last = recent[0]
    st.markdown(f"### Most Recent Scan: `{last['url']}`")
    st.markdown(f"<div style='color:#4A5568; font-size:0.82rem; margin-bottom:16px;'>{format_datetime(last['date'])}</div>", unsafe_allow_html=True)

    g1, g2, g3 = st.columns(3)
    with g1:
        st.plotly_chart(score_gauge(last["security_score"], "Security Score"), use_container_width=True, key="dash_sec_gauge")
    with g2:
        st.plotly_chart(score_gauge(last["privacy_score"], "Privacy Score"), use_container_width=True, key="dash_priv_gauge")
    with g3:
        st.plotly_chart(score_gauge(last["trust_score"], "Trust Score"), use_container_width=True, key="dash_trust_gauge")

    st.markdown("---")

    # ── Recent scans table + severity chart ───────────────────────────────────
    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown("### 📋 Recent Scan History")
        rows = []
        for s in recent:
            rows.append({
                "URL": s["url"],
                "Date": format_datetime(s["date"]),
                "Security": f"{s['security_score']:.0f}",
                "Privacy": f"{s['privacy_score']:.0f}",
                "Trust": f"{s['trust_score']:.0f}",
                "Findings": s["total_findings"],
            })
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)

    with col_right:
        st.markdown("### 📊 Severity Distribution")
        # Aggregate all findings for all scans
        db = get_session()
        try:
            all_findings_q = db.query(Finding).all()
            dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
            for f in all_findings_q:
                if f.severity in dist:
                    dist[f.severity] += 1
        finally:
            db.close()

        if any(v > 0 for v in dist.values()):
            st.plotly_chart(severity_donut(dist), use_container_width=True, key="dash_donut")
        else:
            st.info("No findings data yet.")

    # ── Top recommendations ────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 🎯 Top Security Recommendations")

    if "last_scan_findings" in st.session_state and st.session_state.last_scan_findings:
        recs = top_recommendations(st.session_state.last_scan_findings, 5)
        for i, r in enumerate(recs, 1):
            sev = r.get("severity", "Informational")
            st.markdown(f"""
            <div class="finding-row">
                <div class="finding-name">#{i} {r.get('finding_name', 'Finding')}
                    &nbsp;{badge_html(sev)}
                </div>
                <div class="finding-impact">{r.get('recommendation', '')[:200]}</div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown('<div class="info-box">Run a scan to see personalised recommendations.</div>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: SCAN WEBSITE
# ═══════════════════════════════════════════════════════════════════════════════
def page_scan():
    st.markdown('<div class="page-title">🔍 Scan Website</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Run a passive security and privacy assessment on a website you are authorised to test.</div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="warn-box">
        <b>⚠️ Authorization Required:</b> Only scan websites you own or have explicit written
        permission to test. Unauthorised scanning may be illegal. This tool performs
        passive, read-only checks only — no exploitation or intrusive testing is performed.
    </div>
    """, unsafe_allow_html=True)

    with st.form("scan_form", clear_on_submit=False):
        url_input = st.text_input(
            "🌐 Website URL",
            placeholder="https://example.com",
            help="Enter the full URL of the website to scan.",
        )
        auth_confirm = st.checkbox(
            "✅ I confirm I am authorised to scan this website and I understand this tool "
            "performs passive checks only.",
            value=False,
        )
        col1, col2 = st.columns([2, 5])
        with col1:
            submitted = st.form_submit_button("🚀 Start Scan", use_container_width=True)

    if submitted:
        if not auth_confirm:
            st.error("Please confirm you are authorised to scan the target website.")
            return

        if not url_input or url_input.strip() == "":
            st.error("Please enter a URL.")
            return

        is_valid, url_or_error = validate_url(url_input)
        if not is_valid:
            st.error(f"Invalid URL: {url_or_error}")
            return

        url = url_or_error
        st.markdown(f"**Target:** `{url}`")

        # Progress display
        progress_bar = st.progress(0, text="Initialising scan...")
        status_box = st.empty()
        start_time = time.time()

        with st.spinner(""):
            # Security scan
            status_box.markdown('<div class="info-box">🔒 Running security checks (HTTPS, headers, TLS, cookies)...</div>', unsafe_allow_html=True)
            progress_bar.progress(20, text="Security analysis...")
            security_findings = run_security_scan(url)

            # Privacy scan
            status_box.markdown('<div class="info-box">🔏 Running privacy checks (trackers, cookies, privacy policy)...</div>', unsafe_allow_html=True)
            progress_bar.progress(55, text="Privacy analysis...")
            privacy_findings = run_privacy_scan(url)

            # Combine
            all_findings = security_findings + privacy_findings
            progress_bar.progress(70, text="Calculating scores...")

            # Scores
            status_box.markdown('<div class="info-box">📊 Calculating risk scores...</div>', unsafe_allow_html=True)
            scores = calculate_scores(all_findings)

            # Save to DB
            progress_bar.progress(85, text="Saving results...")
            status_box.markdown('<div class="info-box">💾 Saving results to database...</div>', unsafe_allow_html=True)
            scan_id = save_scan_to_db(url, all_findings, scores)

            elapsed = round(time.time() - start_time, 2)
            progress_bar.progress(100, text="Scan complete!")
            status_box.empty()

        # Store in session
        st.session_state.last_scan_url = url
        st.session_state.last_scan_id = scan_id
        st.session_state.last_scan_findings = all_findings
        st.session_state.last_scan_scores = scores

        # Result summary
        st.success(f"✅ Scan completed in {elapsed}s")

        st.markdown("---")
        st.markdown("### 📊 Scan Results Summary")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("🔒 Security Score", f"{scores['security_score']:.0f} / 100")
        c2.metric("🔏 Privacy Score", f"{scores['privacy_score']:.0f} / 100")
        c3.metric("🤝 Trust Score", f"{scores['trust_score']:.0f} / 100")
        c4.metric("⚠️ Findings", len(all_findings))

        # Severity breakdown
        dist = get_severity_distribution(all_findings)
        sc1, sc2, sc3, sc4, sc5 = st.columns(5)
        sc1.metric("🔴 Critical", dist.get("Critical", 0))
        sc2.metric("🟠 High", dist.get("High", 0))
        sc3.metric("🟡 Medium", dist.get("Medium", 0))
        sc4.metric("🔵 Low", dist.get("Low", 0))
        sc5.metric("🟢 Info", dist.get("Informational", 0))

        st.markdown("""
        <div class="success-box">
            Results saved. Navigate to <b>Security Analysis</b>, <b>Privacy Analysis</b>,
            <b>Weaknesses</b> or <b>Reports</b> for detailed findings.
        </div>
        """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: SECURITY ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
def page_security():
    st.markdown('<div class="page-title">🔒 Security Analysis</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Detailed passive security findings from the most recent scan.</div>', unsafe_allow_html=True)

    findings = st.session_state.get("last_scan_findings", [])
    scores = st.session_state.get("last_scan_scores", {})
    url = st.session_state.get("last_scan_url", "")

    if not findings:
        st.markdown('<div class="info-box">No scan results available. Run a scan from the <b>Scan Website</b> page first.</div>', unsafe_allow_html=True)
        return

    security_findings = [f for f in findings if f.get("category") == "security"]

    st.markdown(f"**Target:** `{url}`")
    st.markdown("---")

    # Score + gauge
    col_gauge, col_summary = st.columns([2, 3])
    with col_gauge:
        sec_score = scores.get("security_score", 0)
        st.plotly_chart(score_gauge(sec_score, "Security Score"), use_container_width=True, key="sec_gauge")

    with col_summary:
        dist = get_severity_distribution(security_findings)
        st.markdown("**Security Findings Breakdown**")
        for sev, cnt in dist.items():
            if cnt > 0:
                color = severity_color(sev)
                st.markdown(
                    f'<div style="display:flex; justify-content:space-between; padding:6px 0; '
                    f'border-bottom:1px solid #1E3A5F;">'
                    f'<span style="color:{color}; font-weight:600;">{sev}</span>'
                    f'<span style="color:#94A3B8;">{cnt} finding(s)</span></div>',
                    unsafe_allow_html=True,
                )

    st.markdown("---")

    # Check categories
    checks = {
        "HTTPS": [f for f in security_findings if "https" in f["finding_name"].lower() or "http" in f["finding_name"].lower()],
        "Security Headers": [f for f in security_findings if any(x in f["finding_name"].lower() for x in ["hsts", "csp", "content-security", "x-content", "x-frame", "referrer", "permissions"])],
        "TLS / Certificate": [f for f in security_findings if any(x in f["finding_name"].lower() for x in ["tls", "cert", "ssl"])],
        "Cookies": [f for f in security_findings if "cookie" in f["finding_name"].lower()],
        "Other": [],
    }
    # Bucket uncategorised
    already = set()
    for group in checks.values():
        for f in group:
            already.add(f["finding_name"])
    checks["Other"] = [f for f in security_findings if f["finding_name"] not in already]

    tabs = st.tabs(list(checks.keys()))
    for tab, (group_name, group_findings) in zip(tabs, checks.items()):
        with tab:
            if not group_findings:
                st.markdown('<div class="success-box">✅ No issues detected in this category.</div>', unsafe_allow_html=True)
                continue
            for f in sorted(group_findings, key=lambda x: severity_order(x.get("severity", "Informational"))):
                _render_finding_card(f)


def _render_finding_card(f: dict, show_ai_button: bool = False, finding_idx: int = 0):
    sev = f.get("severity", "Informational")
    sev_clr = severity_color(sev)
    with st.expander(f"{badge_html(sev)}&nbsp;&nbsp;{f.get('finding_name', 'Finding')}", expanded=(sev in ["Critical", "High"])):
        c1, c2, c3 = st.columns(3)
        c1.markdown(f"**Category:** {f.get('category', '').title()}")
        c2.markdown(f"**Severity:** <span style='color:{sev_clr}; font-weight:700;'>{sev}</span>", unsafe_allow_html=True)
        c3.markdown(f"**Confidence:** {f.get('confidence', '')}")

        if f.get("evidence"):
            st.markdown("**Evidence:**")
            st.markdown(f'<div class="finding-evidence">{f["evidence"]}</div>', unsafe_allow_html=True)

        if f.get("impact"):
            st.markdown(f"**Business Impact:** {f['impact']}")

        if f.get("recommendation"):
            st.markdown(f"**Recommended Fix:** {f['recommendation']}")

        if f.get("ai_explanation"):
            st.markdown("---")
            st.markdown("**🤖 AI Explanation:**")
            st.markdown(f.get("ai_explanation", ""))


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: PRIVACY ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
def page_privacy():
    st.markdown('<div class="page-title">🔏 Privacy Analysis</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Third-party tracking detection, cookie analysis and privacy policy assessment.</div>', unsafe_allow_html=True)

    findings = st.session_state.get("last_scan_findings", [])
    scores = st.session_state.get("last_scan_scores", {})
    url = st.session_state.get("last_scan_url", "")

    if not findings:
        st.markdown('<div class="info-box">No scan results available. Run a scan from the <b>Scan Website</b> page first.</div>', unsafe_allow_html=True)
        return

    privacy_findings = [f for f in findings if f.get("category") == "privacy"]

    st.markdown(f"**Target:** `{url}`")
    st.markdown("""
    <div class="info-box">
        <b>Important:</b> Detecting an external resource request does <b>not</b> confirm tracking.
        Only resources matching the known tracker domain reference list are classified as likely
        tracking. All findings are labelled with their confidence level.
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")

    col_gauge, col_summary = st.columns([2, 3])
    with col_gauge:
        priv_score = scores.get("privacy_score", 0)
        st.plotly_chart(score_gauge(priv_score, "Privacy Score"), use_container_width=True, key="priv_gauge")

    with col_summary:
        dist = get_severity_distribution(privacy_findings)
        st.markdown("**Privacy Findings Breakdown**")
        for sev, cnt in dist.items():
            if cnt > 0:
                color = severity_color(sev)
                st.markdown(
                    f'<div style="display:flex; justify-content:space-between; padding:6px 0; '
                    f'border-bottom:1px solid #1E3A5F;">'
                    f'<span style="color:{color}; font-weight:600;">{sev}</span>'
                    f'<span style="color:#94A3B8;">{cnt} finding(s)</span></div>',
                    unsafe_allow_html=True,
                )

    st.markdown("---")

    # Group by sub-category
    checks = {
        "Cookies": [f for f in privacy_findings if "cookie" in f["finding_name"].lower()],
        "Trackers & Analytics": [f for f in privacy_findings if any(x in f["finding_name"].lower() for x in ["analytics", "advertising", "tracking", "fingerprint", "social"])],
        "External Resources": [f for f in privacy_findings if "external" in f["finding_name"].lower()],
        "Privacy Policy": [f for f in privacy_findings if "privacy policy" in f["finding_name"].lower() or "privacy" in f["finding_name"].lower()],
        "Other": [],
    }
    already = set()
    for group in checks.values():
        for f in group:
            already.add(f["finding_name"])
    checks["Other"] = [f for f in privacy_findings if f["finding_name"] not in already]

    tabs = st.tabs(list(checks.keys()))
    for tab, (gname, gfindings) in zip(tabs, checks.items()):
        with tab:
            if not gfindings:
                st.markdown('<div class="success-box">✅ No issues detected in this category.</div>', unsafe_allow_html=True)
                continue
            for f in sorted(gfindings, key=lambda x: severity_order(x.get("severity", "Informational"))):
                _render_finding_card(f)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: WEAKNESSES
# ═══════════════════════════════════════════════════════════════════════════════
def page_weaknesses():
    st.markdown('<div class="page-title">⚠️ Weaknesses</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">All detected findings from the most recent scan with filtering and details.</div>', unsafe_allow_html=True)

    findings = st.session_state.get("last_scan_findings", [])
    url = st.session_state.get("last_scan_url", "")

    if not findings:
        st.markdown('<div class="info-box">No scan results available. Run a scan from the <b>Scan Website</b> page first.</div>', unsafe_allow_html=True)
        return

    st.markdown(f"**Target:** `{url}`  |  **Total findings:** {len(findings)}")
    st.markdown("---")

    # Filter bar
    col_sev, col_cat, col_search = st.columns([2, 2, 3])
    with col_sev:
        sev_filter = st.multiselect(
            "Filter by Severity",
            ["Critical", "High", "Medium", "Low", "Informational"],
            default=["Critical", "High", "Medium", "Low", "Informational"],
            key="weaknesses_sev_filter",
        )
    with col_cat:
        cat_filter = st.multiselect(
            "Filter by Category",
            ["security", "privacy"],
            default=["security", "privacy"],
            key="weaknesses_cat_filter",
        )
    with col_search:
        search_term = st.text_input("🔍 Search findings", placeholder="keyword...", key="weaknesses_search")

    # Apply filters
    filtered = [
        f for f in findings
        if f.get("severity", "Informational") in sev_filter
        and f.get("category", "security") in cat_filter
        and (not search_term or search_term.lower() in f.get("finding_name", "").lower()
             or search_term.lower() in (f.get("evidence", "") or "").lower())
    ]

    st.markdown(f"**Showing {len(filtered)} of {len(findings)} findings**")
    st.markdown("---")

    if not filtered:
        st.info("No findings match the current filters.")
        return

    # Sort by severity
    filtered_sorted = sorted(filtered, key=lambda x: severity_order(x.get("severity", "Informational")))

    # Table view
    table_data = []
    for f in filtered_sorted:
        table_data.append({
            "Finding": f.get("finding_name", ""),
            "Category": f.get("category", "").title(),
            "Severity": f.get("severity", ""),
            "Confidence": f.get("confidence", ""),
            "Evidence (truncated)": (f.get("evidence") or "")[:80] + "..." if len(f.get("evidence") or "") > 80 else f.get("evidence", ""),
        })

    df = pd.DataFrame(table_data)
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown("### 🔍 Detailed View")

    for f in filtered_sorted:
        _render_finding_card(f)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: AI EXPLANATION
# ═══════════════════════════════════════════════════════════════════════════════
def page_ai():
    st.markdown('<div class="page-title">🤖 AI Explanation</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Plain-language explanations of detected findings powered by Groq AI.</div>', unsafe_allow_html=True)

    findings = st.session_state.get("last_scan_findings", [])
    url = st.session_state.get("last_scan_url", "")

    if not findings:
        st.markdown('<div class="info-box">No scan results available. Run a scan first.</div>', unsafe_allow_html=True)
        return

    ai_ok = is_ai_available()

    if not ai_ok:
        st.markdown("""
        <div class="warn-box">
            <b>🔴 AI Offline:</b> Groq API key not configured.<br>
            Add <code>GROQ_API_KEY=your_key</code> to a <code>.env</code> file in the project root
            and restart the app. The app works fully without AI — explanations will show
            structured fallback text based on the finding data.
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown('<div class="success-box">🟢 Groq AI is connected. Explanations use the Llama3 model.</div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="info-box">
        <b>Safety note:</b> The AI only explains findings already detected by deterministic rules.
        It cannot invent new vulnerabilities, change severity levels or modify recommendations.
    </div>
    """, unsafe_allow_html=True)

    st.markdown(f"**Target:** `{url}`")
    st.markdown("---")

    # Select a finding to explain
    finding_names = [f"{i+1}. [{f.get('severity')}] {f.get('finding_name')}" for i, f in enumerate(findings)]
    selected_idx = st.selectbox("Select a finding to explain:", range(len(finding_names)), format_func=lambda i: finding_names[i], key="ai_select")

    if st.button("🤖 Generate Explanation", key="ai_explain_btn"):
        selected_finding = findings[selected_idx]
        with st.spinner("Generating AI explanation..."):
            explanation = explain_finding(selected_finding)
            st.session_state.last_ai_explanation = explanation
            st.session_state.last_ai_finding = selected_finding

    if "last_ai_explanation" in st.session_state:
        f = st.session_state.last_ai_finding
        exp = st.session_state.last_ai_explanation

        st.markdown("---")
        st.markdown(f"### 📋 {f.get('finding_name')}")
        col1, col2 = st.columns(2)
        col1.markdown(f"**Severity:** <span style='color:{severity_color(f.get('severity', ''))}; font-weight:700;'>{f.get('severity')}</span>", unsafe_allow_html=True)
        col2.markdown(f"**Confidence:** {f.get('confidence')}")

        st.markdown("""
        <div style='background:rgba(30,144,255,0.07); border:1px solid #1E3A5F; border-radius:10px; padding:20px; margin-top:12px;'>
        """, unsafe_allow_html=True)
        st.markdown(exp)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")

    # Bulk explain
    st.markdown("### 📦 Explain All Findings (Batch)")
    if st.button("🤖 Generate All Explanations", key="ai_explain_all_btn"):
        with st.spinner(f"Generating explanations for {len(findings)} findings..."):
            all_explanations = explain_all_findings(findings)
            st.session_state.all_ai_explanations = all_explanations
            # Update findings in session state with AI explanations
            for i, finding in enumerate(findings):
                finding["ai_explanation"] = all_explanations.get(i, "")
            st.session_state.last_scan_findings = findings
        st.success(f"Generated {len(all_explanations)} explanations.")

    if "all_ai_explanations" in st.session_state:
        st.markdown("#### All AI Explanations")
        for i, f in enumerate(findings):
            exp = st.session_state.all_ai_explanations.get(i, "")
            if exp:
                with st.expander(f"{i+1}. {f.get('finding_name')}", expanded=False):
                    st.markdown(exp)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: REPORTS
# ═══════════════════════════════════════════════════════════════════════════════
def page_reports():
    st.markdown('<div class="page-title">📄 Reports</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Download PDF security assessment reports for completed scans.</div>', unsafe_allow_html=True)

    findings = st.session_state.get("last_scan_findings", [])
    scores = st.session_state.get("last_scan_scores", {})
    scan_id = st.session_state.get("last_scan_id", -1)
    url = st.session_state.get("last_scan_url", "")

    if not findings:
        st.markdown('<div class="info-box">No scan results available. Run a scan from the <b>Scan Website</b> page first.</div>', unsafe_allow_html=True)
        return

    st.markdown(f"**Target:** `{url}`  |  **Scan ID:** #{scan_id}")
    st.markdown("---")

    # Report options
    col1, col2 = st.columns(2)
    with col1:
        include_ai = st.checkbox(
            "Include AI explanations in report",
            value=bool(st.session_state.get("all_ai_explanations")),
            key="report_include_ai",
        )
    with col2:
        st.markdown(f"**Findings to include:** {len(findings)}")

    if st.button("📄 Generate PDF Report", key="gen_report_btn"):
        with st.spinner("Generating PDF report..."):
            ai_expl = st.session_state.get("all_ai_explanations") if include_ai else None

            # Fetch scan date from DB
            db = get_session()
            try:
                scan_obj = db.query(Scan).filter(Scan.id == scan_id).first()
                scan_date = scan_obj.scan_date if scan_obj else datetime.utcnow()
            finally:
                db.close()

            filepath = generate_pdf_report(
                url=url,
                scan_id=scan_id,
                scan_date=scan_date,
                security_score=scores.get("security_score", 0),
                privacy_score=scores.get("privacy_score", 0),
                trust_score=scores.get("trust_score", 0),
                findings=findings,
                ai_explanations=ai_expl,
            )

            # Save report path in DB
            if scan_id > 0:
                db = get_session()
                try:
                    report_rec = Report(scan_id=scan_id, report_path=filepath)
                    db.add(report_rec)
                    db.commit()
                finally:
                    db.close()

            st.session_state.last_report_path = filepath
            st.success(f"✅ Report generated: `{os.path.basename(filepath)}`")

    if "last_report_path" in st.session_state:
        path = st.session_state.last_report_path
        if os.path.exists(path):
            with open(path, "rb") as f:
                pdf_bytes = f.read()

            st.download_button(
                label="⬇️ Download PDF Report",
                data=pdf_bytes,
                file_name=os.path.basename(path),
                mime="application/pdf",
                key="download_pdf_btn",
            )

            st.markdown(f"""
            <div class="success-box">
                Report saved to: <code>{path}</code><br>
                File size: {len(pdf_bytes) / 1024:.1f} KB
            </div>
            """, unsafe_allow_html=True)

    # Previous reports
    st.markdown("---")
    st.markdown("### 📂 Previous Reports")
    db = get_session()
    try:
        reports = (
            db.query(Report, Scan, Website)
            .join(Scan, Report.scan_id == Scan.id)
            .join(Website, Scan.website_id == Website.id)
            .order_by(Report.generated_at.desc())
            .limit(20)
            .all()
        )
        if not reports:
            st.info("No previous reports found.")
        else:
            for rep, scan, site in reports:
                exists = rep.report_path and os.path.exists(rep.report_path)
                status = "✅ Available" if exists else "❌ File not found"
                st.markdown(
                    f"**#{rep.id}** | {site.website_url} | Scan #{scan.id} | "
                    f"{format_datetime(rep.generated_at)} | {status}"
                )
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: REASSESSMENT
# ═══════════════════════════════════════════════════════════════════════════════
def page_reassessment():
    st.markdown('<div class="page-title">🔄 Reassessment</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-subtitle">Compare two scans to track security improvements over time.</div>', unsafe_allow_html=True)

    url = st.session_state.get("last_scan_url", "")

    # URL selector
    col1, col2 = st.columns([4, 1])
    with col1:
        url_input = st.text_input("🌐 Website URL to compare", value=url, key="reassess_url")
    with col2:
        load_btn = st.button("Load Scans", key="reassess_load_btn")

    if load_btn or url_input:
        is_valid, url_or_err = validate_url(url_input)
        if not is_valid:
            st.error(f"Invalid URL: {url_or_err}")
            return

        target_url = url_or_err
        scans = get_scans_for_url(target_url)

        if not scans:
            st.markdown(f'<div class="warn-box">No completed scans found for <b>{target_url}</b>. Run a scan first.</div>', unsafe_allow_html=True)
            return

        st.markdown(f"**Found {len(scans)} scan(s) for** `{target_url}`")

        if len(scans) < 2:
            st.markdown("""
            <div class="warn-box">
                Only 1 scan found. Run another scan on the same URL to enable comparison.
            </div>
            """, unsafe_allow_html=True)

            # Show the single scan
            s = scans[0]
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("🔒 Security Score", f"{s['security_score']:.0f}")
            c2.metric("🔏 Privacy Score", f"{s['privacy_score']:.0f}")
            c3.metric("🤝 Trust Score", f"{s['trust_score']:.0f}")
            c4.metric("⚠️ Findings", s["total_findings"])
            return

        # Scan selectors
        scan_options = {
            f"Scan #{s['id']} – {format_datetime(s['date'])} (Sec:{s['security_score']:.0f})": s["id"]
            for s in scans
        }
        col_a, col_b = st.columns(2)
        with col_a:
            old_label = st.selectbox("📅 Baseline Scan (older)", list(scan_options.keys()), index=min(1, len(scan_options)-1), key="reassess_old")
        with col_b:
            new_label = st.selectbox("📅 Comparison Scan (newer)", list(scan_options.keys()), index=0, key="reassess_new")

        old_id = scan_options[old_label]
        new_id = scan_options[new_label]

        if old_id == new_id:
            st.warning("Please select two different scans to compare.")
            return

        if st.button("🔄 Compare Scans", key="reassess_compare_btn"):
            result = compare_scans(old_id, new_id)

            if "error" in result:
                st.error(result["error"])
                return

            st.markdown("---")
            st.markdown("### 📊 Score Comparison")

            old_s = result["old_scan"]
            new_s = result["new_scan"]

            c1, c2, c3 = st.columns(3)
            sec_delta = result["security_delta"]
            priv_delta = result["privacy_delta"]
            trust_delta = result["trust_delta"]

            c1.metric(
                "🔒 Security Score",
                f"{new_s['security_score']:.0f}",
                delta=f"{sec_delta:+.1f}",
            )
            c2.metric(
                "🔏 Privacy Score",
                f"{new_s['privacy_score']:.0f}",
                delta=f"{priv_delta:+.1f}",
            )
            c3.metric(
                "🤝 Trust Score",
                f"{new_s['trust_score']:.0f}",
                delta=f"{trust_delta:+.1f}",
            )

            # Score comparison bar chart
            fig = go.Figure()
            categories = ["Security", "Privacy", "Trust"]
            old_vals = [old_s["security_score"], old_s["privacy_score"], old_s["trust_score"]]
            new_vals = [new_s["security_score"], new_s["privacy_score"], new_s["trust_score"]]

            fig.add_trace(go.Bar(name="Baseline", x=categories, y=old_vals,
                                 marker_color="#FF8C00", text=[f"{v:.0f}" for v in old_vals],
                                 textposition="outside"))
            fig.add_trace(go.Bar(name="Current", x=categories, y=new_vals,
                                 marker_color="#1E90FF", text=[f"{v:.0f}" for v in new_vals],
                                 textposition="outside"))
            fig.update_layout(
                barmode="group",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font={"family": "Inter", "color": "#E2E8F0"},
                legend=dict(bgcolor="rgba(0,0,0,0)"),
                yaxis=dict(range=[0, 110], gridcolor="#1E3A5F"),
                xaxis=dict(gridcolor="#1E3A5F"),
                height=320,
                margin=dict(t=20, b=20),
            )
            st.plotly_chart(fig, use_container_width=True, key="reassess_bar_chart")

            st.markdown("---")

            # Finding comparison
            col_res, col_new, col_rem = st.columns(3)

            with col_res:
                st.markdown(f"### ✅ Resolved ({len(result['resolved'])})")
                if result["resolved"]:
                    for f in result["resolved"]:
                        st.markdown(f'<div class="success-box">✅ {f["finding_name"]}</div>', unsafe_allow_html=True)
                else:
                    st.info("None resolved.")

            with col_new:
                st.markdown(f"### 🆕 New Findings ({len(result['new_findings'])})")
                if result["new_findings"]:
                    for f in result["new_findings"]:
                        st.markdown(f'<div class="warn-box">🆕 {f["finding_name"]} – {f["severity"]}</div>', unsafe_allow_html=True)
                else:
                    st.info("No new findings.")

            with col_rem:
                st.markdown(f"### ⚠️ Remaining ({len(result['remaining'])})")
                if result["remaining"]:
                    for f in result["remaining"]:
                        sev = f.get("severity", "")
                        st.markdown(f'<div class="finding-row"><span class="finding-name">{f["finding_name"]}</span><br>{badge_html(sev)}</div>', unsafe_allow_html=True)
                else:
                    st.success("All previous findings resolved!")

            st.markdown("---")
            # Summary message
            if sec_delta > 0 or priv_delta > 0:
                st.markdown(f'<div class="success-box">📈 Overall improvement: Security +{sec_delta:.1f}, Privacy +{priv_delta:.1f}, Trust +{trust_delta:.1f}</div>', unsafe_allow_html=True)
            elif sec_delta == 0 and priv_delta == 0:
                st.markdown('<div class="info-box">ℹ️ Scores unchanged between scans.</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="warn-box">📉 Scores changed: Security {sec_delta:.1f}, Privacy {priv_delta:.1f}, Trust {trust_delta:.1f}</div>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN APP ROUTER
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    inject_css()
    render_sidebar()

    page = st.session_state.get("page", "Dashboard")

    if page == "Dashboard":
        page_dashboard()
    elif page == "Scan Website":
        page_scan()
    elif page == "Security Analysis":
        page_security()
    elif page == "Privacy Analysis":
        page_privacy()
    elif page == "Weaknesses":
        page_weaknesses()
    elif page == "AI Explanation":
        page_ai()
    elif page == "Reports":
        page_reports()
    elif page == "Reassessment":
        page_reassessment()
    else:
        page_dashboard()


if __name__ == "__main__":
    main()
