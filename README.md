# 🛡️ ThreatGuard — Threat Detection & Security Analysis System

> A full-stack web security scanner with **React frontend**, **Flask REST API backend**, and **SQLite database** via SQLAlchemy.

---

## 📁 Project Structure

```
Threat_detection and Security Analysis System/
├── backend/            ← Flask REST API
│   ├── app.py          ← API routes & logic
│   ├── run.py          ← Startup script
│   ├── requirements.txt
│   └── .env.example
├── frontend-react/     ← React + Vite frontend
│   ├── src/
│   │   ├── pages/      ← Dashboard, Scan, Security, Privacy, etc.
│   │   ├── components/
│   │   ├── App.jsx
│   │   └── api.js
│   ├── package.json
│   └── vite.config.js
├── threatguard/        ← Python scanning engine (shared)
│   ├── modules/        ← security_scanner, privacy_analyzer, etc.
│   ├── database/       ← SQLAlchemy models & DB session
│   ├── utils/
│   └── app.py          ← (original Streamlit app — still works)
└── README.md
```

---

## 🚀 Quick Start

### 1. Backend (Flask API)

```bash
# From project root
cd "Threat_detection and Security Analysis System"
pip install -r backend/requirements.txt

# Copy env and configure (optional GROQ_API_KEY for AI explanations)
copy backend\.env.example backend\.env

# Run the API
python backend/run.py
# → API running at http://localhost:5000
```

### 2. Frontend (React)

```bash
cd frontend-react
npm install
npm run dev
# → App running at http://localhost:3000
```

Open **http://localhost:3000** in your browser.

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET  | `/api/health` | Health check |
| GET  | `/api/dashboard` | Dashboard stats |
| POST | `/api/scan` | Run a new scan `{ url }` |
| GET  | `/api/scans` | List recent scans |
| GET  | `/api/scans/:id` | Get scan details |
| GET  | `/api/scans/:id/findings` | Get findings (optionally filter by category) |
| POST | `/api/scans/:id/explain` | AI explain findings (needs GROQ_API_KEY) |
| POST | `/api/scans/:id/report` | Generate PDF report |
| GET  | `/api/history` | Scan history by domain |
| POST | `/api/reassess` | Compare two scans |

---

## 🗃️ Database

- **Engine**: SQLite (via SQLAlchemy ORM)
- **File**: `threatguard/threatguard.db` (auto-created on first run)
- **Tables**: `users`, `websites`, `scans`, `findings`, `reports`

---

## 🧠 Features

- ✅ HTTPS & TLS certificate analysis
- ✅ HTTP security headers (CSP, HSTS, X-Frame-Options…)
- ✅ Cookie security flags (Secure, HttpOnly, SameSite)
- ✅ Privacy tracker detection (Google, Facebook, analytics…)
- ✅ Third-party request enumeration
- ✅ Privacy policy detection
- ✅ AI-powered explanations (via Groq LLM)
- ✅ PDF report generation
- ✅ Historical scan comparison (Reassessment)
- ✅ Beautiful React dashboard with charts

---

## 👥 Contributors

| Name | Role | Branch |
|------|------|--------|
| Vaishnavi | Frontend (React) + Integration | `main` |
| _(add team members)_ | Backend / Database | _(branch)_ |

---

## 📋 Requirements

- Python 3.10+
- Node.js 18+
- pip packages: `flask flask-cors sqlalchemy requests beautifulsoup4 reportlab plotly pandas python-dotenv groq cryptography lxml`

---

## 🔐 Environment Variables

```env
GROQ_API_KEY=your_key_here        # Optional — enables AI explanations
DATABASE_URL=sqlite:///threatguard.db
APP_ENV=development
```
