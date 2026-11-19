# 🛡️ ThreatGuard — Threat Detection & Security Analysis System

> A collaborative, full-stack web security scanner with **React frontend**, **Flask REST API backend**, **SQLAlchemy ORM**, and **MySQL reference schema**.

---

## 📁 Project Structure

```
├── backend/                ← Flask REST API server
│   ├── app.py              ← All API routes (scan, findings, dashboard, reports, etc.)
│   ├── run.py              ← Startup script
│   ├── requirements.txt    ← Python dependencies
│   ├── Dockerfile          ← Docker build for backend
│   └── .env.example        ← Environment variable template
│
├── frontend-react/         ← React + Vite frontend (SPA)
│   ├── src/
│   │   ├── pages/          ← Dashboard, ScanPage, ScanResult, Security, Privacy,
│   │   │                     Weaknesses, Reports, History, Reassessment
│   │   ├── components/     ← Shared CSS & reusable components
│   │   ├── App.jsx         ← Router + Sidebar layout
│   │   ├── api.js          ← Axios API client
│   │   └── main.jsx        ← React entry point
│   ├── package.json
│   ├── vite.config.js      ← Dev proxy to Flask backend
│   ├── Dockerfile          ← Production Docker (nginx)
│   └── nginx.conf          ← Reverse proxy config
│
├── threatguard/            ← Python scanning engine (shared modules)
│   ├── database/           ← SQLAlchemy ORM models & session factory
│   │   ├── models.py       ← User, Website, Scan, Finding, Report tables
│   │   └── db.py           ← Engine, session, init_db()
│   ├── modules/            ← Core analysis modules
│   │   ├── security_scanner.py   ← HTTPS, TLS, headers, cookies
│   │   ├── privacy_analyzer.py   ← Trackers, 3rd-party, privacy policy
│   │   ├── scoring_engine.py     ← Security/Privacy/Trust scores
│   │   ├── risk_classifier.py    ← Severity classification rules
│   │   ├── ai_explainer.py       ← Groq LLM explanations
│   │   ├── report_generator.py   ← PDF report generation
│   │   └── reassessment.py       ← Scan comparison
│   ├── utils/              ← Validators, helpers
│   ├── data/               ← Tracker domain lists
│   ├── tests/              ← Test suite
│   └── app.py              ← (Original Streamlit app — still works)
│
├── database/               ← MySQL reference schema (team contribution)
│   ├── schema.sql          ← Full MySQL schema (12 tables)
│   ├── seed.sql            ← Demo data
│   └── queries.sql         ← Common queries
│
├── docker-compose.yml      ← One-command deployment
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.10+** with pip
- **Node.js 18+** with npm

### 1. Install Backend Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Configure Environment (Optional)

```bash
cp backend/.env.example backend/.env
# Edit .env to add your GROQ_API_KEY for AI explanations
```

### 3. Start the Backend API

```bash
python backend/run.py
# → 🛡️ ThreatGuard API running on http://localhost:5000
```

### 4. Start the React Frontend

```bash
cd frontend-react
npm install
npm run dev
# → React app at http://localhost:3000
```

### 5. Open in Browser

Navigate to **http://localhost:3000** — the React app proxies API calls to Flask automatically.

---

## 🔌 REST API Endpoints

| Method | Endpoint                     | Description                              |
|--------|------------------------------|------------------------------------------|
| GET    | `/api/health`                | Health check                             |
| GET    | `/api/dashboard`             | Dashboard stats & averages               |
| POST   | `/api/scan`                  | Run a new scan `{ "url": "..." }`        |
| GET    | `/api/scans`                 | List all completed scans                 |
| GET    | `/api/scans/:id`             | Full scan details with findings          |
| GET    | `/api/scans/:id/findings`    | Findings (optionally `?category=security`) |
| POST   | `/api/scans/:id/explain`     | AI-explain findings (needs GROQ_API_KEY) |
| POST   | `/api/scans/:id/report`      | Generate PDF report                      |
| GET    | `/api/history`               | Scan history grouped by domain           |
| POST   | `/api/reassess`              | Compare scans `{ url }` or `{ scan_id_1, scan_id_2 }` |

---

## 🗃️ Database

### Runtime Database (SQLite + SQLAlchemy ORM)
- Auto-created at `threatguard/threatguard.db` on first run
- Tables: `users`, `websites`, `scans`, `findings`, `reports`
- Defined in [`threatguard/database/models.py`](threatguard/database/models.py)

### Reference Schema (MySQL)
- Full MySQL 8 schema in [`database/schema.sql`](database/schema.sql)
- 12 tables: users, workspaces, assets, scans, findings, incidents, trackers, tickets, risks, notifications, user_settings
- Demo seed data in [`database/seed.sql`](database/seed.sql)

---

## 🧠 Features

| Feature | Description |
|---------|-------------|
| ✅ HTTPS & TLS | Certificate validity, expiry, redirect checks |
| ✅ Security Headers | CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| ✅ Cookie Analysis | Secure, HttpOnly, SameSite flags |
| ✅ Tracker Detection | Google Analytics, Meta Pixel, ad networks, fingerprinting |
| ✅ Privacy Policy | Automated privacy page & keyword detection |
| ✅ Trust Score | 0–100 composite score (security × 0.5 + privacy × 0.5) |
| ✅ AI Explanations | Groq LLM-powered finding explanations |
| ✅ PDF Reports | Downloadable security assessment reports |
| ✅ Reassessment | Compare old vs new scans to track improvements |
| ✅ React Dashboard | Modern dark-themed UI with charts and animations |

---

## 🐳 Docker Deployment

```bash
docker-compose up --build
# Frontend → http://localhost:3000
# Backend  → http://localhost:5000
```

---

## 👥 Team & Contributors

| Contributor | Focus Area |
|-------------|------------|
| Vaishnavi   | Frontend (React) + Backend API Integration |
| Aishwarya | Database Schema (MySQL) |
| Aditi | Backend Modules & Scanning Engine |

---

## 📋 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite, React Router, Recharts, Framer Motion, Lucide Icons |
| Backend  | Flask, Flask-CORS, SQLAlchemy |
| Database | SQLite (runtime), MySQL (reference schema) |
| AI       | Groq API (LLaMA) |
| Reports  | ReportLab (PDF generation) |
| Scanning | Requests, BeautifulSoup, ssl, cryptography |

---

## 🔐 Environment Variables

```env
GROQ_API_KEY=your_key_here        # Optional — enables AI explanations
DATABASE_URL=sqlite:///threatguard.db
FLASK_DEBUG=1
```
