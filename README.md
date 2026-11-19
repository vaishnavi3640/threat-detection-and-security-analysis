# ThreatGuard - Threat Detection & Security Analysis System

A web app that scans websites for security vulnerabilities and privacy issues. Built with React frontend, Flask backend, and SQLite database.

## Project Structure

```
├── backend/              # Flask API server
│   ├── app.py            # API routes
│   ├── run.py            # start the server
│   └── requirements.txt  # python dependencies
│
├── frontend-react/       # React app (Vite)
│   ├── src/pages/        # all the pages (dashboard, scan, results, etc)
│   ├── src/App.jsx       # main layout with sidebar
│   ├── src/api.js        # API calls to backend
│   └── package.json
│
├── threatguard/           # python scanning modules
│   ├── database/          # SQLAlchemy models
│   ├── modules/           # scanner, privacy analyzer, scoring, etc
│   └── utils/             # helpers and validators
│
├── database/              # MySQL schema (reference)
│   ├── schema.sql
│   ├── seed.sql
│   └── queries.sql
│
└── docker-compose.yml
```

## How to Run

**Backend:**
```
pip install -r backend/requirements.txt
python backend/run.py
```
Server starts at http://localhost:5000

**Frontend:**
```
cd frontend-react
npm install
npm run dev
```
Opens at http://localhost:3000

Both need to be running at the same time. The frontend automatically sends API requests to the backend through the Vite proxy.

## What it Does

- Scans any public website URL
- Checks HTTPS, TLS certificates, security headers (CSP, HSTS, etc)
- Checks cookie security flags (Secure, HttpOnly, SameSite)
- Detects third-party trackers and analytics scripts
- Checks if the site has a privacy policy
- Gives a Trust Score out of 100
- Can generate PDF reports
- Compare old and new scans to track improvements

## API Endpoints

| Method | URL | What it does |
|--------|-----|-------------|
| POST | /api/scan | scan a website |
| GET | /api/scans | list all scans |
| GET | /api/scans/:id | get scan details |
| GET | /api/dashboard | dashboard stats |
| GET | /api/scans/:id/findings | get findings |
| POST | /api/scans/:id/report | generate PDF |
| POST | /api/reassess | compare two scans |
| GET | /api/history | scan history |

## Database

Uses SQLite with SQLAlchemy ORM. Tables: users, websites, scans, findings, reports.
Database file gets created automatically when you first run the backend.

MySQL reference schema is in the `database/` folder.

## Tech Stack

- **Frontend:** React, Vite, React Router, Recharts, Axios
- **Backend:** Flask, Flask-CORS
- **Database:** SQLite + SQLAlchemy
- **Scanning:** requests, BeautifulSoup, ssl module
- **Reports:** ReportLab
- **AI:** Groq API (optional - for explaining findings)

## Environment Variables

Create a `.env` file in backend/ (optional):
```
GROQ_API_KEY=your_key_here
```

## Team

| Name | Work |
|------|------|
| Vaishnavi | Frontend (React) + Backend API |
| Aishwarya | Database Schema |
| Aditi | Backend Modules |
