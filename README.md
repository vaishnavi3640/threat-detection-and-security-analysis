# 🛡️ WebShield — Threat Detection & Security Analysis System

A modern, browser-based website security and privacy assessment dashboard built with vanilla HTML, CSS, and JavaScript.

## Features

- **Dashboard** — Cyber risk score, top risks, security incidents, and asset footprint
- **Scan Website** — Authorized, non-intrusive security & privacy assessment flow
- **Attack Surface** — Discovered assets and entry-point analysis
- **Security Analysis** — TLS, headers, cookies, and session security indicators
- **Privacy Analysis** — Cookie consent, third-party trackers, and transparency signals
- **Weaknesses** — Findings list with OWASP mapping and severity ratings
- **Security Hardening** — Prioritized fix recommendations with score estimates
- **Reassessment** — Before/after score comparison after applying fixes
- **Reports** — Exportable assessment reports
- **History** — Scan history and score timeline

## Tech Stack

- Vanilla JavaScript (no frameworks)
- CSS custom properties with dark-mode design system
- Responsive layout (mobile, tablet, desktop)
- Accessible: semantic HTML, ARIA labels, keyboard navigation

## Getting Started

Just open `index.html` in a browser — no build step required.

```bash
# Or serve locally with any static server, e.g.:
npx serve .
```

## Project Structure

```
├── index.html       # App shell & sidebar navigation
├── app.js           # All page logic, rendering, and interactions
├── styles.css       # Core design system and component styles
└── dashboard.css    # Dashboard-specific layout and card styles
```

## Notes

This is a **prototype / demo**. No live network requests are made to any target website. All scan results are illustrative sample data for demonstration purposes.

---

© 2026 WebShield — Capstone Project
