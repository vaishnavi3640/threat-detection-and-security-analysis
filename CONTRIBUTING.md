# Contributing to ThreatGuard

Thank you for contributing to this project! Here's how to get started.

## Getting Started

1. **Fork** the repository
2. **Clone** your fork locally
3. Create a **feature branch**: `git checkout -b feature/your-feature-name`
4. Make your changes
5. **Commit** with meaningful messages: `git commit -m "feat(scope): description"`
6. **Push** your branch: `git push origin feature/your-feature-name`
7. Open a **Pull Request** to the `master` branch

## Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Description |
|--------|-------------|
| `feat(scope):` | New feature |
| `fix(scope):` | Bug fix |
| `refactor(scope):` | Code refactoring |
| `docs:` | Documentation only |
| `style:` | Formatting, no code change |
| `test:` | Adding tests |
| `chore:` | Build, CI, deps |

**Scopes**: `frontend`, `backend`, `database`, `modules`, `docs`

## Project Structure

- `backend/` — Flask REST API
- `frontend-react/` — React + Vite SPA
- `threatguard/` — Python scanning engine modules
- `database/` — MySQL reference schema

## Running Locally

```bash
# Backend
pip install -r backend/requirements.txt
python backend/run.py

# Frontend
cd frontend-react && npm install && npm run dev
```

## Code Guidelines

- Python: PEP 8, type hints where possible
- React: Functional components, hooks only
- CSS: CSS custom properties (no Tailwind)
- Database: SQLAlchemy ORM for runtime, raw SQL for reference schema
