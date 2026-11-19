# Contributing

## Setup

1. Clone the repo
2. Install backend deps: `pip install -r backend/requirements.txt`
3. Install frontend deps: `cd frontend-react && npm install`
4. Run backend: `python backend/run.py`
5. Run frontend: `cd frontend-react && npm run dev`

## Branches

- `master` is the main branch
- Create your own branch for features: `git checkout -b your-name/feature`
- Push and open a pull request when done

## Commit Messages

Try to keep commit messages clear, like:
- `add scan results page`
- `fix dashboard score calculation`
- `update database schema`

## Folder Guide

- `backend/` - Flask API, edit this if you're working on API endpoints
- `frontend-react/src/pages/` - React pages, each page is its own file
- `threatguard/modules/` - scanning logic, privacy checks, scoring
- `database/` - SQL schema files
