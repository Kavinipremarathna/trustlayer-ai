# TrustLayer AI MVP

## Setup

### Backend

cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload

### Frontend

cd frontend
npm install
npm start

### Tests

cd backend
pip install -r requirements-dev.txt
pytest

### Docker Compose

docker compose up --build

### Vercel

The app is wired for Vercel as a single deployment:

1. Push this repository to GitHub and import it into Vercel.
2. Keep the project root as the repository root.
3. Deploy with the default Python runtime. Vercel will use [main.py](main.py) for the FastAPI app, which serves the frontend from [frontend/index.html](frontend/index.html) and exposes the API under `/api/*`.

Vercel needs the runtime dependencies at the repository root, so keep [requirements.txt](requirements.txt) in sync with the backend packages used by the deployed app.

After deployment, open the root URL to reach the frontend. The browser UI calls the API on the same origin, so file and URL scans work without extra environment variables.

### Windows Deploy Helper

From the repo root, run [deploy-vercel.ps1](deploy-vercel.ps1) in PowerShell or double-click [deploy-vercel.bat](deploy-vercel.bat) to:

1. commit local changes if needed,
2. push `main` to GitHub, and
3. deploy the app to Vercel.

You can skip any step with `-SkipCommit`, `-SkipPush`, or `-SkipDeploy`.

### Health Check

Backend health endpoint: <http://127.0.0.1:8000/api/health>

Expected response:
{"status":"ok","service":"trustlayer-ai"}

## Features

- File scanning
- URL scanning
- Scope-based risk scoring (Quick, Balanced, Strict)
- Detection confidence and response recommendations
- Enhanced file and URL threat heuristics
- API tests for key scan routes
- Dockerized backend and frontend startup
