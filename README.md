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

### Health Check

Backend health endpoint: <http://127.0.0.1:8000/health>

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
