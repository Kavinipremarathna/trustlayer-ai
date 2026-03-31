# TrustLayer AI MVP

## Setup

### Backend

cd backend
pip install fastapi uvicorn python-multipart python-magic puremagic tldextract
uvicorn main:app --reload

### Frontend

cd frontend
npm install
npm start

## Features

- File scanning
- URL scanning
- Scope-based risk scoring (Quick, Balanced, Strict)
- Detection confidence and response recommendations
- Enhanced file and URL threat heuristics
