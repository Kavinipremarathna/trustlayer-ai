from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from analyzers.file_analyzer import analyze_file
from analyzers.url_analyzer import analyze_url
from risk_engine import calculate_risk

app = FastAPI()

# Allow local frontend apps to call the API during development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/scan-file/")
async def scan_file(file: UploadFile = File(...), scope: str = "balanced"):
    result = await analyze_file(file)
    risk = calculate_risk(result, scope)
    return {"analysis": result, "risk": risk}

@app.post("/scan-url/")
async def scan_url(url: str, scope: str = "balanced"):
    result = analyze_url(url)
    risk = calculate_risk(result, scope)
    return {"analysis": result, "risk": risk}
