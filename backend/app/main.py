import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response

from app.api.routes import router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="TrustLayer AI", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")

frontend_dir = Path(__file__).resolve().parents[2] / "frontend"
frontend_index_path = frontend_dir / "index.html"
frontend_app_js_path = frontend_dir / "app.js"

if frontend_index_path.exists():
    frontend_index_html = frontend_index_path.read_text(encoding="utf-8")

    @app.get("/", response_class=HTMLResponse)
    def frontend_index():
        return frontend_index_html

    @app.get("/index.html", response_class=HTMLResponse)
    def frontend_index_alias():
        return frontend_index_html

if frontend_app_js_path.exists():
    frontend_app_js = frontend_app_js_path.read_text(encoding="utf-8")

    @app.get("/app.js")
    def frontend_app_js_route():
        return Response(frontend_app_js, media_type="application/javascript")