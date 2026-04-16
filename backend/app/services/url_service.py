import logging
from urllib.parse import urlparse

from fastapi import HTTPException

from analyzers.url_analyzer import analyze_url

from app.core.risk_engine import calculate_risk

logger = logging.getLogger(__name__)


def scan_url(url, scope="balanced"):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    analysis = analyze_url(url)
    risk = calculate_risk(analysis, scope)
    logger.info("URL scanned successfully: %s", analysis.get("domain", "unknown"))
    return {"analysis": analysis, "risk": risk}