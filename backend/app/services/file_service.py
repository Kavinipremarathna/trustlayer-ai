import logging

from analyzers.file_analyzer import analyze_file

from app.core.risk_engine import calculate_risk

logger = logging.getLogger(__name__)


async def scan_file(file, scope="balanced"):
    analysis = await analyze_file(file)
    risk = calculate_risk(analysis, scope)
    logger.info("File scanned successfully: %s", analysis.get("filename", "unknown"))
    return {"analysis": analysis, "risk": risk}