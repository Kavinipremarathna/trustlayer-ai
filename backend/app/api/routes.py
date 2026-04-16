import logging

from fastapi import APIRouter, File, HTTPException, Query, UploadFile

from app.models.schemas import ScanResponse, ScanScope, URLScanRequest
from app.services.file_service import scan_file
from app.services.url_service import scan_url

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/health")
def health_check():
    return {"status": "ok", "service": "trustlayer-ai"}


@router.post("/scan-file/", response_model=ScanResponse)
async def scan_file_route(
    file: UploadFile = File(...),
    scope: ScanScope = Query(default="balanced"),
):
    try:
        return await scan_file(file, scope)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("File scan failed")
        raise HTTPException(status_code=500, detail="File scan failed") from exc


@router.post("/scan-url/", response_model=ScanResponse)
async def scan_url_route(request: URLScanRequest):
    try:
        return scan_url(request.url, request.scope)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("URL scan failed")
        raise HTTPException(status_code=500, detail="URL scan failed") from exc