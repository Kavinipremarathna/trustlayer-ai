from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_check():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "trustlayer-ai"}


def test_scan_url_success():
    fake_analysis = {
        "domain": "example.com",
        "uses_https": True,
        "suspicious_keywords": False,
        "long_url": False,
        "has_at_symbol": False,
        "ip_host": False,
        "suspicious_tld": False,
        "subdomain_depth": 0,
    }
    fake_risk = {
        "score": 10,
        "label": "Safe",
        "reasons": ["No high-risk indicators"],
        "signals": [],
        "scope": "balanced",
        "confidence": "Low",
        "recommendations": [],
    }

    with patch("app.services.url_service.analyze_url", return_value=fake_analysis), patch(
        "app.services.url_service.calculate_risk", return_value=fake_risk
    ):
        response = client.post("/scan-url/", json={"url": "https://example.com", "scope": "balanced"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["analysis"]["domain"] == "example.com"
    assert payload["risk"]["label"] == "Safe"


def test_scan_url_invalid_scheme():
    response = client.post("/scan-url/", json={"url": "ftp://example.com", "scope": "balanced"})

    assert response.status_code == 400
    assert response.json()["detail"] == "URL must start with http:// or https://"


def test_scan_url_missing_required_field():
    response = client.post("/scan-url/", json={"scope": "balanced"})

    assert response.status_code == 422


def test_scan_file_success():
    fake_analysis = {
        "filename": "invoice.pdf",
        "detected_type": "application/pdf",
        "extension": "pdf",
        "mismatch": False,
        "suspicious_strings": False,
        "suspicious_string_hits": 0,
        "size_bytes": 100,
        "is_large_file": False,
        "entropy": 3.1,
        "high_entropy": False,
        "double_extension": False,
        "macro_like_content": False,
        "scriptable_extension": False,
    }
    fake_risk = {
        "score": 0,
        "label": "Safe",
        "reasons": [],
        "signals": [],
        "scope": "balanced",
        "confidence": "Low",
        "recommendations": [],
    }

    with patch(
        "app.services.file_service.analyze_file", AsyncMock(return_value=fake_analysis)
    ), patch("app.services.file_service.calculate_risk", return_value=fake_risk):
        response = client.post(
            "/scan-file/?scope=balanced",
            files={"file": ("invoice.pdf", b"%PDF-sample", "application/pdf")},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["analysis"]["filename"] == "invoice.pdf"
    assert payload["risk"]["score"] == 0