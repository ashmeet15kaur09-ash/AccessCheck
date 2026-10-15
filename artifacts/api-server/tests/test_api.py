from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from accesscheck import database
from accesscheck.api import app
from accesscheck.scanner import ScanTimedOut, SiteScanError, UnsafeRedirectError
from accesscheck.security import UnsafeTarget


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DEFAULT_DB_PATH", tmp_path / "scans.sqlite3")
    monkeypatch.setattr(database, "database_path", lambda: tmp_path / "scans.sqlite3")
    with TestClient(app) as test_client:
        yield test_client


def test_invalid_url_is_rejected_without_a_scan(client, monkeypatch):
    async def reject(_url):
        raise UnsafeTarget("Local and internal hostnames cannot be scanned.")

    monkeypatch.setattr("accesscheck.api.validate_public_url", reject)
    response = client.post("/api/scans", json={"url": "http://localhost"})
    assert response.status_code == 400
    assert "internal" in response.json()["detail"]
    assert client.get("/api/scans").json() == []


def test_completed_scan_with_no_findings_is_a_real_empty_result(client, monkeypatch):
    async def validate(url):
        return url

    async def empty_scan(url):
        return {
            "domain": "example.com",
            "title": "Example Domain",
            "pageTitle": "Example Domain",
            "pageUrl": "https://example.com/",
            "status": "completed",
            "findings": [],
            "violationCount": 0,
            "criticalCount": 0,
            "seriousCount": 0,
            "moderateCount": 0,
            "minorCount": 0,
            "passCount": 32,
            "incompleteCount": 0,
            "error": None,
        }

    monkeypatch.setattr("accesscheck.api.validate_public_url", validate)
    monkeypatch.setattr("accesscheck.api.run_accessibility_scan", empty_scan)
    response = client.post("/api/scans", json={"url": "https://example.com/"})
    assert response.status_code == 200
    scan = response.json()
    assert scan["findings"] == []
    assert scan["passCount"] == 32
    assert client.get("/api/scans/" + scan["id"]).json()["findings"] == []


@pytest.mark.parametrize(
    ("error", "expected_status"),
    [
        (ScanTimedOut("The scan exceeded its time limit. Try again later."), 504),
        (SiteScanError("The website could not be loaded for an accessibility scan."), 422),
        (UnsafeRedirectError("A redirect to a non-public address was blocked."), 400),
    ],
)
def test_redirect_failure_and_timeout_are_handled_safely(
    client, monkeypatch, error, expected_status
):
    async def validate(url):
        return url

    async def fail(_url):
        raise error

    monkeypatch.setattr("accesscheck.api.validate_public_url", validate)
    monkeypatch.setattr("accesscheck.api.run_accessibility_scan", fail)
    response = client.post("/api/scans", json={"url": "https://example.com/"})
    assert response.status_code == expected_status
    assert "Traceback" not in response.text
    history = client.get("/api/scans").json()
    assert len(history) == 1
    assert history[0]["status"] == "failed"


def test_unknown_scan_ids_do_not_expose_files_or_other_records(client):
    response = client.get("/api/scans/../../etc/passwd")
    assert response.status_code in {404, 405}
    assert "root:" not in response.text

    valid_shape_but_missing = client.get("/api/scans/" + "0" * 32)
    assert valid_shape_but_missing.status_code == 404


def test_database_errors_return_safe_service_error(tmp_path, monkeypatch):
    bad_path = tmp_path / "not-a-directory" / "scans.sqlite3"
    bad_path.parent.write_text("not a directory")
    with TestClient(app) as test_client:
        monkeypatch.setattr(database, "database_path", lambda: bad_path)
        response = test_client.get("/api/scans")
    assert response.status_code == 503
    assert "temporarily unavailable" in response.json()["detail"]


def test_csv_export_is_attachment_and_formula_safe(client, monkeypatch):
    async def validate(url):
        return url

    async def one_finding(_url):
        return {
            "domain": "example.com",
            "title": "Example Domain",
            "pageTitle": "Example Domain",
            "pageUrl": "https://example.com/",
            "status": "completed",
            "findings": [
                {
                    "id": "image-alt",
                    "impact": "serious",
                    "description": "Missing image text",
                    "help": "=HYPERLINK(\"bad\")",
                    "helpUrl": "https://example.com/help",
                    "ruleId": "image-alt",
                    "wcag": ["WCAG 1.1.1"],
                    "nodes": [
                        {
                            "target": ["img.hero"],
                            "html": "<img class=\"hero\">",
                            "failureSummary": "Add text alternative",
                        }
                    ],
                }
            ],
            "violationCount": 1,
            "criticalCount": 0,
            "seriousCount": 1,
            "moderateCount": 0,
            "minorCount": 0,
            "passCount": 20,
            "incompleteCount": 0,
            "error": None,
        }

    monkeypatch.setattr("accesscheck.api.validate_public_url", validate)
    monkeypatch.setattr("accesscheck.api.run_accessibility_scan", one_finding)
    scan = client.post("/api/scans", json={"url": "https://example.com/"}).json()
    export = client.get(f"/api/scans/{scan['id']}/export.csv")
    assert export.status_code == 200
    assert "attachment" in export.headers["content-disposition"]
    assert "'=HYPERLINK" in export.text
