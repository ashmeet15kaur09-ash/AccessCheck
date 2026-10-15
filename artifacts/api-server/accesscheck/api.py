from __future__ import annotations

import asyncio
import csv
import io
import re
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field

from accesscheck import database
from accesscheck.scanner import (
    ScanTimedOut,
    SiteScanError,
    UnsafeRedirectError,
    run_accessibility_scan,
)
from accesscheck.security import UnsafeTarget, redact_url, validate_public_url

_scan_slots = threading.BoundedSemaphore(2)
_SCAN_ID = re.compile(r"^[0-9a-f]{32}$")


def _camel(name: str) -> str:
    first, *rest = name.split("_")
    return first + "".join(part.title() for part in rest)


class ApiModel(BaseModel):
    model_config = ConfigDict(alias_generator=_camel, populate_by_name=True)


class ScanInput(ApiModel):
    url: str = Field(min_length=8, max_length=2048)


class FindingNode(ApiModel):
    target: list[str]
    html: str
    failure_summary: str


class Finding(ApiModel):
    id: str
    impact: str
    description: str
    help: str
    help_url: str
    rule_id: str
    wcag: list[str]
    nodes: list[FindingNode]


class ScanSummary(ApiModel):
    id: str
    url: str
    domain: str
    title: str
    status: str
    created_at: datetime
    duration_ms: int
    violation_count: int
    critical_count: int
    serious_count: int
    moderate_count: int
    minor_count: int


class Scan(ScanSummary):
    page_title: str
    findings: list[Finding]
    pass_count: int
    incomplete_count: int
    page_url: str
    error: str | None


class SeverityCounts(ApiModel):
    critical: int
    serious: int
    moderate: int
    minor: int


class Dashboard(ApiModel):
    total_scans: int
    total_violations: int
    severity_counts: SeverityCounts
    recent_scans: list[ScanSummary]


@asynccontextmanager
async def lifespan(_: FastAPI):
    await asyncio.to_thread(database.initialize)
    yield


app = FastAPI(
    title="AccessCheck API",
    description="Automated Playwright and axe-core website accessibility scans.",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _failed_scan(
    scan_id: str,
    safe_url: str,
    domain: str,
    created_at: datetime,
    duration_ms: int,
    error: str,
) -> dict[str, Any]:
    return {
        "id": scan_id,
        "url": safe_url,
        "domain": domain,
        "title": domain,
        "page_title": "",
        "page_url": safe_url,
        "status": "failed",
        "created_at": created_at.isoformat(),
        "duration_ms": duration_ms,
        "violation_count": 0,
        "critical_count": 0,
        "serious_count": 0,
        "moderate_count": 0,
        "minor_count": 0,
        "pass_count": 0,
        "incomplete_count": 0,
        "findings": [],
        "error": error,
    }


def _persist(scan: dict[str, Any]) -> None:
    try:
        database.save_scan(scan)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan history is temporarily unavailable.",
        ) from exc


def _get_saved_scan(scan_id: str) -> dict[str, Any] | None:
    if not _SCAN_ID.fullmatch(scan_id):
        return None
    try:
        return database.get_scan(scan_id)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan history is temporarily unavailable.",
        ) from exc


@app.get("/api/healthz", response_model=dict[str, str])
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/dashboard", response_model=Dashboard)
async def get_dashboard() -> dict[str, Any]:
    try:
        return await asyncio.to_thread(database.dashboard)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Dashboard data is temporarily unavailable.",
        ) from exc


@app.get("/api/scans", response_model=list[ScanSummary])
async def list_scan_history(
    limit: int = Query(default=50, ge=1, le=100),
) -> list[dict[str, Any]]:
    try:
        return await asyncio.to_thread(database.list_scans, limit)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan history is temporarily unavailable.",
        ) from exc


@app.get("/api/scans/{scan_id}", response_model=Scan)
async def get_scan(scan_id: str) -> dict[str, Any]:
    scan = await asyncio.to_thread(_get_saved_scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@app.get("/api/scans/{scan_id}/export.csv")
async def export_scan_csv(scan_id: str) -> Response:
    scan = await asyncio.to_thread(_get_saved_scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        [
            "scan_url",
            "scanned_at",
            "rule_id",
            "severity",
            "description",
            "remediation",
            "wcag_references",
            "affected_elements",
            "html",
            "evidence",
        ]
    )
    for finding in scan["findings"]:
        for node in finding["nodes"]:
            values = [
                scan["url"],
                scan["created_at"],
                finding["ruleId"],
                finding["impact"],
                finding["description"],
                finding["help"],
                "; ".join(finding["wcag"]),
                "; ".join(node["target"]),
                node["html"],
                node["failureSummary"],
            ]
            writer.writerow([_safe_csv_cell(value) for value in values])
    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="accesscheck-{scan_id[:12]}.csv"'},
    )


def _safe_csv_cell(value: Any) -> str:
    text = str(value if value is not None else "")
    if text[:1] in {"=", "+", "-", "@"}:
        return "'" + text
    return text


@app.post("/api/scans", response_model=Scan)
async def create_scan(payload: ScanInput) -> dict[str, Any]:
    try:
        target_url = await validate_public_url(payload.url)
    except UnsafeTarget as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not _scan_slots.acquire(blocking=False):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Two scans are already running. Try again shortly.",
        )

    scan_id = uuid.uuid4().hex
    created_at = _now()
    safe_url = redact_url(target_url)
    domain = urlsplit(target_url).hostname or ""
    started = time.monotonic()
    try:
        result = await run_accessibility_scan(target_url)
        duration_ms = int((time.monotonic() - started) * 1000)
        scan = {
            "id": scan_id,
            "url": safe_url,
            "domain": result["domain"],
            "title": result["title"] or domain,
            "page_title": result["pageTitle"],
            "page_url": result["pageUrl"],
            "status": "completed",
            "created_at": created_at.isoformat(),
            "duration_ms": duration_ms,
            "violation_count": result["violationCount"],
            "critical_count": result["criticalCount"],
            "serious_count": result["seriousCount"],
            "moderate_count": result["moderateCount"],
            "minor_count": result["minorCount"],
            "pass_count": result["passCount"],
            "incomplete_count": result["incompleteCount"],
            "findings": result["findings"],
            "error": None,
        }
        await asyncio.to_thread(_persist, scan)
        return scan
    except ScanTimedOut as exc:
        message = str(exc)
        failed = _failed_scan(
            scan_id, safe_url, domain, created_at, int((time.monotonic() - started) * 1000), message
        )
        await asyncio.to_thread(_persist, failed)
        raise HTTPException(status_code=504, detail=message) from exc
    except UnsafeRedirectError as exc:
        message = str(exc)
        failed = _failed_scan(
            scan_id, safe_url, domain, created_at, int((time.monotonic() - started) * 1000), message
        )
        await asyncio.to_thread(_persist, failed)
        raise HTTPException(status_code=400, detail=message) from exc
    except SiteScanError as exc:
        message = str(exc)
        failed = _failed_scan(
            scan_id, safe_url, domain, created_at, int((time.monotonic() - started) * 1000), message
        )
        await asyncio.to_thread(_persist, failed)
        raise HTTPException(status_code=422, detail=message) from exc
    finally:
        _scan_slots.release()
