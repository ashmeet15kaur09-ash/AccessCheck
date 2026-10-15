from __future__ import annotations

import asyncio
import re
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from accesscheck.security import UnsafeTarget, redact_url, validate_public_url

AXE_CORE_PATH = Path(__file__).resolve().parents[1] / "node_modules" / "axe-core" / "axe.min.js"
SCAN_TIMEOUT_SECONDS = 38
NAVIGATION_TIMEOUT_MS = 24_000
MAX_REQUESTS = 120
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_TOTAL_RESPONSE_BYTES = 24 * 1024 * 1024
MAX_REDIRECTS = 5
MAX_FINDINGS = 200
MAX_NODES_PER_FINDING = 30

WCAG_LEVEL_TAGS = {
    "wcag2a": "WCAG 2.0 A",
    "wcag2aa": "WCAG 2.0 AA",
    "wcag2aaa": "WCAG 2.0 AAA",
    "wcag21a": "WCAG 2.1 A",
    "wcag21aa": "WCAG 2.1 AA",
    "wcag21aaa": "WCAG 2.1 AAA",
    "wcag22a": "WCAG 2.2 A",
    "wcag22aa": "WCAG 2.2 AA",
    "wcag22aaa": "WCAG 2.2 AAA",
}


class SiteScanError(RuntimeError):
    pass


class UnsafeRedirectError(SiteScanError):
    pass


class ScanTimedOut(SiteScanError):
    pass


def _format_wcag_tag(tag: str) -> str | None:
    if tag in WCAG_LEVEL_TAGS:
        return WCAG_LEVEL_TAGS[tag]
    match = re.fullmatch(r"wcag([1-2])([1-4])([1-4])", tag)
    if match:
        return f"WCAG {match.group(1)}.{match.group(2)}.{match.group(3)}"
    return None


def _finding(rule: dict) -> dict:
    nodes = []
    for node in rule.get("nodes", [])[:MAX_NODES_PER_FINDING]:
        nodes.append(
            {
                "target": [str(target)[:500] for target in node.get("target", [])[:12]],
                "html": str(node.get("html", ""))[:1200],
                "failureSummary": str(node.get("failureSummary") or "")[:2400],
            }
        )
    impact = rule.get("impact")
    if impact not in {"critical", "serious", "moderate", "minor"}:
        impact = "moderate"
    tags = {
        formatted
        for tag in rule.get("tags", [])
        if (formatted := _format_wcag_tag(str(tag).lower())) is not None
    }
    return {
        "id": str(rule.get("id", "unknown"))[:160],
        "impact": impact,
        "description": str(rule.get("description", ""))[:1000],
        "help": str(rule.get("help", ""))[:1000],
        "helpUrl": str(rule.get("helpUrl", ""))[:2048],
        "ruleId": str(rule.get("id", "unknown"))[:160],
        "wcag": sorted(tags),
        "nodes": nodes,
    }


async def run_accessibility_scan(raw_url: str) -> dict:
    if not AXE_CORE_PATH.is_file():
        raise SiteScanError("The accessibility engine is not installed.")

    safe_url = await validate_public_url(raw_url)
    request_count = 0
    total_bytes = 0
    unsafe_destination: str | None = None
    navigation_response_status: int | None = None
    try:
        async with asyncio.timeout(SCAN_TIMEOUT_SECONDS):
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch()
                try:
                    context = await browser.new_context(
                        service_workers="block",
                        accept_downloads=False,
                        java_script_enabled=True,
                        viewport={"width": 1365, "height": 900},
                    )
                    network_slots = asyncio.Semaphore(8)
                    budget_lock = asyncio.Lock()
                    network_client = httpx.AsyncClient(
                        follow_redirects=False,
                        timeout=httpx.Timeout(8.0),
                        trust_env=False,
                    )

                    async def guard_request(route) -> None:
                        nonlocal request_count, total_bytes, unsafe_destination
                        request_count += 1
                        if request_count > MAX_REQUESTS:
                            await route.abort("blockedbyclient")
                            return
                        request = route.request
                        if request.resource_type in {"media", "websocket"}:
                            await route.abort("blockedbyclient")
                            return
                        try:
                            request_url = await validate_public_url(request.url)
                        except UnsafeTarget:
                            unsafe_destination = request.url
                            await route.abort("blockedbyclient")
                            return
                        try:
                            request_headers = {
                                key: value
                                for key, value in request.headers.items()
                                if key.lower()
                                not in {
                                    "host",
                                    "content-length",
                                    "connection",
                                    "proxy-authorization",
                                    "proxy-authenticate",
                                    "transfer-encoding",
                                    "accept-encoding",
                                }
                            }
                            request_method = request.method
                            request_body = request.post_data_buffer
                            current_url = request_url
                            async with network_slots:
                                for redirect_index in range(MAX_REDIRECTS + 1):
                                    if redirect_index:
                                        request_count += 1
                                        if request_count > MAX_REQUESTS:
                                            await route.abort("blockedbyclient")
                                            return
                                    async with network_client.stream(
                                        request_method,
                                        current_url,
                                        headers=request_headers,
                                        content=request_body,
                                    ) as response:
                                        location = response.headers.get("location")
                                        if response.status_code in {301, 302, 303, 307, 308} and location:
                                            if redirect_index == MAX_REDIRECTS:
                                                await route.abort("blockedbyclient")
                                                return
                                            redirect_url = urljoin(current_url, location)
                                            try:
                                                next_url = await validate_public_url(redirect_url)
                                            except UnsafeTarget:
                                                unsafe_destination = redirect_url
                                                await route.abort("blockedbyclient")
                                                return

                                            current_origin = urlsplit(current_url)
                                            next_origin = urlsplit(next_url)
                                            if (
                                                current_origin.scheme,
                                                current_origin.hostname,
                                                current_origin.port,
                                            ) != (
                                                next_origin.scheme,
                                                next_origin.hostname,
                                                next_origin.port,
                                            ):
                                                request_headers = {
                                                    key: value
                                                    for key, value in request_headers.items()
                                                    if key.lower()
                                                    not in {"authorization", "cookie", "origin", "referer"}
                                                }
                                            if response.status_code == 303 or (
                                                response.status_code in {301, 302}
                                                and request_method.upper() not in {"GET", "HEAD"}
                                            ):
                                                request_method = "GET"
                                                request_body = None
                                                request_headers = {
                                                    key: value
                                                    for key, value in request_headers.items()
                                                    if key.lower()
                                                    not in {"content-type", "content-encoding"}
                                                }
                                            current_url = next_url
                                            continue

                                        declared_length = response.headers.get("content-length")
                                        if (
                                            declared_length
                                            and int(declared_length) > MAX_RESPONSE_BYTES
                                        ):
                                            await route.abort("blockedbyclient")
                                            return

                                        body = bytearray()
                                        async for chunk in response.aiter_bytes(64 * 1024):
                                            if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                                                await route.abort("blockedbyclient")
                                                return
                                            async with budget_lock:
                                                total_bytes += len(chunk)
                                                exceeded_total = (
                                                    total_bytes > MAX_TOTAL_RESPONSE_BYTES
                                                )
                                            if exceeded_total:
                                                await route.abort("blockedbyclient")
                                                return
                                            body.extend(chunk)

                                        response_headers = {
                                            key: value
                                            for key, value in response.headers.items()
                                            if key.lower()
                                            not in {
                                                "content-length",
                                                "content-encoding",
                                                "connection",
                                                "keep-alive",
                                                "proxy-authenticate",
                                                "proxy-authorization",
                                                "te",
                                                "trailer",
                                                "transfer-encoding",
                                                "upgrade",
                                            }
                                        }
                                        await route.fulfill(
                                            status=response.status_code,
                                            headers=response_headers,
                                            body=bytes(body),
                                        )
                                        break
                        except (httpx.HTTPError, PlaywrightError, ValueError, OSError):
                            await route.abort("failed")

                    await context.route("**/*", guard_request)
                    page = await context.new_page()
                    page.set_default_navigation_timeout(NAVIGATION_TIMEOUT_MS)
                    page.on("popup", lambda popup: asyncio.create_task(popup.close()))
                    try:
                        response = await page.goto(
                            safe_url,
                            wait_until="domcontentloaded",
                            timeout=NAVIGATION_TIMEOUT_MS,
                        )
                        if response is not None:
                            navigation_response_status = response.status
                        if unsafe_destination:
                            raise UnsafeRedirectError(
                                "A redirect or embedded request to a non-public address was blocked."
                            )
                        if response is not None and response.status >= 400:
                            raise SiteScanError(
                                f"The website responded with HTTP {response.status}."
                            )
                        await page.wait_for_timeout(350)
                        await page.add_script_tag(path=str(AXE_CORE_PATH))
                        result = await page.evaluate(
                            """async () => {
                              const report = await axe.run(document);
                              return {
                                violations: report.violations,
                                passes: report.passes.length,
                                incomplete: report.incomplete.length
                              };
                            }"""
                        )
                        if unsafe_destination:
                            raise UnsafeRedirectError(
                                "A redirect or embedded request to a non-public address was blocked."
                            )
                        findings = [_finding(rule) for rule in result["violations"][:MAX_FINDINGS]]
                        page_url = redact_url(page.url)
                        parts = urlsplit(page_url)
                        return {
                            "url": redact_url(raw_url),
                            "domain": parts.hostname or urlsplit(raw_url).hostname or "",
                            "title": (page_title := (await page.title()).strip()[:500]),
                            "pageTitle": page_title,
                            "pageUrl": page_url,
                            "status": "completed",
                            "findings": findings,
                            "violationCount": len(findings),
                            "criticalCount": sum(f["impact"] == "critical" for f in findings),
                            "seriousCount": sum(f["impact"] == "serious" for f in findings),
                            "moderateCount": sum(f["impact"] == "moderate" for f in findings),
                            "minorCount": sum(f["impact"] == "minor" for f in findings),
                            "passCount": int(result["passes"]),
                            "incompleteCount": int(result["incomplete"]),
                            "error": None,
                        }
                    finally:
                        await network_client.aclose()
                        await context.close()
                finally:
                    await browser.close()
    except TimeoutError as exc:
        raise ScanTimedOut("The scan exceeded its time limit. Try again later.") from exc
    except UnsafeRedirectError:
        raise
    except SiteScanError:
        raise
    except PlaywrightTimeoutError as exc:
        raise ScanTimedOut("The website took too long to load. Try again later.") from exc
    except PlaywrightError as exc:
        if unsafe_destination:
            raise UnsafeRedirectError(
                "A redirect or embedded request to a non-public address was blocked."
            ) from exc
        if navigation_response_status is not None and navigation_response_status >= 400:
            raise SiteScanError(
                f"The website responded with HTTP {navigation_response_status}."
            ) from exc
        raise SiteScanError("The website could not be loaded for an accessibility scan.") from exc
    except Exception as exc:
        raise SiteScanError("The website could not be scanned. Try again later.") from exc
