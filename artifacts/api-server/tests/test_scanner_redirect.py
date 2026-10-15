from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from accesscheck.scanner import UnsafeRedirectError, run_accessibility_scan
from accesscheck.security import UnsafeTarget


def test_browser_blocks_a_redirect_to_a_private_destination(monkeypatch):
    requested_paths: list[str] = []

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            requested_paths.append(self.path)
            if self.path == "/":
                self.send_response(302)
                self.send_header(
                    "Location",
                    f"http://127.0.0.1:{self.server.server_port}/private",
                )
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"should not be reached")

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    start_url = f"http://127.0.0.1:{server.server_port}/"
    validation_calls = 0

    async def allow_start_only(url: str) -> str:
        nonlocal validation_calls
        validation_calls += 1
        if validation_calls <= 2 and url == start_url:
            return url
        raise UnsafeTarget("Private redirect blocked by test.")

    monkeypatch.setattr("accesscheck.scanner.validate_public_url", allow_start_only)
    try:
        with pytest.raises(UnsafeRedirectError):
            asyncio.run(run_accessibility_scan(start_url))
        assert requested_paths == ["/"]
    finally:
        server.shutdown()
        server.server_close()


def test_browser_follows_a_valid_public_redirect(monkeypatch):
    requested_paths: list[str] = []

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            requested_paths.append(self.path)
            if self.path == "/":
                self.send_response(302)
                self.send_header("Location", "/landing")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"<html lang='en'><head><title>Redirect destination</title></head>"
                b"<body><main><h1>Landing</h1></main></body></html>"
            )

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_port}/"

    async def allow_test_origin(url: str) -> str:
        if url.startswith(origin):
            return url
        raise UnsafeTarget("Unexpected redirect target.")

    monkeypatch.setattr("accesscheck.scanner.validate_public_url", allow_test_origin)
    try:
        result = asyncio.run(run_accessibility_scan(origin))
        assert result["pageTitle"] == "Redirect destination"
        assert requested_paths == ["/", "/landing"]
    finally:
        server.shutdown()
        server.server_close()
