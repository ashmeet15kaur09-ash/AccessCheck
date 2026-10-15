from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import SplitResult, urlsplit, urlunsplit


class UnsafeTarget(ValueError):
    """Raised when a URL could reach a non-public network destination."""


_BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".test",
    ".invalid",
)


def _validate_ip(address: str) -> None:
    try:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError as exc:
        raise UnsafeTarget("The website hostname did not resolve to a valid IP address.") from exc
    if not parsed.is_global:
        raise UnsafeTarget("Private and reserved network addresses cannot be scanned.")


async def resolve_public_addresses(hostname: str) -> set[str]:
    """Resolve a host and reject it if any returned address is not globally routable."""
    host = hostname.rstrip(".")
    if not host or host.lower() == "localhost" or host.lower().endswith(_BLOCKED_SUFFIXES):
        raise UnsafeTarget("Local and internal hostnames cannot be scanned.")

    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None

    if literal is not None:
        _validate_ip(str(literal))
        return {str(literal)}

    loop = asyncio.get_running_loop()
    try:
        answers = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=socket.SOCK_STREAM),
            timeout=3.0,
        )
    except (OSError, asyncio.TimeoutError) as exc:
        raise UnsafeTarget("The website hostname could not be resolved safely.") from exc

    addresses = {answer[4][0].split("%", 1)[0] for answer in answers}
    if not addresses:
        raise UnsafeTarget("The website hostname did not resolve to a public address.")
    for address in addresses:
        _validate_ip(address)
    return addresses


def split_http_url(raw_url: str) -> SplitResult:
    try:
        parts = urlsplit(raw_url.strip())
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise UnsafeTarget("Enter a valid public website URL.") from exc

    if parts.scheme.lower() not in {"http", "https"}:
        raise UnsafeTarget("Only public HTTP and HTTPS websites can be scanned.")
    if not hostname or parts.username is not None or parts.password is not None:
        raise UnsafeTarget("Enter a website URL without embedded credentials.")
    normalized_host = hostname.rstrip(".").lower()
    if normalized_host == "localhost" or normalized_host.endswith(_BLOCKED_SUFFIXES):
        raise UnsafeTarget("Local and internal hostnames cannot be scanned.")
    try:
        literal = ipaddress.ip_address(normalized_host.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None:
        _validate_ip(str(literal))
    expected_port = 443 if parts.scheme.lower() == "https" else 80
    if port is not None and port != expected_port:
        raise UnsafeTarget("Only the standard HTTP and HTTPS ports can be scanned.")
    if any(ord(char) < 32 for char in raw_url):
        raise UnsafeTarget("The URL contains invalid characters.")
    return parts


async def validate_public_url(raw_url: str) -> str:
    """Validate the URL and its DNS answers immediately before it is requested."""
    parts = split_http_url(raw_url)
    await resolve_public_addresses(parts.hostname or "")
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc, path, parts.query, ""))


def redact_url(raw_url: str) -> str:
    """Remove query strings and fragments before saving or displaying scan URLs."""
    parts = urlsplit(raw_url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
