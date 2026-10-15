from __future__ import annotations

import pytest

from accesscheck.security import UnsafeTarget, redact_url, split_http_url


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "http://localhost/",
        "http://sub.localhost/",
        "http://127.0.0.1/",
        "http://10.2.3.4/",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.1.10/",
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://example.com:8080/",
        "http://user:password@example.com/",
    ],
)
def test_rejects_non_public_or_unsupported_urls(url: str) -> None:
    with pytest.raises(UnsafeTarget):
        split_http_url(url)


def test_accepts_standard_public_url_shape() -> None:
    parts = split_http_url("https://example.com/docs?q=search#section")
    assert parts.hostname == "example.com"
    assert parts.scheme == "https"


def test_redacts_query_and_fragment_before_storage() -> None:
    assert redact_url("https://example.com/path?token=secret#top") == "https://example.com/path"
