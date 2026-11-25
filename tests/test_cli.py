"""Unit tests for PostureGuard CLI validation."""

import pytest

from main import validate_url


def test_validate_url_accepts_valid_http_and_https_urls() -> None:
    """Valid http and https URLs with hostnames should be returned intact."""
    assert validate_url("https://example.com") == "https://example.com"
    assert validate_url("http://localhost:8000/health") == "http://localhost:8000/health"


def test_validate_url_rejects_missing_scheme() -> None:
    """URLs lacking an explicit http/https scheme should exit with code 1."""
    with pytest.raises(SystemExit) as exc_info:
        validate_url("localhost:8000")

    assert exc_info.value.code == 1


@pytest.mark.parametrize("bad_url", ["", "   ", "http://", "not a valid url", "https://example.com:badport"])
def test_validate_url_rejects_empty_or_malformed_strings(bad_url: str) -> None:
    """Empty or malformed URL strings should exit with code 1."""
    with pytest.raises(SystemExit) as exc_info:
        validate_url(bad_url)

    assert exc_info.value.code == 1
