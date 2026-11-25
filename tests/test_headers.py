"""Unit tests for the PostureGuard HTTP Security Header Scanner."""

from unittest.mock import Mock, patch

import pytest
import requests

from modules.header_scanner import USER_AGENT, scan_headers


def _mock_response(headers: dict[str, str], status_code: int = 200, url: str = "https://example.com") -> Mock:
    response = Mock()
    response.headers = headers
    response.status_code = status_code
    response.url = url
    return response


def test_scan_headers_fully_hardened_response() -> None:
    """All 6 security headers present (case-insensitive) should yield Score 100 and Grade A."""
    hardened_headers = {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "CONTENT-SECURITY-POLICY": "default-src 'self'",
        "x-frame-options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=(), camera=()",
    }

    with patch(
        "modules.header_scanner.requests.get",
        return_value=_mock_response(hardened_headers),
    ) as mock_get:
        result = scan_headers("https://example.com")

    mock_get.assert_called_once_with(
        "https://example.com",
        headers={"User-Agent": USER_AGENT},
        timeout=10,
        allow_redirects=True,
    )
    assert result["error"] is None
    assert result["score"] == 100
    assert result["grade"] == "A"
    assert len(result["security_headers"]) == 6
    assert all(item["status"] == "Present" for item in result["security_headers"])
    assert all(item["remediation"] is None for item in result["security_headers"])
    assert result["info_disclosure"] == []


def test_scan_headers_bare_response_with_exposed_server() -> None:
    """Missing security headers and an exposed Server header should yield Score 0, Grade F, and flag disclosure."""
    bare_headers = {
        "server": "Apache/2.4.49 (Unix)",
    }

    with patch(
        "modules.header_scanner.requests.get",
        return_value=_mock_response(bare_headers),
    ):
        result = scan_headers("https://example.com")

    assert result["error"] is None
    assert result["score"] == 0
    assert result["grade"] == "F"
    assert len(result["security_headers"]) == 6
    assert all(item["status"] == "Missing" for item in result["security_headers"])
    assert all(isinstance(item["remediation"], str) and item["remediation"] for item in result["security_headers"])

    assert len(result["info_disclosure"]) == 1
    disclosure = result["info_disclosure"][0]
    assert disclosure["header"] == "Server"
    assert disclosure["status"] == "Exposed"
    assert disclosure["severity"] == "Info"
    assert disclosure["cwe"] == "CWE-200"
    assert disclosure["value"] == "Apache/2.4.49 (Unix)"
    assert isinstance(disclosure["remediation"], str) and disclosure["remediation"]


@pytest.mark.parametrize(
    "exc",
    [
        requests.exceptions.Timeout("timed out"),
        requests.exceptions.ConnectionError("connection refused"),
        requests.exceptions.RequestException("unexpected request error"),
    ],
)
def test_scan_headers_handles_network_errors_gracefully(exc: requests.exceptions.RequestException) -> None:
    """Network exceptions should return a structured error dict without raising."""
    with patch("modules.header_scanner.requests.get", side_effect=exc):
        result = scan_headers("https://unreachable.local", timeout=5)

    assert result["url"] == "https://unreachable.local"
    assert result["error"]
    assert result["error_type"] == type(exc).__name__
    assert result["score"] == 0
    assert result["grade"] == "F"
    assert result["security_headers"] == []
    assert result["info_disclosure"] == []
