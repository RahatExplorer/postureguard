"""Unit tests for PostureGuard CLI validation and exit code behavior."""

from pathlib import Path
from unittest.mock import patch

import pytest

from main import main, validate_url


def test_validate_url_accepts_valid_http_and_https_urls() -> None:
    """Valid http, https, uppercase scheme, and IPv6 URLs should validate and normalize scheme."""
    assert validate_url("https://example.com") == "https://example.com"
    assert validate_url("http://localhost:8000/health") == "http://localhost:8000/health"
    assert validate_url("HTTPS://example.com/Path") == "https://example.com/Path"
    assert validate_url("http://[::1]:8000/") == "http://[::1]:8000/"


def test_validate_url_rejects_missing_scheme() -> None:
    """URLs lacking an explicit http/https scheme should exit with code 1."""
    with pytest.raises(SystemExit) as exc_info:
        validate_url("localhost:8000")

    assert exc_info.value.code == 1


@pytest.mark.parametrize(
    "bad_url",
    [
        "",
        "   ",
        "http://",
        "not a valid url",
        "https://example.com:badport",
        "https://localhost:0",
    ],
)
def test_validate_url_rejects_empty_or_malformed_strings(bad_url: str) -> None:
    """Empty, port-zero, or malformed URL strings should exit with code 1."""
    with pytest.raises(SystemExit) as exc_info:
        validate_url(bad_url)

    assert exc_info.value.code == 1


def test_main_exits_nonzero_on_diff_error_and_save_baseline_directory(tmp_path: Path) -> None:
    """--diff errors and unwritable --save-baseline directories should return exit code 1."""
    fake_headers = {
        "url": "https://example.com",
        "final_url": "https://example.com",
        "redirected": False,
        "status_code": 200,
        "error": None,
        "security_headers": [],
        "info_disclosure": [],
        "score": 100,
        "grade": "A",
    }
    fake_ssl = {"status": "ok", "hostname": "example.com", "port": 443}

    with (
        patch("main.scan_headers", return_value=fake_headers),
        patch("main.inspect_ssl", return_value=fake_ssl),
    ):
        rc_diff = main(["--url", "https://example.com", "--diff", str(tmp_path / "missing.json")])
        rc_save = main(["--url", "https://example.com", "--save-baseline", str(tmp_path)])

    assert rc_diff == 1
    assert rc_save == 1


def test_main_inspects_https_endpoint_after_http_redirect() -> None:
    """HTTP-to-HTTPS redirect should invoke inspect_ssl on the redirected HTTPS final_url."""
    fake_headers = {
        "url": "http://example.com",
        "final_url": "https://example.com/",
        "redirected": True,
        "status_code": 404,
        "error": None,
        "security_headers": [],
        "info_disclosure": [],
        "score": 0,
        "grade": "F",
    }
    fake_ssl = {"status": "ok", "hostname": "example.com", "port": 443}

    with (
        patch("main.scan_headers", return_value=fake_headers),
        patch("main.inspect_ssl", return_value=fake_ssl) as mock_ssl,
    ):
        rc = main(["--url", "http://example.com"])

    assert rc == 0
    mock_ssl.assert_called_once_with("https://example.com/")
