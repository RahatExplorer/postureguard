"""Offline unit tests for SSL/TLS inspection and safe port scanning."""

import socket
import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from modules.port_scanner import DEFAULT_PORTS, scan_ports
from modules.ssl_inspector import inspect_ssl


def test_inspect_ssl_on_http_returns_not_https() -> None:
    """Plain HTTP targets should return status='not_https' with CWE-319 note."""
    result = inspect_ssl("http://localhost:8000")

    assert result["status"] == "not_https"
    assert result["note"] == "Target uses unencrypted HTTP (CWE-319)"
    assert result["error"] is None


def test_inspect_ssl_handles_socket_timeout_gracefully() -> None:
    """Socket timeouts during SSL inspection should return a structured error dict."""
    with patch(
        "modules.ssl_inspector.socket.create_connection",
        side_effect=socket.timeout("timed out"),
    ):
        result = inspect_ssl("https://example.com", timeout=5)

    assert result["status"] == "error"
    assert result["hostname"] == "example.com"
    assert result["port"] == 443
    assert result["error_type"] == "TimeoutError"
    assert "timed out" in result["error"]


def test_inspect_ssl_extracts_cert_details_and_flags_warnings() -> None:
    """HTTPS inspection should extract cert metadata and warn on expiring cert or legacy TLS."""
    now = datetime.now(timezone.utc)
    not_before = (now - timedelta(days=30)).strftime("%b %d %H:%M:%S %Y GMT")
    not_after = (now + timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")

    mock_tls_sock = MagicMock()
    mock_tls_sock.version.return_value = "TLSv1.1"
    mock_tls_sock.getpeercert.return_value = {
        "issuer": ((("organizationName", "Test CA"),), (("commonName", "Test Root"),)),
        "subject": ((("commonName", "example.com"),),),
        "notBefore": not_before,
        "notAfter": not_after,
    }
    mock_tls_sock.__enter__.return_value = mock_tls_sock

    mock_raw_sock = MagicMock()
    mock_raw_sock.__enter__.return_value = mock_raw_sock

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = mock_tls_sock

    with (
        patch("modules.ssl_inspector.ssl.create_default_context", return_value=mock_context),
        patch("modules.ssl_inspector.socket.create_connection", return_value=mock_raw_sock),
    ):
        result = inspect_ssl("https://example.com:8443")

    assert result["status"] == "ok"
    assert result["hostname"] == "example.com"
    assert result["port"] == 8443
    assert result["tls_version"] == "TLSv1.1"
    assert result["issuer"] == "Test Root (Test CA)"
    assert result["subject"] == "example.com"
    assert result["not_before"] == not_before
    assert result["not_after"] == not_after
    assert result["days_remaining"] is not None
    assert result["days_remaining"] < 30
    assert result["warning"] is not None
    assert "Deprecated TLS protocol" in result["warning"]


def test_inspect_ssl_handles_ssl_error_gracefully() -> None:
    """ssl.SSLError should return a structured error dict without raising."""
    with patch(
        "modules.ssl_inspector.socket.create_connection",
        side_effect=ssl.SSLError("certificate verify failed"),
    ):
        result = inspect_ssl("https://bad-cert.example")

    assert result["status"] == "error"
    assert result["error_type"] == "SSLError"
    assert "certificate verify failed" in result["error"]


def test_scan_ports_returns_sorted_open_ports_and_services() -> None:
    """scan_ports() should return sorted open ports mapped to standard service names."""
    open_set = {22, 80, 8000}

    def _fake_socket_factory(*args, **kwargs):
        sock = MagicMock()
        sock.__enter__.return_value = sock

        def _connect_ex(addr):
            _, port = addr
            return 0 if port in open_set else 111

        sock.connect_ex.side_effect = _connect_ex
        return sock

    with patch("modules.port_scanner.socket.socket", side_effect=_fake_socket_factory):
        result = scan_ports("example.com")

    assert result["hostname"] == "example.com"
    assert result["scanned_count"] == len(DEFAULT_PORTS)
    assert result["open_ports"] == [
        {"port": 22, "service": "SSH", "status": "open"},
        {"port": 80, "service": "HTTP", "status": "open"},
        {"port": 8000, "service": "HTTP-Alt", "status": "open"},
    ]
