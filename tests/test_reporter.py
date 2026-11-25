"""Offline unit tests for PostureGuard Markdown and HTML report exporters."""

import re
from pathlib import Path

from modules.reporter import export_html, export_markdown


def _sample_scan_data() -> dict:
    return {
        "url": "https://app.example.com:8443",
        "timestamp": "2026-11-25 14:30:00 UTC",
        "header_results": {
            "url": "https://app.example.com:8443",
            "score": 40,
            "grade": "D",
            "security_headers": [
                {
                    "header": "Strict-Transport-Security",
                    "status": "Present",
                    "severity": "High",
                    "cwe": "CWE-319",
                    "value": "max-age=31536000",
                    "remediation": None,
                },
                {
                    "header": "Content-Security-Policy",
                    "status": "Missing",
                    "severity": "High",
                    "cwe": "CWE-693",
                    "value": None,
                    "remediation": "Define a restrictive Content-Security-Policy header.",
                },
            ],
            "info_disclosure": [
                {
                    "header": "Server",
                    "status": "Exposed",
                    "severity": "Info",
                    "cwe": "CWE-200",
                    "value": "nginx/1.24 <script>alert(1)</script>",
                    "remediation": "Suppress the Server header.",
                }
            ],
        },
        "ssl_results": {
            "status": "ok",
            "hostname": "app.example.com",
            "port": 8443,
            "tls_version": "TLSv1.3",
            "subject": "app.example.com",
            "issuer": "Example CA",
            "not_before": "Jan 01 00:00:00 2026 GMT",
            "not_after": "Dec 31 23:59:59 2026 GMT",
            "days_remaining": 36,
            "warning": None,
        },
        "port_results": {
            "hostname": "app.example.com",
            "scanned_count": 10,
            "open_ports": [
                {"port": 443, "service": "HTTPS", "status": "open"},
                {"port": 8443, "service": "HTTPS-Alt", "status": "open"},
            ],
        },
        "remediation_stack": "nginx",
        "remediation": 'server_tokens off;\nadd_header Content-Security-Policy "default-src \'self\'" always;',
        "drift_results": {
            "status": "REGRESSED",
            "baseline_score": 65,
            "current_score": 40,
            "score_delta": -25,
            "score_delta_str": "-25",
            "new_missing_headers": ["Content-Security-Policy"],
            "fixed_headers": [],
            "new_open_ports": [8443],
            "closed_ports": [],
        },
    }


def test_export_markdown_creates_complete_report(tmp_path: Path) -> None:
    """export_markdown() should write a timestamped .md file with all audit sections."""
    report_path = Path(export_markdown(_sample_scan_data(), output_dir=str(tmp_path)))

    assert report_path.is_file()
    assert re.match(r"^app\.example\.com_\d{8}_\d{6}\.md$", report_path.name)

    content = report_path.read_text(encoding="utf-8")
    assert len(content) > 0
    assert "https://app.example.com:8443" in content
    assert "40/100 (Grade: D)" in content
    assert "CWE-319" in content
    assert "CWE-693" in content
    assert "CWE-200" in content
    assert "TLSv1.3" in content
    assert "8443" in content
    assert "server_tokens off;" in content
    assert "REGRESSED" in content


def test_export_html_creates_offline_dashboard_report(tmp_path: Path) -> None:
    """export_html() should write a self-contained dark-mode HTML report without external CDNs."""
    report_path = Path(export_html(_sample_scan_data(), output_dir=str(tmp_path)))

    assert report_path.is_file()
    assert re.match(r"^app\.example\.com_\d{8}_\d{6}\.html$", report_path.name)

    content = report_path.read_text(encoding="utf-8")
    assert len(content) > 0
    assert "<style>" in content
    assert "<link " not in content.lower()
    assert "<script " not in content.lower()
    assert "https://app.example.com:8443" in content
    assert "40" in content
    assert "Grade D" in content
    assert "CWE-319" in content
    assert "CWE-693" in content
    assert "CWE-200" in content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
    assert "REGRESSED" in content
