"""Offline unit tests for Auto-Remediation and Security Drift Detection."""

from pathlib import Path

from modules.drift_detector import compare_baseline, save_baseline
from modules.remediator import generate_remediation


def _sample_header_results(
    missing: list[str] | None = None,
    exposed: list[str] | None = None,
) -> dict:
    all_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    missing_set = set(missing or [])
    exposed_list = exposed or []

    security_headers = [
        {
            "header": header,
            "status": "Missing" if header in missing_set else "Present",
            "value": None if header in missing_set else "configured",
        }
        for header in all_headers
    ]
    info_disclosure = [
        {
            "header": header,
            "status": "Exposed",
            "value": "sample/1.0",
        }
        for header in exposed_list
    ]
    return {
        "security_headers": security_headers,
        "info_disclosure": info_disclosure,
    }


def test_generate_remediation_nginx_apache_express_snippets() -> None:
    """Remediation should generate stack-specific directives only for missing/exposed headers."""
    results = _sample_header_results(
        missing=["Strict-Transport-Security", "X-Frame-Options"],
        exposed=["Server", "X-Powered-By"],
    )

    nginx_patch = generate_remediation(results, "nginx")
    assert "server_tokens off;" in nginx_patch
    assert 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' in nginx_patch
    assert 'add_header X-Frame-Options "DENY" always;' in nginx_patch
    assert "Content-Security-Policy" not in nginx_patch

    apache_patch = generate_remediation(results, "apache")
    assert "ServerTokens Prod" in apache_patch
    assert "ServerSignature Off" in apache_patch
    assert 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"' in apache_patch
    assert 'Header always set X-Frame-Options "DENY"' in apache_patch
    assert "Content-Security-Policy" not in apache_patch

    express_patch = generate_remediation(results, "express")
    assert "helmet" in express_patch
    assert "app.disable('x-powered-by');" in express_patch
    assert "res.setHeader('Strict-Transport-Security'" in express_patch
    assert "res.setHeader('X-Frame-Options'" in express_patch
    assert "Content-Security-Policy" not in express_patch


def test_generate_remediation_returns_clean_message_when_hardened() -> None:
    """Hardened header results should report that no patches are required."""
    results = _sample_header_results(missing=[], exposed=[])
    message = generate_remediation(results, "nginx")
    assert "No header patches required" in message


def test_save_and_compare_baseline_detects_regression(tmp_path: Path) -> None:
    """compare_baseline() should detect score drop, new missing header, and new open port."""
    baseline_file = tmp_path / "baseline.json"

    baseline_scan = {
        "url": "https://example.com",
        "header_results": {
            "url": "https://example.com",
            "score": 85,
            "grade": "B",
            "security_headers": [
                {"header": "Strict-Transport-Security", "status": "Present"},
                {"header": "X-Frame-Options", "status": "Missing"},
            ],
        },
        "ssl_results": {"status": "ok"},
        "port_results": {"open_ports": [{"port": 443, "service": "HTTPS", "status": "open"}]},
    }
    save_baseline(baseline_scan, str(baseline_file))
    assert baseline_file.is_file()

    regressed_scan = {
        "url": "https://example.com",
        "header_results": {
            "url": "https://example.com",
            "score": 60,
            "grade": "C",
            "security_headers": [
                {"header": "Strict-Transport-Security", "status": "Missing"},
                {"header": "X-Frame-Options", "status": "Missing"},
            ],
        },
        "ssl_results": {"status": "ok"},
        "port_results": {
            "open_ports": [
                {"port": 443, "service": "HTTPS", "status": "open"},
                {"port": 8080, "service": "HTTP-Proxy", "status": "open"},
            ]
        },
    }

    drift = compare_baseline(regressed_scan, str(baseline_file))
    assert drift["status"] == "REGRESSED"
    assert drift["score_delta"] == -25
    assert drift["score_delta_str"] == "-25"
    assert drift["new_missing_headers"] == ["Strict-Transport-Security"]
    assert drift["fixed_headers"] == []
    assert drift["new_open_ports"] == [8080]
    assert drift["closed_ports"] == []


def test_compare_baseline_handles_missing_and_corrupted_files(tmp_path: Path) -> None:
    """Missing or corrupted baseline files should return ERROR status without crashing."""
    current = {
        "url": "https://example.com",
        "header_score": 100,
        "header_grade": "A",
        "missing_headers": [],
        "open_ports": [443],
        "ssl_status": "ok",
    }

    missing_drift = compare_baseline(current, str(tmp_path / "does_not_exist.json"))
    assert missing_drift["status"] == "ERROR"
    assert missing_drift["error"]

    corrupted_file = tmp_path / "corrupted.json"
    corrupted_file.write_text("{not valid json", encoding="utf-8")
    corrupted_drift = compare_baseline(current, str(corrupted_file))
    assert corrupted_drift["status"] == "ERROR"
    assert corrupted_drift["error"]
