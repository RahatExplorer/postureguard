"""HTTP Security Header Scanner with CWE mapping and weighted scoring."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests

USER_AGENT = "PostureGuard/0.2"


@dataclass(frozen=True)
class SecurityHeaderSpec:
    """Definition for an expected HTTP security header."""

    name: str
    severity: str
    cwe: str
    weight: int
    remediation: str


@dataclass(frozen=True)
class DisclosureHeaderSpec:
    """Definition for an HTTP information disclosure header."""

    name: str
    cwe: str
    remediation: str


SECURITY_HEADER_SPECS: tuple[SecurityHeaderSpec, ...] = (
    SecurityHeaderSpec(
        name="Strict-Transport-Security",
        severity="High",
        cwe="CWE-319",
        weight=25,
        remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS connections.",
    ),
    SecurityHeaderSpec(
        name="Content-Security-Policy",
        severity="High",
        cwe="CWE-693",
        weight=25,
        remediation="Define a restrictive Content-Security-Policy header to limit trusted script and resource origins.",
    ),
    SecurityHeaderSpec(
        name="X-Frame-Options",
        severity="Medium",
        cwe="CWE-1021",
        weight=15,
        remediation="Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to protect against clickjacking attacks.",
    ),
    SecurityHeaderSpec(
        name="X-Content-Type-Options",
        severity="Medium",
        cwe="CWE-16",
        weight=15,
        remediation="Set 'X-Content-Type-Options: nosniff' to prevent browsers from MIME-sniffing responses.",
    ),
    SecurityHeaderSpec(
        name="Referrer-Policy",
        severity="Low",
        cwe="CWE-200",
        weight=10,
        remediation="Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer' to limit referrer leakage.",
    ),
    SecurityHeaderSpec(
        name="Permissions-Policy",
        severity="Low",
        cwe="CWE-693",
        weight=10,
        remediation="Add a Permissions-Policy header to disable unnecessary browser features such as camera, microphone, and geolocation.",
    ),
)

DISCLOSURE_HEADER_SPECS: tuple[DisclosureHeaderSpec, ...] = (
    DisclosureHeaderSpec(
        name="Server",
        cwe="CWE-200",
        remediation="Suppress or strip the Server header at the web server or reverse proxy to avoid exposing software versions.",
    ),
    DisclosureHeaderSpec(
        name="X-Powered-By",
        cwe="CWE-200",
        remediation="Disable the X-Powered-By header in your framework or runtime configuration to conceal backend technologies.",
    ),
    DisclosureHeaderSpec(
        name="X-AspNet-Version",
        cwe="CWE-200",
        remediation="Set enableVersionHeader='false' in ASP.NET httpRuntime configuration to remove X-AspNet-Version.",
    ),
)


def calculate_grade(score: int) -> str:
    """Return letter grade for a 0-100 security header score."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _error_result(url: str, exc: Exception, message: str) -> dict[str, Any]:
    """Build a structured error dictionary for failed network requests."""
    return {
        "url": url,
        "final_url": None,
        "status_code": None,
        "error": message,
        "error_type": type(exc).__name__,
        "security_headers": [],
        "info_disclosure": [],
        "score": 0,
        "grade": "F",
    }


def scan_headers(url: str, timeout: int = 10) -> dict[str, Any]:
    """Fetch target URL headers and evaluate security posture and disclosures.

    Args:
        url: Validated http/https target URL.
        timeout: Request timeout in seconds.

    Returns:
        Structured dictionary containing findings, score, grade, or error info.
    """
    try:
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
            allow_redirects=True,
        )
    except requests.exceptions.Timeout as exc:
        return _error_result(
            url,
            exc,
            f"Request timed out after {timeout}s while connecting to {url}.",
        )
    except requests.exceptions.ConnectionError as exc:
        return _error_result(
            url,
            exc,
            f"Failed to establish a connection to {url}: {exc}",
        )
    except requests.exceptions.RequestException as exc:
        return _error_result(
            url,
            exc,
            f"HTTP request error while scanning {url}: {exc}",
        )

    normalized_headers = {
        str(key).lower(): str(value)
        for key, value in response.headers.items()
    }

    security_findings: list[dict[str, Any]] = []
    score = 0

    for spec in SECURITY_HEADER_SPECS:
        raw_value = normalized_headers.get(spec.name.lower())
        is_present = bool(raw_value and raw_value.strip())
        if is_present:
            score += spec.weight

        security_findings.append(
            {
                "header": spec.name,
                "status": "Present" if is_present else "Missing",
                "severity": spec.severity,
                "cwe": spec.cwe,
                "weight": spec.weight,
                "value": raw_value.strip() if is_present and raw_value else None,
                "remediation": None if is_present else spec.remediation,
            }
        )

    disclosure_findings: list[dict[str, Any]] = []
    for spec in DISCLOSURE_HEADER_SPECS:
        raw_value = normalized_headers.get(spec.name.lower())
        if raw_value and raw_value.strip():
            disclosure_findings.append(
                {
                    "header": spec.name,
                    "status": "Exposed",
                    "severity": "Info",
                    "cwe": spec.cwe,
                    "value": raw_value.strip(),
                    "remediation": spec.remediation,
                }
            )

    return {
        "url": url,
        "final_url": getattr(response, "url", url),
        "status_code": getattr(response, "status_code", None),
        "error": None,
        "security_headers": security_findings,
        "info_disclosure": disclosure_findings,
        "score": score,
        "grade": calculate_grade(score),
    }
