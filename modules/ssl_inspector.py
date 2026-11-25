"""SSL/TLS certificate and protocol inspector."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

LEGACY_TLS_VERSIONS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"})
CERT_EXPIRY_WARNING_DAYS = 30


def _flatten_rdn(rdns: tuple[Any, ...] | None) -> dict[str, str]:
    """Flatten OpenSSL RDN tuples from getpeercert() into a key-value dict."""
    flattened: dict[str, str] = {}
    if not rdns:
        return flattened
    for rdn in rdns:
        for entry in rdn:
            if isinstance(entry, (tuple, list)) and len(entry) == 2:
                key, value = entry
                flattened[str(key)] = str(value)
    return flattened


def _format_issuer(issuer_rdns: tuple[Any, ...] | None) -> str:
    """Extract a readable Common Name / Organization string for certificate issuer."""
    fields = _flatten_rdn(issuer_rdns)
    cn = fields.get("commonName")
    org = fields.get("organizationName")
    if cn and org and cn != org:
        return f"{cn} ({org})"
    return cn or org or "Unknown"


def _format_subject(subject_rdns: tuple[Any, ...] | None) -> str:
    """Extract Common Name (or Organization fallback) for certificate subject."""
    fields = _flatten_rdn(subject_rdns)
    return fields.get("commonName") or fields.get("organizationName") or "Unknown"


def _parse_days_remaining(not_after: str | None) -> int | None:
    """Compute whole days remaining until certificate expiration in UTC."""
    if not not_after:
        return None
    expiry_epoch = ssl.cert_time_to_seconds(not_after)
    expiry_dt = datetime.fromtimestamp(expiry_epoch, tz=timezone.utc)
    return (expiry_dt - datetime.now(timezone.utc)).days


def _ssl_error_result(
    hostname: str | None,
    port: int,
    exc: Exception,
    message: str,
) -> dict[str, Any]:
    """Build a structured error dictionary for SSL/socket failures."""
    return {
        "status": "error",
        "hostname": hostname,
        "port": port,
        "tls_version": None,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "warning": None,
        "error": message,
        "error_type": type(exc).__name__,
    }


def inspect_ssl(url: str, timeout: int = 5) -> dict[str, Any]:
    """Inspect SSL/TLS configuration and certificate metadata for a target URL.

    Args:
        url: Validated target URL.
        timeout: Socket connection timeout in seconds.

    Returns:
        Structured dictionary describing SSL/TLS state, certificate info,
        non-HTTPS status, or connection error details.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname

    try:
        parsed_port = parsed.port
    except ValueError as exc:
        return _ssl_error_result(
            hostname,
            443 if scheme == "https" else 80,
            exc,
            f"Invalid port in URL '{url}': {exc}",
        )

    if parsed_port is not None and parsed_port < 1:
        return _ssl_error_result(
            hostname,
            parsed_port,
            ValueError(f"Port out of valid range: {parsed_port}"),
            f"Invalid port number {parsed_port} in URL '{url}'.",
        )

    port = parsed_port if parsed_port is not None else (443 if scheme == "https" else 80)

    if scheme == "http":
        return {
            "status": "not_https",
            "hostname": hostname,
            "port": port,
            "note": "Target uses unencrypted HTTP (CWE-319)",
            "tls_version": None,
            "issuer": None,
            "subject": None,
            "not_before": None,
            "not_after": None,
            "days_remaining": None,
            "warning": None,
            "error": None,
        }

    if scheme != "https":
        return _ssl_error_result(
            hostname,
            port,
            ValueError(f"Unsupported scheme: {scheme}"),
            f"Unsupported URL scheme '{scheme}' for SSL/TLS inspection.",
        )

    if not hostname:
        return {
            "status": "error",
            "hostname": None,
            "port": port,
            "tls_version": None,
            "issuer": None,
            "subject": None,
            "not_before": None,
            "not_after": None,
            "days_remaining": None,
            "warning": None,
            "error": f"Unable to parse hostname from URL '{url}'.",
            "error_type": "ValueError",
        }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                tls_version = tls_sock.version()
                cert = tls_sock.getpeercert() or {}
    except ssl.SSLError as exc:
        return _ssl_error_result(
            hostname,
            port,
            exc,
            f"SSL/TLS handshake error for {hostname}:{port}: {exc}",
        )
    except socket.timeout as exc:
        return _ssl_error_result(
            hostname,
            port,
            exc,
            f"SSL/TLS connection to {hostname}:{port} timed out after {timeout}s.",
        )
    except OSError as exc:
        return _ssl_error_result(
            hostname,
            port,
            exc,
            f"Network error connecting to {hostname}:{port}: {exc}",
        )

    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    warnings: list[str] = []

    try:
        days_remaining = _parse_days_remaining(not_after)
    except ValueError:
        days_remaining = None
        warnings.append("Unable to parse certificate expiration date.")

    if days_remaining is not None:
        if days_remaining < 0:
            warnings.append(f"Certificate expired {abs(days_remaining)} days ago.")
        elif days_remaining < CERT_EXPIRY_WARNING_DAYS:
            warnings.append(
                f"Certificate expires in {days_remaining} days (< {CERT_EXPIRY_WARNING_DAYS} days)."
            )
    if tls_version in LEGACY_TLS_VERSIONS:
        warnings.append(f"Deprecated TLS protocol negotiated: {tls_version}.")

    return {
        "status": "ok",
        "hostname": hostname,
        "port": port,
        "tls_version": tls_version,
        "issuer": _format_issuer(cert.get("issuer")),
        "subject": _format_subject(cert.get("subject")),
        "not_before": not_before,
        "not_after": not_after,
        "days_remaining": days_remaining,
        "warning": " ".join(warnings) if warnings else None,
        "error": None,
    }
