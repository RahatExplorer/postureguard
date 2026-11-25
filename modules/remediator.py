"""Auto-remediation configuration snippet generator for web servers and apps."""

from __future__ import annotations

from typing import Any

SUPPORTED_STACKS = frozenset({"nginx", "apache", "express"})

RECOMMENDED_HEADER_VALUES: dict[str, str] = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}

_HELMET_MAPPING: dict[str, str] = {
    "Strict-Transport-Security": "hsts: { maxAge: 31536000, includeSubDomains: true }",
    "Content-Security-Policy": "contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"], objectSrc: [\"'none'\"], frameAncestors: [\"'self'\"] } }",
    "X-Frame-Options": "frameguard: { action: 'deny' }",
    "X-Content-Type-Options": "noSniff: true",
    "Referrer-Policy": "referrerPolicy: { policy: 'strict-origin-when-cross-origin' }",
}


def _generate_nginx(missing: list[str], exposed: set[str]) -> str:
    lines = ["# PostureGuard Nginx Security Remediation"]
    if "Server" in exposed:
        lines.append("server_tokens off;")
    for header in ("X-Powered-By", "X-AspNet-Version"):
        if header in exposed:
            lines.append(f"proxy_hide_header {header};")
    for header in missing:
        value = RECOMMENDED_HEADER_VALUES.get(header)
        if value:
            lines.append(f'add_header {header} "{value}" always;')
    return "\n".join(lines)


def _generate_apache(missing: list[str], exposed: set[str]) -> str:
    lines = ["# PostureGuard Apache (.htaccess / httpd.conf) Security Remediation"]
    if "Server" in exposed:
        lines.append("ServerTokens Prod")
        lines.append("ServerSignature Off")
    for header in ("X-Powered-By", "X-AspNet-Version"):
        if header in exposed:
            lines.append(f"Header always unset {header}")
    for header in missing:
        value = RECOMMENDED_HEADER_VALUES.get(header)
        if value:
            lines.append(f'Header always set {header} "{value}"')
    return "\n".join(lines)


def _generate_express(missing: list[str], exposed: set[str]) -> str:
    lines = [
        "// PostureGuard Express.js Security Remediation",
        "// Recommended: npm install helmet",
        "const helmet = require('helmet');",
        "",
    ]

    if "X-Powered-By" in exposed:
        lines.append("app.disable('x-powered-by');")

    helmet_opts = [_HELMET_MAPPING[h] for h in missing if h in _HELMET_MAPPING]
    if helmet_opts:
        lines.append("app.use(helmet({")
        for opt in helmet_opts:
            lines.append(f"  {opt},")
        lines.append("}));")

    if missing or ("Server" in exposed) or ("X-AspNet-Version" in exposed):
        lines.append("")
        lines.append("// Explicit header enforcement middleware")
        lines.append("app.use((req, res, next) => {")
        for header in ("Server", "X-AspNet-Version"):
            if header in exposed:
                lines.append(f"  res.removeHeader('{header}');")
        for header in missing:
            value = RECOMMENDED_HEADER_VALUES.get(header)
            if value:
                lines.append(f'  res.setHeader(\'{header}\', "{value}");')
        lines.append("  next();")
        lines.append("});")

    return "\n".join(lines)


def generate_remediation(header_results: dict[str, Any], stack: str) -> str:
    """Generate targeted configuration remediation for missing or exposed headers.

    Args:
        header_results: Output dictionary returned by scan_headers().
        stack: Target web stack ('nginx', 'apache', or 'express').

    Returns:
        Copy-pasteable configuration snippet, or a no-op message if hardened.

    Raises:
        ValueError: If an unsupported stack name is provided.
    """
    normalized_stack = stack.strip().lower()
    if normalized_stack not in SUPPORTED_STACKS:
        raise ValueError(
            f"Unsupported stack '{stack}'. Choose from: {', '.join(sorted(SUPPORTED_STACKS))}."
        )

    missing_headers = [
        str(item["header"])
        for item in header_results.get("security_headers", [])
        if item.get("status") == "Missing" and item.get("header")
    ]
    exposed_headers = {
        str(item["header"])
        for item in header_results.get("info_disclosure", [])
        if item.get("status") == "Exposed" and item.get("header")
    }

    if not missing_headers and not exposed_headers:
        return "No header patches required: all recommended security headers are present and no disclosure headers are exposed."

    if normalized_stack == "nginx":
        return _generate_nginx(missing_headers, exposed_headers)
    if normalized_stack == "apache":
        return _generate_apache(missing_headers, exposed_headers)
    return _generate_express(missing_headers, exposed_headers)
