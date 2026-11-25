"""PostureGuard CLI entrypoint."""

from __future__ import annotations

import argparse
import sys
from typing import Any, Sequence
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from modules.header_scanner import scan_headers
from modules.port_scanner import scan_ports
from modules.ssl_inspector import inspect_ssl

VERSION = "0.3"
ALLOWED_SCHEMES = frozenset({"http", "https"})

console = Console()


def display_banner() -> None:
    """Display the PostureGuard startup banner and ethical-use disclaimer."""
    banner_text = (
        f"[bold cyan]PostureGuard v{VERSION}[/bold cyan]\n"
        "[dim]For authorized security testing and local lab use only.[/dim]"
    )
    console.print(Panel.fit(banner_text, border_style="cyan"))


def _exit_with_url_error(message: str) -> None:
    """Print a red error panel and terminate with status code 1."""
    console.print(
        Panel(
            Text(message, style="bold red"),
            title="Invalid Target URL",
            border_style="red",
        )
    )
    sys.exit(1)


def validate_url(url: str) -> str:
    """Validate that a target URL uses http/https and includes a hostname.

    Args:
        url: Raw target URL string supplied via CLI.

    Returns:
        The normalized URL string if valid.

    Raises:
        SystemExit: Exits with status code 1 if the URL is empty, malformed,
            missing an http/https scheme, or missing a hostname.
    """
    if not isinstance(url, str):
        _exit_with_url_error("Target URL must be a non-empty string.")

    cleaned = url.strip()
    if not cleaned or any(char.isspace() for char in cleaned):
        _exit_with_url_error(
            "Target URL is empty or contains whitespace. "
            "Expected format: http(s)://<host>[:port][/path]"
        )

    parsed = urlparse(cleaned)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        _exit_with_url_error(
            f"Unsupported or missing URL scheme in '{cleaned}'. "
            "Use 'http://' or 'https://'."
        )

    if not parsed.hostname:
        _exit_with_url_error(
            f"Target URL '{cleaned}' is missing a valid hostname."
        )

    try:
        _ = parsed.port
    except ValueError:
        _exit_with_url_error(
            f"Target URL '{cleaned}' contains an invalid port number."
        )

    return cleaned


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="postureguard",
        description="PostureGuard - Modular Cybersecurity Posture Assessment CLI",
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Target URL to validate (must include http:// or https://).",
    )
    parser.add_argument(
        "--ports",
        action="store_true",
        default=False,
        help="Run a safe common-port TCP scan against the target hostname.",
    )
    return parser


_SEVERITY_STYLES = {
    "High": "bold red",
    "Medium": "yellow",
    "Low": "cyan",
    "Info": "blue",
}


def _status_text(status: str) -> Text:
    """Format finding status with color coding."""
    if status == "Present":
        return Text(status, style="bold green")
    if status == "Missing":
        return Text(status, style="bold red")
    return Text(status, style="bold yellow")


def _grade_style(grade: str) -> str:
    """Return Rich border/text color for a security letter grade."""
    if grade in {"A", "B"}:
        return "green"
    if grade in {"C", "D"}:
        return "yellow"
    return "red"


def display_header_results(result: dict[str, Any]) -> None:
    """Render HTTP security header scan results and summary score panel."""
    table = Table(
        title="HTTP Security Header Analysis",
        show_header=True,
        header_style="bold magenta",
        show_lines=True,
    )
    table.add_column("Header Name", style="bold white", no_wrap=True)
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("CWE ID", justify="center", no_wrap=True)
    table.add_column("Value/Note", overflow="fold")

    for item in result["security_headers"]:
        note = (
            item["value"]
            if item["status"] == "Present"
            else item["remediation"]
        )
        severity = item["severity"]
        table.add_row(
            Text(item["header"], style="bold white"),
            _status_text(item["status"]),
            Text(severity, style=_SEVERITY_STYLES.get(severity, "white")),
            Text(item["cwe"], style="dim"),
            Text(note or ""),
        )

    for item in result["info_disclosure"]:
        note = f"Exposed: {item['value']} | Tip: {item['remediation']}"
        severity = item["severity"]
        table.add_row(
            Text(item["header"], style="bold white"),
            _status_text(item["status"]),
            Text(severity, style=_SEVERITY_STYLES.get(severity, "blue")),
            Text(item["cwe"], style="dim"),
            Text(note),
        )

    console.print(table)

    score = result["score"]
    grade = result["grade"]
    grade_color = _grade_style(grade)
    summary = Text(f"Score: {score}/100 (Grade: {grade})", style=f"bold {grade_color}")
    console.print(Panel.fit(summary, title="Security Posture Summary", border_style=grade_color))


def display_ssl_results(ssl_result: dict[str, Any]) -> None:
    """Render SSL/TLS certificate inspection results in a panel or table."""
    status = ssl_result.get("status")
    if status == "not_https":
        console.print(
            Panel.fit(
                Text(str(ssl_result["note"]), style="bold yellow"),
                title="SSL/TLS Inspection",
                border_style="yellow",
            )
        )
        return

    if status == "error":
        console.print(
            Panel(
                Text(str(ssl_result["error"]), style="bold red"),
                title="SSL/TLS Inspection Error",
                border_style="red",
            )
        )
        return

    table = Table(
        title="SSL/TLS Inspection",
        show_header=True,
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Property", style="bold white", no_wrap=True)
    table.add_column("Value", overflow="fold")

    days = ssl_result.get("days_remaining")
    days_display = f"{days} days" if days is not None else "Unknown"
    days_style = "bold red" if (days is not None and days < 30) else "green"

    table.add_row("Target", Text(f"{ssl_result['hostname']}:{ssl_result['port']}"))
    table.add_row("TLS Version", Text(str(ssl_result.get("tls_version") or "Unknown")))
    table.add_row("Subject (CN)", Text(str(ssl_result.get("subject") or "Unknown")))
    table.add_row("Issuer", Text(str(ssl_result.get("issuer") or "Unknown")))
    table.add_row("Valid From", Text(str(ssl_result.get("not_before") or "Unknown")))
    table.add_row("Valid Until", Text(str(ssl_result.get("not_after") or "Unknown")))
    table.add_row("Days Remaining", Text(days_display, style=days_style))

    if ssl_result.get("warning"):
        table.add_row("Warning", Text(str(ssl_result["warning"]), style="bold yellow"))

    console.print(table)


def display_port_results(port_result: dict[str, Any]) -> None:
    """Render common TCP port scan results."""
    open_ports = port_result.get("open_ports", [])
    scanned_count = port_result.get("scanned_count", 0)
    hostname = port_result.get("hostname", "")

    if not open_ports:
        console.print(
            Panel.fit(
                Text(
                    f"No open ports detected on {hostname} ({scanned_count} common ports scanned).",
                    style="bold green",
                ),
                title="Common Port Scan",
                border_style="green",
            )
        )
        return

    table = Table(
        title=f"Common Port Scan ({hostname} - {len(open_ports)}/{scanned_count} Open)",
        show_header=True,
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Port", justify="right", style="bold white", no_wrap=True)
    table.add_column("Service", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center", no_wrap=True)

    for entry in open_ports:
        table.add_row(
            Text(str(entry["port"])),
            Text(str(entry["service"])),
            Text(str(entry["status"]).upper(), style="bold yellow"),
        )

    console.print(table)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for PostureGuard."""
    parser = build_parser()
    args = parser.parse_args(argv)

    display_banner()
    validated_url = validate_url(args.url)
    console.print(
        Text(
            f"Target validated: {validated_url}. Running security checks...",
            style="bold green",
        )
    )

    scan_result = scan_headers(validated_url)
    if scan_result.get("error"):
        console.print(
            Panel(
                Text(str(scan_result["error"]), style="bold red"),
                title="Scan Error",
                border_style="red",
            )
        )
        return 1

    display_header_results(scan_result)

    ssl_result = inspect_ssl(validated_url)
    display_ssl_results(ssl_result)

    if args.ports:
        hostname = urlparse(validated_url).hostname
        if hostname:
            port_result = scan_ports(hostname)
            display_port_results(port_result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
