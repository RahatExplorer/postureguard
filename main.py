"""PostureGuard CLI entrypoint."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

VERSION = "0.1"
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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for PostureGuard."""
    parser = build_parser()
    args = parser.parse_args(argv)

    display_banner()
    validated_url = validate_url(args.url)
    console.print(
        Text(
            f"Target validated: {validated_url}. Ready for scanning modules.",
            style="bold green",
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
