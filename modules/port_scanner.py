"""Safe concurrent TCP common-port scanner."""

from __future__ import annotations

import concurrent.futures
import socket
from typing import Any

DEFAULT_PORTS: list[int] = [21, 22, 25, 53, 80, 443, 3306, 8000, 8080, 8443]

PORT_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}


def _resolve_service(port: int) -> str:
    """Return a human-readable service name for a TCP port."""
    if port in PORT_SERVICES:
        return PORT_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "Unknown"


def _probe_port(hostname: str, port: int, timeout: float) -> dict[str, Any] | None:
    """Attempt a TCP connect_ex probe on a single port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((hostname, port)) == 0:
                return {
                    "port": port,
                    "service": _resolve_service(port),
                    "status": "open",
                }
    except OSError:
        return None
    return None


def scan_ports(
    hostname: str,
    ports: list[int] | None = None,
    timeout: float = 1.0,
    max_workers: int = 10,
) -> dict[str, Any]:
    """Scan a list of common TCP ports on a target hostname.

    Args:
        hostname: Target hostname or IPv4 address.
        ports: Optional list of TCP port numbers. Defaults to DEFAULT_PORTS.
        timeout: Per-port socket timeout in seconds (default 1.0s).
        max_workers: Maximum concurrent worker threads.

    Returns:
        Dictionary with hostname, scanned_count, and sorted open_ports entries.
    """
    target_ports = list(ports) if ports is not None else list(DEFAULT_PORTS)
    open_ports: list[dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(_probe_port, hostname, port, timeout)
            for port in target_ports
        ]
        for future in concurrent.futures.as_completed(futures):
            finding = future.result()
            if finding is not None:
                open_ports.append(finding)

    open_ports.sort(key=lambda entry: entry["port"])

    return {
        "hostname": hostname,
        "scanned_count": len(target_ports),
        "open_ports": open_ports,
    }
