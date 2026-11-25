"""Safe concurrent TCP common-port scanner."""

from __future__ import annotations

import concurrent.futures
import ipaddress
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


def _resolve_socket_targets(
    hostname: str,
    port: int,
) -> list[tuple[int, int, int, Any]]:
    """Resolve IPv4/IPv6 socket targets for a hostname and port."""
    try:
        addr_infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        if addr_infos:
            return [
                (family, socktype, proto, sockaddr)
                for family, socktype, proto, _, sockaddr in addr_infos
            ]
    except OSError:
        pass

    try:
        ip_obj = ipaddress.ip_address(hostname)
        if ip_obj.version == 6:
            return [(socket.AF_INET6, socket.SOCK_STREAM, 0, (hostname, port, 0, 0))]
    except ValueError:
        pass

    return [(socket.AF_INET, socket.SOCK_STREAM, 0, (hostname, port))]


def _probe_port(hostname: str, port: int, timeout: float) -> dict[str, Any] | None:
    """Attempt a TCP connect_ex probe on a single port across IPv4/IPv6."""
    if not isinstance(hostname, str) or not hostname.strip():
        return None
    if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
        return None

    for family, socktype, proto, sockaddr in _resolve_socket_targets(hostname, port):
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex(sockaddr) == 0:
                    return {
                        "port": port,
                        "service": _resolve_service(port),
                        "status": "open",
                    }
        except (OSError, TypeError):
            continue
    return None


def scan_ports(
    hostname: str,
    ports: list[int] | None = None,
    timeout: float = 1.0,
    max_workers: int = 10,
) -> dict[str, Any]:
    """Scan a list of common TCP ports on a target hostname.

    Args:
        hostname: Target hostname or IPv4/IPv6 address.
        ports: Optional list of TCP port numbers. Defaults to DEFAULT_PORTS.
        timeout: Per-port socket timeout in seconds (default 1.0s).
        max_workers: Maximum concurrent worker threads.

    Returns:
        Dictionary with hostname, scanned_count, and sorted open_ports entries.
    """
    target_ports = list(ports) if ports is not None else list(DEFAULT_PORTS)
    safe_timeout = timeout if timeout > 0 else 1.0
    safe_workers = max(1, int(max_workers))
    open_ports: list[dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=safe_workers) as executor:
        futures = [
            executor.submit(_probe_port, hostname, port, safe_timeout)
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
