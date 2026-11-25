"""Security drift detection via JSON baseline snapshots."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def build_baseline_snapshot(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Normalize scan output into a compact, serializable baseline snapshot."""
    if "header_score" in scan_data and "missing_headers" in scan_data:
        return {
            "timestamp": scan_data.get("timestamp")
            or datetime.now(timezone.utc).isoformat(),
            "url": scan_data.get("url", ""),
            "header_score": int(scan_data.get("header_score", 0)),
            "header_grade": str(scan_data.get("header_grade", "F")),
            "missing_headers": sorted(str(h) for h in scan_data.get("missing_headers", [])),
            "open_ports": sorted(int(p) for p in scan_data.get("open_ports", [])),
            "ssl_status": str(scan_data.get("ssl_status", "unknown")),
        }

    header_results = scan_data.get("header_results", scan_data)
    ssl_results = scan_data.get("ssl_results") or {}
    port_results = scan_data.get("port_results") or {}

    missing_headers = sorted(
        str(item["header"])
        for item in header_results.get("security_headers", [])
        if item.get("status") == "Missing" and item.get("header")
    )

    raw_ports = port_results.get("open_ports", scan_data.get("open_ports", []))
    open_ports = sorted(
        int(entry["port"] if isinstance(entry, dict) else entry)
        for entry in raw_ports
    )

    return {
        "timestamp": scan_data.get("timestamp")
        or datetime.now(timezone.utc).isoformat(),
        "url": scan_data.get("url") or header_results.get("url", ""),
        "header_score": int(header_results.get("score", 0)),
        "header_grade": str(header_results.get("grade", "F")),
        "missing_headers": missing_headers,
        "open_ports": open_ports,
        "ssl_status": str(
            ssl_results.get("status") or scan_data.get("ssl_status") or "unknown"
        ),
    }


def save_baseline(scan_data: dict[str, Any], filepath: str) -> None:
    """Persist the current scan snapshot as formatted JSON."""
    snapshot = build_baseline_snapshot(scan_data)
    target_path = Path(filepath)
    if target_path.parent:
        target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")


def compare_baseline(current_scan: dict[str, Any], baseline_path: str) -> dict[str, Any]:
    """Compare current scan results against a previously saved JSON baseline.

    Args:
        current_scan: Current scan snapshot or composite scan dictionary.
        baseline_path: Path to the saved JSON baseline file.

    Returns:
        Structured drift report dictionary, or an ERROR status dict if the
        baseline file is missing or unreadable/corrupted.
    """
    path = Path(baseline_path)
    if not path.is_file():
        return {
            "status": "ERROR",
            "error": f"Baseline file not found: {baseline_path}",
            "score_delta": 0,
            "score_delta_str": "0",
            "new_missing_headers": [],
            "fixed_headers": [],
            "new_open_ports": [],
            "closed_ports": [],
        }

    try:
        raw_content = path.read_text(encoding="utf-8")
        baseline_data = json.loads(raw_content)
        if not isinstance(baseline_data, dict):
            raise ValueError("Baseline JSON root must be an object.")
        baseline = build_baseline_snapshot(baseline_data)
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        return {
            "status": "ERROR",
            "error": f"Failed to load baseline '{baseline_path}': {exc}",
            "score_delta": 0,
            "score_delta_str": "0",
            "new_missing_headers": [],
            "fixed_headers": [],
            "new_open_ports": [],
            "closed_ports": [],
        }

    current = build_baseline_snapshot(current_scan)

    score_delta = current["header_score"] - baseline["header_score"]
    score_delta_str = f"{score_delta:+d}" if score_delta != 0 else "0"

    baseline_missing = set(baseline["missing_headers"])
    current_missing = set(current["missing_headers"])
    new_missing_headers = sorted(current_missing - baseline_missing)
    fixed_headers = sorted(baseline_missing - current_missing)

    baseline_ports = set(baseline["open_ports"])
    current_ports = set(current["open_ports"])
    new_open_ports = sorted(current_ports - baseline_ports)
    closed_ports = sorted(baseline_ports - current_ports)

    has_regression = (
        score_delta < 0
        or bool(new_missing_headers)
        or bool(new_open_ports)
    )
    has_improvement = (
        score_delta > 0
        or bool(fixed_headers)
        or bool(closed_ports)
    )

    if has_regression and not has_improvement:
        status = "REGRESSED"
    elif has_improvement and not has_regression:
        status = "IMPROVED"
    elif has_regression and has_improvement:
        status = "IMPROVED" if score_delta > 0 else "REGRESSED"
    else:
        status = "UNCHANGED"

    return {
        "status": status,
        "error": None,
        "baseline_timestamp": baseline["timestamp"],
        "baseline_score": baseline["header_score"],
        "current_score": current["header_score"],
        "score_delta": score_delta,
        "score_delta_str": score_delta_str,
        "new_missing_headers": new_missing_headers,
        "fixed_headers": fixed_headers,
        "new_open_ports": new_open_ports,
        "closed_ports": closed_ports,
        "baseline_ssl_status": baseline["ssl_status"],
        "current_ssl_status": current["ssl_status"],
    }
