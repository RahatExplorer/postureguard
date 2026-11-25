"""Markdown and offline HTML audit report exporters for PostureGuard."""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def _sanitize_hostname(url: str) -> str:
    """Extract and sanitize hostname for safe report filenames."""
    parsed = urlparse(url)
    raw_host = parsed.hostname or "target"
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", raw_host).strip("._")
    return sanitized or "target"


def _build_report_path(url: str, output_dir: str, extension: str) -> Path:
    """Build a timestamped report path inside output_dir and ensure directory exists."""
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    hostname = _sanitize_hostname(url)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return target_dir / f"{hostname}_{timestamp}.{extension}"


def _escape_md(value: Any) -> str:
    """Escape pipe characters and newlines for Markdown table cells."""
    text = str(value if value is not None else "")
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _format_ssl_summary_line(ssl_results: dict[str, Any]) -> str:
    status = ssl_results.get("status", "unknown")
    if status == "ok":
        tls = ssl_results.get("tls_version") or "Unknown"
        days = ssl_results.get("days_remaining")
        days_part = f", {days} days remaining" if days is not None else ""
        return f"OK ({tls}{days_part})"
    if status == "not_https":
        return str(ssl_results.get("note") or "Unencrypted HTTP (CWE-319)")
    if status == "error":
        return f"Error ({ssl_results.get('error') or 'Handshake failed'})"
    return str(status)


def _collect_header_rows(header_results: dict[str, Any]) -> list[dict[str, str]]:
    """Combine security header and disclosure findings into uniform table rows."""
    rows: list[dict[str, str]] = []
    for item in header_results.get("security_headers", []):
        tip = (
            f"Value: `{item.get('value')}`"
            if item.get("status") == "Present"
            else str(item.get("remediation") or "")
        )
        rows.append(
            {
                "header": str(item.get("header", "")),
                "status": str(item.get("status", "")),
                "severity": str(item.get("severity", "")),
                "cwe": str(item.get("cwe", "")),
                "tip": tip,
                "raw_tip": str(item.get("value") or "")
                if item.get("status") == "Present"
                else str(item.get("remediation") or ""),
            }
        )
    for item in header_results.get("info_disclosure", []):
        exposed_val = str(item.get("value") or "")
        remediation = str(item.get("remediation") or "")
        rows.append(
            {
                "header": str(item.get("header", "")),
                "status": str(item.get("status", "Exposed")),
                "severity": str(item.get("severity", "Info")),
                "cwe": str(item.get("cwe", "CWE-200")),
                "tip": f"Exposed `{exposed_val}` — {remediation}",
                "raw_tip": f"Exposed: {exposed_val} — {remediation}",
            }
        )
    return rows


def export_markdown(scan_data: dict[str, Any], output_dir: str = "reports") -> str:
    """Export complete PostureGuard scan findings to a Markdown report.

    Args:
        scan_data: Composite scan dictionary containing URL, header, SSL,
            optional port, optional remediation, and optional drift results.
        output_dir: Destination directory for the generated `.md` report.

    Returns:
        File path to the written Markdown report.
    """
    url = str(scan_data.get("url") or scan_data.get("header_results", {}).get("url") or "")
    timestamp = str(
        scan_data.get("timestamp")
        or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    )
    header_results = scan_data.get("header_results") or {}
    ssl_results = scan_data.get("ssl_results") or {}
    port_results = scan_data.get("port_results")
    remediation = scan_data.get("remediation")
    remediation_stack = str(scan_data.get("remediation_stack") or "")
    drift_results = scan_data.get("drift_results")

    score = header_results.get("score", 0)
    grade = header_results.get("grade", "F")
    ssl_summary = _format_ssl_summary_line(ssl_results)

    lines: list[str] = [
        "# PostureGuard Security Audit Report",
        "",
        "## Executive Summary",
        "",
        f"- **Target URL:** {url}",
        f"- **Scan Timestamp:** {timestamp}",
        f"- **Security Header Score:** {score}/100 (Grade: {grade})",
        f"- **SSL/TLS Status:** {ssl_summary}",
        "",
        "## HTTP Security Headers & CWE Findings",
        "",
        "| Header | Status | Severity | CWE ID | Value / Remediation Tip |",
        "| --- | --- | --- | --- | --- |",
    ]

    for row in _collect_header_rows(header_results):
        lines.append(
            f"| {_escape_md(row['header'])} "
            f"| {_escape_md(row['status'])} "
            f"| {_escape_md(row['severity'])} "
            f"| {_escape_md(row['cwe'])} "
            f"| {_escape_md(row['tip'])} |"
        )

    lines.extend(["", "## SSL/TLS & Open Ports", ""])
    ssl_status = ssl_results.get("status", "unknown")
    if ssl_status == "ok":
        lines.extend(
            [
                f"- **Target:** {ssl_results.get('hostname')}:{ssl_results.get('port')}",
                f"- **TLS Version:** {ssl_results.get('tls_version')}",
                f"- **Subject (CN):** {ssl_results.get('subject')}",
                f"- **Issuer:** {ssl_results.get('issuer')}",
                f"- **Valid From:** {ssl_results.get('not_before')}",
                f"- **Valid Until:** {ssl_results.get('not_after')}",
                f"- **Days Remaining:** {ssl_results.get('days_remaining')}",
            ]
        )
        if ssl_results.get("warning"):
            lines.append(f"- **Warning:** {ssl_results['warning']}")
    elif ssl_status == "not_https":
        lines.append(f"- **Warning:** {ssl_results.get('note')}")
    elif ssl_status == "error":
        lines.append(f"- **SSL/TLS Error:** {ssl_results.get('error')}")
    else:
        lines.append("- **SSL/TLS:** Not inspected.")

    lines.append("")
    if port_results is not None:
        open_ports = port_results.get("open_ports", [])
        scanned_count = port_results.get("scanned_count", 0)
        if open_ports:
            lines.extend(
                [
                    f"### Open Common Ports ({len(open_ports)}/{scanned_count} Open)",
                    "",
                    "| Port | Service | Status |",
                    "| --- | --- | --- |",
                ]
            )
            for entry in open_ports:
                lines.append(
                    f"| {_escape_md(entry.get('port'))} "
                    f"| {_escape_md(entry.get('service'))} "
                    f"| {_escape_md(str(entry.get('status', 'open')).upper())} |"
                )
        else:
            lines.append(
                f"No open ports detected ({scanned_count} common ports scanned)."
            )
    else:
        lines.append("Port scan not enabled for this run (pass `--ports` to include).")

    if remediation:
        lang = "javascript" if remediation_stack == "express" else remediation_stack
        title_suffix = f" ({remediation_stack})" if remediation_stack else ""
        lines.extend(
            [
                "",
                f"## Auto-Remediation Patch{title_suffix}",
                "",
                f"```{lang}",
                str(remediation),
                "```",
            ]
        )

    if drift_results:
        lines.extend(["", "## Security Drift Report", ""])
        if drift_results.get("status") == "ERROR":
            lines.append(f"- **Error:** {drift_results.get('error')}")
        else:
            lines.extend(
                [
                    f"- **Drift Status:** {drift_results.get('status')}",
                    f"- **Score Change:** {drift_results.get('baseline_score')} -> "
                    f"{drift_results.get('current_score')} ({drift_results.get('score_delta_str')})",
                    f"- **New Missing Headers:** {', '.join(drift_results.get('new_missing_headers') or []) or 'None'}",
                    f"- **Fixed Headers:** {', '.join(drift_results.get('fixed_headers') or []) or 'None'}",
                    f"- **New Open Ports:** {', '.join(str(p) for p in (drift_results.get('new_open_ports') or [])) or 'None'}",
                    f"- **Closed Ports:** {', '.join(str(p) for p in (drift_results.get('closed_ports') or [])) or 'None'}",
                ]
            )

    lines.append("")
    output_path = _build_report_path(url, output_dir, "md")
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return str(output_path)


def _badge_class(label: str) -> str:
    normalized = label.lower()
    if normalized in {"present", "a", "b", "improved", "ok"}:
        return "badge-green"
    if normalized in {"missing", "high", "f", "regressed", "error"}:
        return "badge-red"
    if normalized in {"medium", "c", "d", "exposed", "not_https"}:
        return "badge-yellow"
    return "badge-blue"


def export_html(scan_data: dict[str, Any], output_dir: str = "reports") -> str:
    """Export complete PostureGuard scan findings to a self-contained dark-mode HTML report.

    Args:
        scan_data: Composite scan dictionary containing URL, header, SSL,
            optional port, optional remediation, and optional drift results.
        output_dir: Destination directory for the generated `.html` report.

    Returns:
        File path to the written HTML report.
    """
    url = str(scan_data.get("url") or scan_data.get("header_results", {}).get("url") or "")
    timestamp = str(
        scan_data.get("timestamp")
        or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    )
    header_results = scan_data.get("header_results") or {}
    ssl_results = scan_data.get("ssl_results") or {}
    port_results = scan_data.get("port_results")
    remediation = scan_data.get("remediation")
    remediation_stack = str(scan_data.get("remediation_stack") or "")
    drift_results = scan_data.get("drift_results")

    score = header_results.get("score", 0)
    grade = str(header_results.get("grade", "F"))
    ssl_summary = _format_ssl_summary_line(ssl_results)

    header_rows_html = []
    for row in _collect_header_rows(header_results):
        status_cls = _badge_class(row["status"])
        sev_cls = _badge_class(row["severity"])
        header_rows_html.append(
            "<tr>"
            f"<td><code>{html.escape(row['header'])}</code></td>"
            f"<td><span class=\"badge {status_cls}\">{html.escape(row['status'])}</span></td>"
            f"<td><span class=\"badge {sev_cls}\">{html.escape(row['severity'])}</span></td>"
            f"<td><code>{html.escape(row['cwe'])}</code></td>"
            f"<td>{html.escape(row['raw_tip'])}</td>"
            "</tr>"
        )

    ssl_status = ssl_results.get("status", "unknown")
    if ssl_status == "ok":
        warning_html = (
            f"<p class=\"alert-warn\"><strong>Warning:</strong> {html.escape(str(ssl_results['warning']))}</p>"
            if ssl_results.get("warning")
            else ""
        )
        ssl_block_html = (
            "<div class=\"kv-grid\">"
            f"<div><span>Target</span><strong>{html.escape(str(ssl_results.get('hostname')))}:{html.escape(str(ssl_results.get('port')))}</strong></div>"
            f"<div><span>TLS Version</span><strong>{html.escape(str(ssl_results.get('tls_version')))}</strong></div>"
            f"<div><span>Subject (CN)</span><strong>{html.escape(str(ssl_results.get('subject')))}</strong></div>"
            f"<div><span>Issuer</span><strong>{html.escape(str(ssl_results.get('issuer')))}</strong></div>"
            f"<div><span>Valid From</span><strong>{html.escape(str(ssl_results.get('not_before')))}</strong></div>"
            f"<div><span>Valid Until</span><strong>{html.escape(str(ssl_results.get('not_after')))}</strong></div>"
            f"<div><span>Days Remaining</span><strong>{html.escape(str(ssl_results.get('days_remaining')))}</strong></div>"
            "</div>"
            f"{warning_html}"
        )
    elif ssl_status == "not_https":
        ssl_block_html = f"<p class=\"alert-warn\">{html.escape(str(ssl_results.get('note')))}</p>"
    elif ssl_status == "error":
        ssl_block_html = f"<p class=\"alert-error\">{html.escape(str(ssl_results.get('error')))}</p>"
    else:
        ssl_block_html = "<p class=\"muted\">SSL/TLS inspection not available.</p>"

    if port_results is not None:
        open_ports = port_results.get("open_ports", [])
        scanned_count = port_results.get("scanned_count", 0)
        if open_ports:
            port_rows = "".join(
                "<tr>"
                f"<td><code>{html.escape(str(entry.get('port')))}</code></td>"
                f"<td>{html.escape(str(entry.get('service')))}</td>"
                f"<td><span class=\"badge badge-yellow\">{html.escape(str(entry.get('status', 'open')).upper())}</span></td>"
                "</tr>"
                for entry in open_ports
            )
            ports_block_html = (
                f"<h3>Open Common Ports ({len(open_ports)}/{scanned_count} Open)</h3>"
                "<div class=\"table-wrap\"><table><thead><tr><th>Port</th><th>Service</th><th>Status</th></tr></thead>"
                f"<tbody>{port_rows}</tbody></table></div>"
            )
        else:
            ports_block_html = (
                f"<p class=\"alert-ok\">No open ports detected ({scanned_count} common ports scanned).</p>"
            )
    else:
        ports_block_html = "<p class=\"muted\">Port scan not enabled for this run (pass <code>--ports</code> to include).</p>"

    remediation_section_html = ""
    if remediation:
        stack_label = f" ({html.escape(remediation_stack)})" if remediation_stack else ""
        remediation_section_html = (
            "<section class=\"card\">"
            f"<h2>Auto-Remediation Patch{stack_label}</h2>"
            f"<pre><code>{html.escape(str(remediation))}</code></pre>"
            "</section>"
        )

    drift_section_html = ""
    if drift_results:
        if drift_results.get("status") == "ERROR":
            drift_inner = f"<p class=\"alert-error\">{html.escape(str(drift_results.get('error')))}</p>"
        else:
            drift_status = str(drift_results.get("status", "UNCHANGED"))
            drift_cls = _badge_class(drift_status)
            new_missing = ", ".join(drift_results.get("new_missing_headers") or []) or "None"
            fixed = ", ".join(drift_results.get("fixed_headers") or []) or "None"
            new_ports = ", ".join(str(p) for p in (drift_results.get("new_open_ports") or [])) or "None"
            closed_ports = ", ".join(str(p) for p in (drift_results.get("closed_ports") or [])) or "None"
            drift_inner = (
                f"<p><span class=\"badge {drift_cls}\">{html.escape(drift_status)}</span></p>"
                "<div class=\"kv-grid\">"
                f"<div><span>Score Change</span><strong>{html.escape(str(drift_results.get('baseline_score')))} &rarr; {html.escape(str(drift_results.get('current_score')))} ({html.escape(str(drift_results.get('score_delta_str')))})</strong></div>"
                f"<div><span>New Missing Headers</span><strong>{html.escape(new_missing)}</strong></div>"
                f"<div><span>Fixed Headers</span><strong>{html.escape(fixed)}</strong></div>"
                f"<div><span>New Open Ports</span><strong>{html.escape(new_ports)}</strong></div>"
                f"<div><span>Closed Ports</span><strong>{html.escape(closed_ports)}</strong></div>"
                "</div>"
            )
        drift_section_html = f"<section class=\"card\"><h2>Security Drift Report</h2>{drift_inner}</section>"

    grade_cls = _badge_class(grade)
    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PostureGuard Audit Report - {html.escape(url)}</title>
  <style>
    :root {{
      --bg: #0d1117;
      --surface: #161b22;
      --surface-alt: #1f2630;
      --border: #30363d;
      --text: #e6edf3;
      --muted: #8b949e;
      --accent: #58a6ff;
      --green: #2ea043;
      --red: #f85149;
      --yellow: #d29922;
      --blue: #388bfd;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 2rem 1rem;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
    }}
    .container {{ max-width: 1080px; margin: 0 auto; display: grid; gap: 1.25rem; }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.25rem 1.5rem;
    }}
    h1, h2, h3 {{ margin-top: 0; color: var(--text); }}
    h1 {{ font-size: 1.6rem; margin-bottom: 0.25rem; }}
    h2 {{ font-size: 1.15rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin-bottom: 1rem; }}
    .subtitle {{ color: var(--muted); font-size: 0.9rem; margin: 0; }}
    .summary-grid, .kv-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 0.9rem;
    }}
    .summary-grid > div, .kv-grid > div {{
      background: var(--surface-alt);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.75rem 0.9rem;
    }}
    .summary-grid span, .kv-grid span {{ display: block; font-size: 0.78rem; color: var(--muted); margin-bottom: 0.2rem; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; }}
    th, td {{ text-align: left; padding: 0.65rem 0.75rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ color: var(--accent); font-weight: 600; background: var(--surface-alt); }}
    code {{ background: #0b0f14; padding: 0.15rem 0.35rem; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 0.86em; }}
    pre {{ background: #0b0f14; border: 1px solid var(--border); border-radius: 8px; padding: 1rem; overflow-x: auto; }}
    pre code {{ background: transparent; padding: 0; color: #c9d1d9; }}
    .badge {{
      display: inline-block;
      padding: 0.15rem 0.55rem;
      border-radius: 999px;
      font-size: 0.78rem;
      font-weight: 600;
    }}
    .badge-green {{ background: rgba(46, 160, 67, 0.2); color: #56d364; border: 1px solid rgba(46, 160, 67, 0.45); }}
    .badge-red {{ background: rgba(248, 81, 73, 0.2); color: #ff7b72; border: 1px solid rgba(248, 81, 73, 0.45); }}
    .badge-yellow {{ background: rgba(210, 153, 34, 0.2); color: #e3b341; border: 1px solid rgba(210, 153, 34, 0.45); }}
    .badge-blue {{ background: rgba(56, 139, 253, 0.2); color: #79c0ff; border: 1px solid rgba(56, 139, 253, 0.45); }}
    .alert-warn {{ background: rgba(210, 153, 34, 0.14); border: 1px solid var(--yellow); padding: 0.75rem 1rem; border-radius: 8px; color: #e3b341; }}
    .alert-error {{ background: rgba(248, 81, 73, 0.14); border: 1px solid var(--red); padding: 0.75rem 1rem; border-radius: 8px; color: #ff7b72; }}
    .alert-ok {{ background: rgba(46, 160, 67, 0.14); border: 1px solid var(--green); padding: 0.75rem 1rem; border-radius: 8px; color: #56d364; }}
    .muted {{ color: var(--muted); }}
  </style>
</head>
<body>
  <main class="container">
    <header class="card">
      <h1>PostureGuard Security Audit Report</h1>
      <p class="subtitle">Automated Web Security Posture Auditor &bull; For authorized security testing and local lab use only.</p>
    </header>

    <section class="card">
      <h2>Executive Summary</h2>
      <div class="summary-grid">
        <div><span>Target URL</span><strong>{html.escape(url)}</strong></div>
        <div><span>Scan Timestamp</span><strong>{html.escape(timestamp)}</strong></div>
        <div><span>Security Header Score</span><strong>{html.escape(str(score))}/100</strong> <span class="badge {grade_cls}">Grade {html.escape(grade)}</span></div>
        <div><span>SSL/TLS Status</span><strong>{html.escape(ssl_summary)}</strong></div>
      </div>
    </section>

    <section class="card">
      <h2>HTTP Security Headers &amp; CWE Findings</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Header</th>
              <th>Status</th>
              <th>Severity</th>
              <th>CWE ID</th>
              <th>Value / Remediation Tip</th>
            </tr>
          </thead>
          <tbody>
            {''.join(header_rows_html)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="card">
      <h2>SSL/TLS &amp; Open Ports</h2>
      {ssl_block_html}
      {ports_block_html}
    </section>

    {remediation_section_html}
    {drift_section_html}
  </main>
</body>
</html>
"""

    output_path = _build_report_path(url, output_dir, "html")
    output_path.write_text(html_doc, encoding="utf-8")
    return str(output_path)
