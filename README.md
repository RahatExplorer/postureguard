# PostureGuard

**Automated Web Security Posture Auditor with Auto-Remediation & Drift Detection**

PostureGuard is a modular Python CLI tool for inspecting web application security posture across HTTP security headers, TLS/SSL certificates, and common exposed TCP services—complete with CWE mapping, stack-specific remediation patch generation, JSON baseline drift detection, and offline audit report exports.

---

## Key Features

- **CWE-Mapped HTTP Security Header Auditing:** Evaluates 6 critical security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`), flags information-disclosure headers (`Server`, `X-Powered-By`, `X-AspNet-Version`) under `CWE-200`, and computes a weighted `0–100` score with `A–F` grading.
- **SSL/TLS Certificate & Protocol Inspection:** Extracts TLS version, subject, issuer, validity window, and remaining certificate lifetime, warning on legacy protocols (`< TLSv1.2`), certificates expiring within 30 days, or unencrypted `http://` targets (`CWE-319`).
- **Safe Concurrent Common-Port Scanner (`--ports`):** Scans 10 high-signal TCP ports (`21, 22, 25, 53, 80, 443, 3306, 8000, 8080, 8443`) using `ThreadPoolExecutor` with a strict 1-second per-port timeout and service mapping.
- **Auto-Remediation Config Generation (`--remediate`):** Produces copy-pasteable configuration patches strictly for missing or exposed headers across **Nginx**, **Apache**, and **Express.js** (`helmet` + `res.setHeader` / `app.disable('x-powered-by')`).
- **Baseline Security Drift Diffing (`--save-baseline` / `--diff`):** Captures JSON posture snapshots and detects score changes, newly missing/fixed headers, and newly opened/closed ports across deployments (`IMPROVED`, `REGRESSED`, or `UNCHANGED`).
- **Offline Markdown & HTML Audit Reports (`--output`):** Generates timestamped Markdown and self-contained dark-mode HTML reports (zero external CDN dependencies) in `reports/`.

---

## Architecture

```text
postureguard/
├── main.py                       # CLI entrypoint, argument parsing, Rich terminal UI
├── modules/
│   ├── __init__.py
│   ├── header_scanner.py         # HTTP header checks, CWE mapping, weighted scoring
│   ├── ssl_inspector.py          # SSL/TLS handshake & X.509 certificate inspection
│   ├── port_scanner.py           # Concurrent safe TCP common-port scanner
│   ├── remediator.py             # Nginx / Apache / Express config patch generator
│   ├── drift_detector.py         # JSON baseline persistence & security drift diffing
│   └── reporter.py               # Markdown & offline dark-mode HTML report exporters
├── reports/
│   └── .gitkeep                  # Output directory for generated reports & baselines
├── tests/
│   ├── __init__.py
│   ├── test_cli.py               # URL validation unit tests
│   ├── test_headers.py           # Header scanner & error handling unit tests
│   ├── test_network.py           # SSL inspector & port scanner unit tests
│   ├── test_unique_features.py   # Remediator & drift detector unit tests
│   └── test_reporter.py          # Markdown & HTML exporter unit tests
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Installation

```bash
git clone <https://github.com/RahatExplorer/postureguard> postureguard
cd postureguard

python -m venv venv
# Windows (PowerShell)
.\venv\Scripts\Activate.ps1
# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
```

---

## Usage Examples

Run a standard HTTP header + SSL/TLS posture audit:

```bash
python main.py --url https://example.com
```

Include the concurrent common-port scan and generate an Nginx remediation patch:

```bash
python main.py --url https://example.com --ports --remediate nginx
```

Generate Apache or Express.js patches and save a baseline snapshot:

```bash
python main.py --url https://localhost:8443 --remediate express --save-baseline reports/baseline.json
```

Compare a new scan against a saved baseline and export both Markdown and HTML reports:

```bash
python main.py --url https://example.com --ports --remediate apache --diff reports/baseline.json --output both
```

### CLI Options

| Flag | Description |
| --- | --- |
| `--url URL` | *(Required)* Target URL (`http://` or `https://`). |
| `--ports` | Run the safe concurrent TCP common-port scan. |
| `--remediate {nginx,apache,express}` | Print syntax-highlighted config patch for missing/exposed headers. |
| `--save-baseline PATH` | Save current scan snapshot to a JSON file. |
| `--diff PATH` | Compare current scan against a saved JSON baseline. |
| `--output {md,html,both}` | Export timestamped report(s) into `reports/`. |

---

## Running Tests

All unit tests run completely offline using mocked HTTP and socket layers:

```bash
pytest -v
```

---

## Screenshots

> Add terminal output and HTML dashboard report screenshots here:
>
> - `docs/terminal-audit.png` — Rich CLI tables, remediation patch, and drift report
> - `docs/html-report.png` — Offline dark-mode HTML security audit report

---

## Ethical Use Disclaimer

PostureGuard is built strictly **for authorized security testing, educational research, and local lab use only**. Do not run scans against systems or networks without explicit authorization from the asset owner.

## License

Released under the [MIT License](https://opensource.org/licenses/MIT).
