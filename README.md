# PKI Agentic AI System

An enterprise-grade Python agentic AI for **PKI & certificate lifecycle management (CLM/LCM)** — similar in spirit to Venafi — built around **TLS/SSL discovery**, an **Entrust Shield HSM** root of trust, **Shor's-algorithm-aware** quantum threat scoring, firewall/port scanning, compliance reporting and a creative web UI.

## Highlights

- 🔐 **PKI & CLM**: discovers, inventories and monitors certificates from a centralized repository (`data/inventory.json`) with optional live TLS probing.
- ⏰ **45-day expiry threshold** (configurable) with 7-day critical window, automated renew/replace recommendations and severity-classified alerts.
- 🛡️ **Firewall scanner** sweeping ports **0–65000** via Nmap when available or a fast multi-threaded socket probe. **Strict policy: only TCP/443 (HTTPS) is permitted.** Every other reachable port is reported as a policy violation with full vulnerability intel — class, description, attack vector, mitigation, CVE/CWE/MITRE ATT&CK references.
- 🧪 **Quantum threat model** scoring every certificate against **Shor's algorithm** (RSA, ECC, DSA all flagged) and recommending NIST PQC (ML-KEM, ML-DSA, SLH-DSA) migration paths.
- 🏛️ **HSM integration** layer for the **Entrust Shield HSM** with a development-safe local fallback (keys never leave memory unencrypted).
- 🧠 **Autonomous agent** that scores certificates, evaluates scans and emits ranked decisions (`replace_certificate`, `trigger_renewal`, `block_port`, `plan_pqc_migration`, ...).
- 📊 **Reports** in CSV, HTML and PDF (ReportLab) plus structured JSONL audit log.
- 🌐 **Smooth glassmorphism web UI** with aurora background, animated KPIs, severity bars, per-page panels (Dashboard, Certificates, Firewall, Quantum, HSM, Compliance, Audit, Reports).
- ✅ **Compliance mapping**: PCI-DSS 4.0, HIPAA, ISO 27001, SOC 2, NIST 800-53.

## Project layout

```
d:\pki_agent\
├── app.py                       # Flask web app, routes, JSON API
├── requirements.txt
├── pki_agent/                   # Core package
│   ├── ai_agent.py              # RiskEngine + AutonomousAgent
│   ├── audit.py                 # Structured JSONL audit log
│   ├── compliance.py            # PCI/HIPAA/ISO/SOC2/NIST mapping
│   ├── config.py                # Tunables / env vars
│   ├── discovery.py             # Cert discovery + inventory persistence
│   ├── hsm_integration.py       # Entrust Shield HSM + local fallback
│   ├── models.py                # Dataclasses
│   ├── notifier.py              # Webhook/email fan-out
│   ├── reporting.py             # CSV / HTML / PDF reports
│   ├── scanner.py               # Firewall scanner (nmap + socket)
│   ├── scheduler.py             # Daily / weekly background jobs
│   └── threat_model.py          # Shor's algorithm scoring
├── templates/                   # Jinja2 pages
├── static/css/style.css         # Glassmorphism dashboard theme
├── static/js/app.js             # KPI animations, live status poll
├── data/
│   ├── hosts.json               # Hosts for live TLS discovery
│   └── inventory.json           # Centralized certificate inventory
├── sample_reports/              # Pre-generated CSV samples + runtime outputs
└── logs/audit.log               # Structured audit trail (created at runtime)
```

## Setup

```powershell
cd d:\pki_agent
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Optional environment overrides:

| Variable | Default | Purpose |
|---|---|---|
| `PKI_EXPIRY_DAYS` | `45` | Renewal threshold (days) |
| `PKI_CRITICAL_DAYS` | `7` | Critical renewal window |
| `PKI_PORT_START`/`PKI_PORT_END` | `0` / `65000` | Default scan range |
| `PKI_SCAN_TIMEOUT` | `0.4` | Per-port socket timeout |
| `PKI_SCAN_WORKERS` | `256` | Concurrency for socket scan |
| `HSM_ENDPOINT` | `https://hsm.local.example` | Entrust Shield HSM REST endpoint |
| `HSM_API_KEY` | (empty) | If set, real HSM is used; otherwise local fallback |
| `PKI_NOTIFY_WEBHOOK` | (empty) | POST critical alerts to this URL |
| `PKI_NO_SCHEDULER` | (empty) | Set to `1` to disable background scheduler |

## Run

```powershell
python app.py
```

Then open <http://127.0.0.1:5000>.

The background scheduler immediately schedules:
- Daily certificate inventory + expiry report at `03:00`
- Weekly firewall sweep at `04:00`
- Agent decision cycle every 6 hours

## Pages

| Route | Purpose |
|---|---|
| `/` | Mission-control dashboard with KPIs, severity mix, expiring certs, agent decisions, firewall snapshot |
| `/certificates` | Full inventory with search filter and per-cert quantum risk score |
| `/ports` | Firewall scanner form (host, range, engine) + reportable findings |
| `/threat` | Shor's-algorithm-aware quantum exposure per certificate |
| `/hsm` | Entrust Shield HSM status + key-management operational flow |
| `/compliance` | PCI-DSS / HIPAA / ISO 27001 / SOC 2 / NIST 800-53 verdicts |
| `/audit` | Structured audit-log viewer |
| `/reports` | List + download CSV / HTML / PDF reports |

## JSON API

| Endpoint | Description |
|---|---|
| `GET /api/status` | KPI snapshot, critical alerts, scan meta |
| `GET /api/certificates` | Full inventory as JSON |
| `GET /api/ports` | Last scan results + meta |
| `GET /api/decisions` | Latest agent decisions |
| `GET /api/threat/<algo>/<key_size>` | Per-key quantum score |

## Sample reports

Pre-generated samples live in `sample_reports/`:

- `certificate_expiry_report.csv` — 8 certificates across expired / critical / expiring / healthy / quantum-vulnerable / quantum-safe.
- `firewall_scan_report.csv` — diverse open / filtered / closed findings; HTTPS/443 included but flagged as expected.
- `agent_decisions_report.csv` — agent output (`replace_certificate`, `trigger_renewal`, `block_port`, `plan_pqc_migration`, …).

Trigger fresh CSV + HTML + PDF copies from the **Reports** page or via:

```powershell
curl -X POST http://127.0.0.1:5000/actions/generate-expiry-report
```

## Threat model alignment

The system is opinionated about two threat axes:

1. **Classical TLS posture** — every certificate is checked for expiry, weak keys, weak signature algorithms, weak issuers and unknown SANs. The 45-day threshold prevents the long-tail of forgotten-renewal incidents that take down production.
2. **Shor's algorithm** — RSA, DH, DSA and all classical EC curves are scored as quantum-vulnerable. Migration playbooks point at NIST FIPS 203 / 204 / 205 (ML-KEM, ML-DSA, SLH-DSA). The HSM-bound hybrid hierarchy keeps the existing PKI working while PQC pilots are introduced under the same audit trail.

## HSM integration

`pki_agent/hsm_integration.py` exposes an `EntrustShieldHSMClient` (REST) and a `LocalHSMFallback` for development. When `HSM_API_KEY` is set the real client is used; otherwise the system falls back to in-memory generation with `BestAvailableEncryption`, never leaving plaintext private keys on disk. Adapt `_headers()` / endpoint paths to match your appliance's REST schema or subclass for PKCS#11 / KMIP transport.

## Notes & caveats

- A full `0–65000` socket scan against an arbitrary host is heavy. The scanner caps the **socket-engine** at `PKI_SCAN_DEMO_LIMIT` (4096 ports) so the web UI stays responsive; install `nmap` to run the entire range with service detection.
- Live TLS discovery is optional — the system works fully offline with the JSON inventory.
- Running the agent against external hosts must comply with your acceptable-use policy and applicable law. Scan only systems you are authorized to assess.
