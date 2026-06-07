"""Flask web UI + JSON API for the PKI Agentic AI System."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from flask import (
    Flask, abort, jsonify, render_template, request, send_from_directory,
    redirect, url_for, flash,
)

from pki_agent.ai_agent import AutonomousAgent, RiskEngine
from pki_agent.audit import AuditLogger
from pki_agent.compliance import aggregate as aggregate_compliance, FRAMEWORK_CONTROLS
from pki_agent.config import (
    ALLOWED_PORT, EXPIRY_THRESHOLD_DAYS, CRITICAL_EXPIRY_DAYS,
    SCAN_PORT_START, SCAN_PORT_END, REPORT_DIR, HSM_VENDOR,
    FLASK_SECRET, IS_SERVERLESS,
)
from pki_agent.discovery import CertificateInventory
from pki_agent.hsm_integration import get_hsm_client, HSMIntegrationError
from pki_agent.notifier import Notifier
from pki_agent.reporting import ReportManager
from pki_agent.scanner import NetworkScanner
from pki_agent.scheduler import Scheduler
from pki_agent.threat_model import ThreatModel
from pki_agent import supply_chain as supply_chain_module

# -- service wiring -----------------------------------------------------------

audit          = AuditLogger()
inventory      = CertificateInventory(audit_logger=audit)
scanner        = NetworkScanner(audit_logger=audit)
risk_engine    = RiskEngine(audit_logger=audit)
report_manager = ReportManager(audit_logger=audit)
threat         = ThreatModel()
agent          = AutonomousAgent(risk_engine, audit)
notifier       = Notifier(audit)
scheduler      = Scheduler(inventory, scanner, risk_engine, report_manager, audit, agent, notifier)

app = Flask(__name__)
# Use FLASK_SECRET from config (reads PKI_FLASK_SECRET env var).
# On Vercel set PKI_FLASK_SECRET in the dashboard — never commit a real secret.
app.secret_key = FLASK_SECRET

# -- helpers ------------------------------------------------------------------

def _dashboard_context():
    certs       = inventory.load_inventory()
    alerts      = risk_engine.evaluate_certificate_inventory(certs)
    scan_results = scanner.load_last_scan()
    scan_alerts  = risk_engine.evaluate_scan(scan_results)

    supply_findings = []
    try:
        supply_findings = supply_chain_module.run_bumblebee()
        if supply_findings:
            supply_chain_module.record_findings(supply_findings, audit)
            supply_chain_module.persist_findings(supply_findings)
    except Exception:
        supply_findings = supply_chain_module.load_persisted()

    decisions = agent.decide(certs, scan_results, supply_findings)

    return {
        'certs':              certs,
        'alerts':             alerts,
        'scan_alerts':        scan_alerts,
        'decisions':          decisions,
        'scan_meta':          scanner.last_meta,
        'scan_results':       scan_results,
        'supply_findings':    supply_findings,
        'summary':            threat.summary(),
        'expiry_threshold':   EXPIRY_THRESHOLD_DAYS,
        'critical_threshold': CRITICAL_EXPIRY_DAYS,
        'scan_range':         (SCAN_PORT_START, SCAN_PORT_END),
        'hsm_vendor':         HSM_VENDOR,
        'allowed_port':       ALLOWED_PORT,
    }


def _severity_counts(records, key='severity'):
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for r in records:
        sev = getattr(r, key, 'low')
        counts[sev] = counts.get(sev, 0) + 1
    return counts

# -- pages --------------------------------------------------------------------

@app.route('/')
def dashboard():
    ctx = _dashboard_context()
    ctx['severity_counts'] = _severity_counts(ctx['alerts'])
    ctx['expiring'] = sorted(
        [c for c in ctx['certs'] if 0 < c.days_remaining <= EXPIRY_THRESHOLD_DAYS],
        key=lambda c: c.days_remaining,
    )
    ctx['expired']           = [c for c in ctx['certs'] if c.days_remaining <= 0]
    ctx['quantum_vulnerable'] = [c for c in ctx['certs'] if c.quantum_score >= 70]
    return render_template('dashboard.html', **ctx)


@app.route('/certificates')
def certificates():
    ctx = _dashboard_context()
    return render_template('certificates.html', **ctx)


@app.route('/ports', methods=['GET', 'POST'])
def ports():
    if request.method == 'POST':
        host = request.form.get('host', '127.0.0.1').strip() or '127.0.0.1'
        try:
            start = int(request.form.get('start_port', SCAN_PORT_START))
            end   = int(request.form.get('end_port',   SCAN_PORT_END))
        except ValueError:
            start, end = SCAN_PORT_START, SCAN_PORT_END
        engine = request.form.get('engine', 'auto')
        scanner.perform_firewall_scan(host=host, start_port=start, end_port=end, engine=engine)
        report_manager.generate_firewall_report(scanner.load_last_scan())
        flash(f'Scan complete: {scanner.last_meta.get("total", 0)} reportable ports.', 'success')
        return redirect(url_for('ports'))

    ctx = _dashboard_context()
    ctx['suspicious'] = scanner.suspicious_findings()
    return render_template('ports.html', **ctx)


@app.route('/threat')
def threat_page():
    certs = inventory.load_inventory()
    scored = [
        {'cert': c, 'score': threat.score_certificate(c.key_algorithm, c.key_size)}
        for c in certs
    ]
    return render_template(
        'threat.html',
        summary=threat.summary(),
        scored=scored,
        expiry_threshold=EXPIRY_THRESHOLD_DAYS,
    )


@app.route('/hsm')
def hsm_page():
    client = get_hsm_client()
    info = {'vendor': getattr(client, 'vendor', HSM_VENDOR)}
    try:
        info.update(client.health())
    except HSMIntegrationError as exc:
        info['status'] = 'unreachable'
        info['error']  = str(exc)
    return render_template('hsm.html', hsm=info, hsm_vendor=HSM_VENDOR)


@app.route('/compliance')
def compliance_page():
    certs           = inventory.load_inventory()
    scans           = scanner.load_last_scan()
    supply_findings = supply_chain_module.load_persisted()
    verdicts        = aggregate_compliance(certs, scans, supply_findings)
    return render_template('compliance.html', verdicts=verdicts, frameworks=FRAMEWORK_CONTROLS)


@app.route('/supply-chain')
def supply_chain():
    findings   = supply_chain_module.load_persisted()
    certs      = inventory.load_inventory()
    scans      = scanner.load_last_scan()
    compliance = aggregate_compliance(certs, scans, findings)
    return render_template('supply_chain.html', supply_findings=findings, compliance=compliance)


@app.route('/audit')
def audit_page():
    return render_template('audit.html', events=audit.tail(limit=400))


@app.route('/reports')
def reports():
    return render_template('reports.html', reports=report_manager.list_reports())


@app.route('/reports/<path:filename>')
def reports_download(filename: str):
    safe_path = Path(filename).name  # prevent path traversal
    full = REPORT_DIR / safe_path
    if not full.exists():
        abort(404)
    return send_from_directory(str(REPORT_DIR), safe_path, as_attachment=True)

# -- actions ------------------------------------------------------------------

@app.route('/actions/generate-expiry-report', methods=['POST'])
def action_generate_expiry():
    certs = inventory.load_inventory()
    paths = report_manager.generate_certificate_expiry_report(certs)
    flash(f'Generated expiry report ({Path(paths["csv"]).name}).', 'success')
    return redirect(request.referrer or url_for('reports'))


@app.route('/actions/run-agent', methods=['GET', 'POST'])
def action_run_agent():
    """Supports both POST (web UI button) and GET (Vercel Cron job)."""
    certs           = inventory.load_inventory()
    supply_findings = supply_chain_module.load_persisted()
    decisions       = agent.decide(certs, scanner.load_last_scan(), supply_findings)
    report_manager.generate_agent_decisions_report(decisions)

    if request.method == 'GET':
        # Called by Vercel Cron — return JSON instead of redirect
        return jsonify({'decisions': len(decisions), 'status': 'ok'})

    flash(f'Agent emitted {len(decisions)} decisions.', 'success')
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/actions/refresh-inventory', methods=['POST'])
def action_refresh_inventory():
    hosts = inventory.load_hosts()
    if hosts:
        inventory.merge_live_into_inventory(hosts)
        flash(f'Probed {len(hosts)} hosts and merged into inventory.', 'success')
    else:
        flash('No hosts configured in data/hosts.json — using local inventory.', 'info')
    return redirect(request.referrer or url_for('certificates'))

# -- JSON API -----------------------------------------------------------------

@app.route('/api/status')
def api_status():
    ctx = _dashboard_context()
    return jsonify({
        'timestamp':               datetime.utcnow().isoformat() + 'Z',
        'certificate_count':       len(ctx['certs']),
        'expiring_within_threshold': sum(
            1 for c in ctx['certs'] if 0 < c.days_remaining <= EXPIRY_THRESHOLD_DAYS
        ),
        'expired':            sum(1 for c in ctx['certs'] if c.days_remaining <= 0),
        'quantum_vulnerable': sum(1 for c in ctx['certs'] if c.quantum_score >= 70),
        'critical_alerts':    [a.to_dict() for a in ctx['alerts'] if a.severity == 'critical'],
        'scan_meta':          scanner.last_meta,
        'decisions_pending':  sum(1 for d in ctx['decisions'] if not d.automated),
    })


@app.route('/api/certificates')
def api_certificates():
    return jsonify([c.to_dict() for c in inventory.load_inventory()])


@app.route('/api/ports')
def api_ports():
    return jsonify({
        'meta':    scanner.last_meta,
        'results': [r.to_dict() for r in scanner.load_last_scan()],
    })


@app.route('/api/decisions')
def api_decisions():
    supply_findings = supply_chain_module.load_persisted()
    decisions = agent.decide(inventory.load_inventory(), scanner.load_last_scan(), supply_findings)
    return jsonify([d.to_dict() for d in decisions])


@app.route('/api/threat/<algorithm>/<int:key_size>')
def api_threat_score(algorithm: str, key_size: int):
    return jsonify(threat.score_certificate(algorithm, key_size))

# -- bootstrap ----------------------------------------------------------------

def _start_background():
    """Start the in-process scheduler only in long-lived (non-serverless) environments."""
    if IS_SERVERLESS or os.getenv('PKI_NO_SCHEDULER') == '1':
        return
    scheduler.start()


_start_background()

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', '5000')),
        debug=True,
        use_reloader=False,
    )