"""Report generation in CSV, HTML, and PDF formats."""

import html
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from .audit import AuditLogger
from .config import REPORT_DIR
from .models import AgentDecision, AlertRecord, CertificateRecord, ScanResult


CERT_COLUMNS = [
    'domain', 'issuer', 'not_after', 'days_remaining', 'status',
    'key_algorithm', 'key_size', 'quantum_risk', 'recommendations',
]
SCAN_COLUMNS = [
    'host', 'port', 'state', 'service', 'risk', 'policy_violation',
    'vulnerability_class', 'vulnerability_description',
    'attack_vector', 'mitigation', 'references',
    'product', 'version', 'intrusion_indicator', 'notes',
]


def _timestamp() -> str:
    return datetime.utcnow().strftime('%Y%m%d_%H%M%S')


class ReportManager:
    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        self.audit = audit_logger
        self.report_dir: Path = REPORT_DIR
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.last_reports = {}

    # -- public API ----------------------------------------------------------

    def generate_certificate_expiry_report(self, certs: Iterable[CertificateRecord]) -> dict:
        certs = list(certs)
        rows = [c.to_dict() for c in certs]
        df = pd.DataFrame(rows, columns=CERT_COLUMNS) if rows else pd.DataFrame(columns=CERT_COLUMNS)
        stem = self.report_dir / f'certificate_expiry_{_timestamp()}'
        paths = self._write_all(stem, 'Certificate Expiry Report', df)
        self.last_reports['certificate_expiry'] = paths
        # Also keep a stable "latest" alias so the UI can link without history lookup.
        self._write_all(self.report_dir / 'certificate_expiry_report', 'Certificate Expiry Report', df)
        if self.audit:
            self.audit.record('Certificate expiry report generated', metadata={'rows': len(rows)})
        return paths

    def generate_firewall_report(self, scans: Iterable[ScanResult]) -> dict:
        scans = list(scans)
        rows = [s.to_dict() for s in scans]
        df = pd.DataFrame(rows, columns=SCAN_COLUMNS) if rows else pd.DataFrame(columns=SCAN_COLUMNS)
        stem = self.report_dir / f'firewall_scan_{_timestamp()}'
        paths = self._write_all(stem, 'Firewall Scan Report', df)
        self.last_reports['firewall'] = paths
        self._write_all(self.report_dir / 'firewall_scan_report', 'Firewall Scan Report', df)
        if self.audit:
            self.audit.record('Firewall scan report generated', metadata={'rows': len(rows)})
        return paths

    def generate_agent_decisions_report(self, decisions: Iterable[AgentDecision]) -> dict:
        rows = [d.to_dict() for d in decisions]
        cols = ['decided_at', 'action', 'target', 'severity', 'confidence', 'automated', 'rationale']
        df = pd.DataFrame(rows, columns=cols) if rows else pd.DataFrame(columns=cols)
        stem = self.report_dir / f'agent_decisions_{_timestamp()}'
        paths = self._write_all(stem, 'Agent Decision Log', df)
        self.last_reports['decisions'] = paths
        self._write_all(self.report_dir / 'agent_decisions_report', 'Agent Decision Log', df)
        if self.audit:
            self.audit.record('Agent decisions report generated', metadata={'rows': len(rows)})
        return paths

    def list_reports(self) -> List[dict]:
        files = []
        for path in sorted(self.report_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if path.is_file() and path.suffix in {'.csv', '.html', '.pdf'}:
                files.append({
                    'name': path.name,
                    'size': path.stat().st_size,
                    'modified': datetime.utcfromtimestamp(path.stat().st_mtime).isoformat() + 'Z',
                    'kind': path.suffix.lstrip('.'),
                })
        return files

    def get_last_report(self, kind: str) -> Optional[dict]:
        return self.last_reports.get(kind)

    # -- writers -------------------------------------------------------------

    def _write_all(self, stem: Path, title: str, df: pd.DataFrame) -> dict:
        csv_path = stem.with_suffix('.csv')
        html_path = stem.with_suffix('.html')
        pdf_path = stem.with_suffix('.pdf')
        df.to_csv(csv_path, index=False)
        self._write_html(html_path, title, df)
        self._write_pdf(pdf_path, title, df)
        return {'csv': str(csv_path), 'html': str(html_path), 'pdf': str(pdf_path)}

    def _write_html(self, path: Path, title: str, df: pd.DataFrame) -> None:
        rows_html = ''.join(
            '<tr>' + ''.join(f'<td>{html.escape(str(v))}</td>' for v in row) + '</tr>'
            for row in df.itertuples(index=False)
        )
        headers_html = ''.join(f'<th>{html.escape(c)}</th>' for c in df.columns)
        body = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
 body {{ font-family: 'Segoe UI', Inter, sans-serif; background: #0b1220; color: #e2e8f0; padding: 32px; }}
 h1 {{ color: #38bdf8; letter-spacing: -.02em; }}
 .meta {{ color: #94a3b8; margin-bottom: 24px; }}
 table {{ width: 100%; border-collapse: collapse; background: rgba(15,23,42,.6); }}
 th, td {{ padding: 10px 12px; border-bottom: 1px solid rgba(148,163,184,.15); text-align: left; }}
 th {{ background: rgba(56,189,248,.1); color: #38bdf8; font-weight: 600; }}
 tr:hover td {{ background: rgba(56,189,248,.05); }}
</style></head><body>
<h1>{html.escape(title)}</h1>
<div class="meta">Generated: {datetime.utcnow().isoformat()}Z &middot; {len(df)} records</div>
<table><thead><tr>{headers_html}</tr></thead><tbody>{rows_html}</tbody></table>
</body></html>"""
        path.write_text(body, encoding='utf-8')

    def _write_pdf(self, path: Path, title: str, df: pd.DataFrame) -> None:
        doc = SimpleDocTemplate(str(path), pagesize=letter,
                                leftMargin=0.5 * inch, rightMargin=0.5 * inch,
                                topMargin=0.5 * inch, bottomMargin=0.5 * inch)
        styles = getSampleStyleSheet()
        story = [
            Paragraph(f'<b>{html.escape(title)}</b>', styles['Title']),
            Paragraph(f'Generated: {datetime.utcnow().isoformat()}Z &nbsp;·&nbsp; {len(df)} records',
                      styles['Normal']),
            Spacer(1, 12),
        ]
        if df.empty:
            story.append(Paragraph('<i>No records.</i>', styles['Normal']))
        else:
            data = [[str(c) for c in df.columns]] + [
                [str(v)[:40] for v in row] for row in df.itertuples(index=False)
            ]
            tbl = Table(data, repeatRows=1)
            tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a8a')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                 [colors.HexColor('#f8fafc'), colors.HexColor('#e2e8f0')]),
                ('GRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#94a3b8')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(tbl)
        doc.build(story)
