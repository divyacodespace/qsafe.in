"""Supply-chain scanning integration (Bumblebee runner + helpers).

Runs the Bumblebee CLI as a subprocess, parses NDJSON findings, and
exposes helpers to return findings and record them into the audit trail.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from .audit import AuditLogger
from .config import DATA_DIR


def run_bumblebee(catalog_path: str = "threat_intel/") -> List[Dict[str, Any]]:
    """Run `bumblebee scan --profile deep` against `catalog_path` and
    return a list of parsed NDJSON findings.

    If the `bumblebee` binary is not available or the scan fails, this
    returns an empty list.
    """
    try:
        result = subprocess.run(
            [
                "bumblebee",
                "scan",
                "--profile",
                "deep",
                "--exposure-catalog",
                catalog_path,
                "--findings-only",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return []
    out: List[Dict[str, Any]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            out.append(obj)
        except json.JSONDecodeError:
            continue
    return out


def record_findings(findings: List[Dict[str, Any]], audit: Optional[AuditLogger] = None) -> int:
    """Append Bumblebee findings to the audit log via the provided
    AuditLogger. Returns the number of findings recorded.
    """
    if not findings:
        return 0
    if audit is None:
        audit = AuditLogger()
    for f in findings:
        sev = f.get('severity') or f.get('level') or 'high'
        action = 'supply_chain_finding'
        metadata = f.copy()
        audit.record(action, severity=sev, metadata=metadata)
    return len(findings)


def persist_findings(findings: List[Dict[str, Any]]) -> Path:
    """Persist last findings to data/supply_chain_findings.jsonl and
    return the path for quick reload by the UI.
    """
    out = DATA_DIR / 'supply_chain_findings.jsonl'
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('w', encoding='utf-8') as fh:
        for f in findings:
            fh.write(json.dumps(f, default=str) + '\n')
    return out


def load_persisted() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    p = DATA_DIR / 'supply_chain_findings.jsonl'
    if not p.exists():
        return out
    with p.open('r', encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out
