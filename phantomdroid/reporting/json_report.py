"""PhantomDroid X - JSON report generator."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from phantomdroid.core.models import ScanResult


def generate_json_report(
    result: ScanResult,
    output_path: str,
    pretty: bool = True,
) -> str:
    """Generate a JSON report from scan results.

    Args:
        result: ScanResult to report on.
        output_path: Path to write the JSON file.
        pretty: Whether to pretty-print the JSON.

    Returns:
        Path to the generated report.
    """
    report: dict[str, Any] = {
        "tool": "PhantomDroid X",
        "version": "3.0.0",
        "generated": datetime.now().isoformat(),
        "target": result.target,
        "scan_type": result.scan_type,
        "summary": {
            "total_findings": result.finding_count,
            "severity_counts": result.severity_counts,
            "confidence_counts": result.confidence_counts,
            "highest_severity": result.highest_severity.value if result.highest_severity else None,
            "errors": len(result.errors),
            "warnings": len(result.warnings),
        },
        "findings": [f.to_dict() for f in result.findings],
        "manifest": result.manifest.to_dict() if result.manifest else None,
        "components": [c.to_dict() for c in result.components],
        "permissions": [p.to_dict() for p in result.permissions],
        "device": result.device.to_dict() if result.device else None,
        "metadata": result.metadata,
        "timing": {
            "start": result.start_time.isoformat(),
            "end": result.end_time.isoformat() if result.end_time else None,
        },
        "errors": result.errors,
        "warnings": result.warnings,
    }

    indent = 2 if pretty else None
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=indent, default=str, ensure_ascii=False)

    return output_path
