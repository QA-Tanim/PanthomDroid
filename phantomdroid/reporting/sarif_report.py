"""PhantomDroid X - SARIF 2.1.0 report generator."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from phantomdroid.core.models import Finding, ScanResult


def generate_sarif_report(
    result: ScanResult,
    output_path: str,
) -> str:
    """Generate a SARIF 2.1.0 report.

    Args:
        result: ScanResult to report on.
        output_path: Path to write the SARIF file.

    Returns:
        Path to the generated report.
    """
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_ids: set[str] = set()

    for finding in result.findings:
        if finding.id not in rule_ids:
            rule_ids.add(finding.id)
            rules.append(_rule_to_sarif(finding))
        results.append(_finding_to_sarif(finding))

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PhantomDroid X",
                        "version": "3.0.0",
                        "informationUri": "https://github.com/phantomdroid/phantomdroid-x",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": result.start_time.astimezone(UTC).isoformat(),
                        "endTimeUtc": (
                            result.end_time.astimezone(UTC).isoformat()
                            if result.end_time
                            else datetime.now(UTC).isoformat()
                        ),
                    }
                ],
            }
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)

    return output_path


def _rule_to_sarif(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to a SARIF rule."""
    rule: dict[str, Any] = {
        "id": finding.id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "helpUri": finding.references[0] if finding.references else "",
        "properties": {
            "category": finding.category,
            "confidence": finding.confidence.value,
            "status": finding.status.value,
        },
    }

    if finding.cwe:
        rule["properties"]["cwe"] = finding.cwe

    if finding.owasp_masvs:
        rule["properties"]["owasp_masvs"] = finding.owasp_masvs

    return rule


def _finding_to_sarif(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to a SARIF result."""
    level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }

    level = level_map.get(finding.severity.value, "note")

    result: dict[str, Any] = {
        "ruleId": finding.id,
        "level": level,
        "message": {"text": finding.description},
        "locations": [],
        "properties": {
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "status": finding.status.value,
        },
    }

    if finding.affected_component:
        result["locations"].append({
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.affected_component,
                },
            },
        })

    if finding.evidence:
        result["properties"]["evidence"] = [
            {
                "type": ev.type,
                "source": ev.source,
                "attribute": ev.attribute,
                "value": ev.value,
            }
            for ev in finding.evidence
        ]

    return result
