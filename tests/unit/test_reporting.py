"""Tests for reporting modules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from phantomdroid.core.models import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    ManifestInfo,
    ScanResult,
    Severity,
)
from phantomdroid.reporting.html_report import generate_html_report
from phantomdroid.reporting.json_report import generate_json_report
from phantomdroid.reporting.sarif_report import generate_sarif_report


@pytest.fixture
def sample_result() -> ScanResult:
    """Create a sample ScanResult for testing."""
    result = ScanResult(target="test.apk", scan_type="apk")
    result.manifest = ManifestInfo(
        package_name="com.test.app",
        min_sdk=21,
        target_sdk=33,
        debuggable=True,
        allow_backup=True,
    )
    result.findings = [
        Finding(
            id="PD-TEST-001",
            title="Test Finding",
            category="Test",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            cwe="CWE-798",
            description="This is a test finding.",
            evidence=[
                Evidence(type="manifest", source="test.xml", attribute="debug", value="true"),
            ],
            remediation="Fix this.",
        ),
        Finding(
            id="PD-TEST-002",
            title="Low Finding",
            category="Test",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            status=FindingStatus.HEURISTIC,
            description="Low severity finding.",
        ),
    ]
    return result


class TestJsonReport:
    def test_generate(self, sample_result: ScanResult, tmp_path: Path):
        output = tmp_path / "report.json"
        result_path = generate_json_report(sample_result, str(output))
        assert Path(result_path).exists()

        with open(result_path) as f:
            data = json.load(f)

        assert data["tool"] == "PhantomDroid X"
        assert data["target"] == "test.apk"
        assert data["summary"]["total_findings"] == 2
        assert data["summary"]["severity_counts"]["HIGH"] == 1

    def test_pretty(self, sample_result: ScanResult, tmp_path: Path):
        output = tmp_path / "report.json"
        generate_json_report(sample_result, str(output), pretty=True)
        content = output.read_text()
        assert "\n" in content  # Pretty-printed


class TestHtmlReport:
    def test_generate(self, sample_result: ScanResult, tmp_path: Path):
        output = tmp_path / "report.html"
        result_path = generate_html_report(sample_result, str(output))
        assert Path(result_path).exists()

        content = output.read_text()
        assert "PhantomDroid X" in content
        assert "Test Finding" in content
        assert "CWE-798" in content

    def test_html_escaping(self, sample_result: ScanResult, tmp_path: Path):
        """Verify that HTML content is properly escaped."""
        # Add a finding with HTML in the description
        sample_result.findings.append(
            Finding(
                id="PD-XSS-001",
                title="<script>alert('xss')</script>",
                category="Test",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description="Test <b>bold</b> & special chars",
            )
        )
        output = tmp_path / "report.html"
        generate_html_report(sample_result, str(output))
        content = output.read_text()
        # Script tag should be escaped
        assert "<script>" not in content
        assert "&lt;script&gt;" in content


class TestSarifReport:
    def test_generate(self, sample_result: ScanResult, tmp_path: Path):
        output = tmp_path / "report.sarif"
        result_path = generate_sarif_report(sample_result, str(output))
        assert Path(result_path).exists()

        with open(result_path) as f:
            data = json.load(f)

        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "PhantomDroid X"
        assert len(run["results"]) == 2

    def test_sarif_rule(self, sample_result: ScanResult, tmp_path: Path):
        output = tmp_path / "report.sarif"
        generate_sarif_report(sample_result, str(output))
        with open(output) as f:
            data = json.load(f)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1
        assert rules[0]["id"] == "PD-TEST-001"
