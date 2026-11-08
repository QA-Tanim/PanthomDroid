"""Tests for core data models."""

from __future__ import annotations

from phantomdroid.core.models import (
    ComponentInfo,
    ComponentType,
    Confidence,
    DeviceInfo,
    Evidence,
    ExportedState,
    Finding,
    FindingStatus,
    ManifestInfo,
    ScanResult,
    Severity,
)


class TestSeverity:
    def test_order(self):
        assert Severity.CRITICAL.order == 0
        assert Severity.HIGH.order == 1
        assert Severity.MEDIUM.order == 2
        assert Severity.LOW.order == 3
        assert Severity.INFO.order == 4

    def test_comparison(self):
        assert Severity.CRITICAL.order < Severity.HIGH.order
        assert Severity.HIGH.order < Severity.MEDIUM.order

    def test_values(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"


class TestConfidence:
    def test_order(self):
        assert Confidence.HIGH.order == 0
        assert Confidence.MEDIUM.order == 1
        assert Confidence.LOW.order == 2


class TestFinding:
    def test_creation(self):
        f = Finding(
            id="PD-TEST-001",
            title="Test Finding",
            category="Test",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
        )
        assert f.id == "PD-TEST-001"
        assert f.title == "Test Finding"
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH
        assert f.status == FindingStatus.CONFIRMED
        assert f.cwe is None
        assert f.evidence == []

    def test_to_dict(self):
        f = Finding(
            id="PD-TEST-001",
            title="Test",
            category="Test",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            cwe="CWE-798",
        )
        d = f.to_dict()
        assert d["id"] == "PD-TEST-001"
        assert d["severity"] == "HIGH"
        assert d["confidence"] == "HIGH"
        assert d["cwe"] == "CWE-798"

    def test_with_evidence(self):
        ev = Evidence(type="manifest", source="test.xml", attribute="debuggable", value="true")
        f = Finding(
            id="PD-TEST-002",
            title="Test",
            category="Test",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            status=FindingStatus.POTENTIAL,
            evidence=[ev],
        )
        assert len(f.evidence) == 1
        assert f.evidence[0].type == "manifest"


class TestEvidence:
    def test_creation(self):
        ev = Evidence(type="file", source="test.txt")
        assert ev.type == "file"
        assert ev.source == "test.txt"
        assert ev.timestamp is not None

    def test_to_dict(self):
        ev = Evidence(type="command", source="adb shell ls", value="output")
        d = ev.to_dict()
        assert d["type"] == "command"
        assert d["value"] == "output"


class TestManifestInfo:
    def test_creation(self):
        m = ManifestInfo(package_name="com.test", min_sdk=21, target_sdk=33)
        assert m.package_name == "com.test"
        assert m.min_sdk == 21
        assert m.debuggable is False

    def test_to_dict(self):
        m = ManifestInfo(package_name="com.test", debuggable=True)
        d = m.to_dict()
        assert d["package_name"] == "com.test"
        assert d["debuggable"] is True


class TestComponentInfo:
    def test_creation(self):
        c = ComponentInfo(
            name=".MainActivity",
            component_type=ComponentType.ACTIVITY,
            exported=ExportedState.EXPORTED_TRUE,
        )
        assert c.name == ".MainActivity"
        assert c.exported == ExportedState.EXPORTED_TRUE

    def test_to_dict(self):
        c = ComponentInfo(
            name=".Service",
            component_type=ComponentType.SERVICE,
            exported=ExportedState.EXPORTED_FALSE,
        )
        d = c.to_dict()
        assert d["component_type"] == "service"
        assert d["exported"] == "exported_false"


class TestDeviceInfo:
    def test_creation(self):
        dev = DeviceInfo(serial="ABC123", model="Pixel 6", android_version="14")
        assert dev.serial == "ABC123"
        assert dev.model == "Pixel 6"

    def test_to_dict(self):
        dev = DeviceInfo(serial="ABC123", sdk_level=34, is_emulator=True)
        d = dev.to_dict()
        assert d["sdk_level"] == 34
        assert d["is_emulator"] is True


class TestScanResult:
    def test_creation(self):
        r = ScanResult(target="test.apk", scan_type="apk")
        assert r.target == "test.apk"
        assert r.finding_count == 0

    def test_severity_counts(self):
        r = ScanResult(target="test", scan_type="test")
        r.findings = [
            Finding(id="1", title="1", category="c", severity=Severity.HIGH, confidence=Confidence.HIGH, status=FindingStatus.CONFIRMED),
            Finding(id="2", title="2", category="c", severity=Severity.HIGH, confidence=Confidence.HIGH, status=FindingStatus.CONFIRMED),
            Finding(id="3", title="3", category="c", severity=Severity.LOW, confidence=Confidence.LOW, status=FindingStatus.INFORMATIONAL),
        ]
        counts = r.severity_counts
        assert counts["HIGH"] == 2
        assert counts["LOW"] == 1

    def test_highest_severity(self):
        r = ScanResult(target="test", scan_type="test")
        assert r.highest_severity is None
        r.findings = [
            Finding(id="1", title="1", category="c", severity=Severity.LOW, confidence=Confidence.LOW, status=FindingStatus.INFORMATIONAL),
            Finding(id="2", title="2", category="c", severity=Severity.CRITICAL, confidence=Confidence.HIGH, status=FindingStatus.CONFIRMED),
        ]
        assert r.highest_severity == Severity.CRITICAL
