"""Tests for scanner engine."""

from __future__ import annotations

from phantomdroid.core.models import Confidence, Finding, FindingStatus, Severity
from phantomdroid.core.scanner import ScanContext, ScannerEngine, SecurityCheck


class DummyCheck(SecurityCheck):
    id = "PD-DUMMY-001"
    name = "Dummy Check"
    category = "test"

    def run(self, context: ScanContext) -> list[Finding]:
        return [
            Finding(
                id="PD-DUMMY-001",
                title="Dummy Finding",
                category="Test",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
            )
        ]


class FailingCheck(SecurityCheck):
    id = "PD-FAIL-001"
    name = "Failing Check"
    category = "test"

    def run(self, context: ScanContext) -> list[Finding]:
        raise RuntimeError("Check failed")

    def can_run(self, context: ScanContext) -> bool:
        return True


class SkippedCheck(SecurityCheck):
    id = "PD-SKIP-001"
    name = "Skipped Check"
    category = "other"

    def run(self, context: ScanContext) -> list[Finding]:
        return []

    def can_run(self, context: ScanContext) -> bool:
        return False


class TestScannerEngine:
    def test_register(self):
        engine = ScannerEngine()
        engine.register(DummyCheck())
        assert engine.check_count == 1

    def test_register_many(self):
        engine = ScannerEngine()
        engine.register_many([DummyCheck(), FailingCheck()])
        assert engine.check_count == 2

    def test_get_checks_by_category(self):
        engine = ScannerEngine()
        engine.register(DummyCheck())
        engine.register(SkippedCheck())
        test_checks = engine.get_checks(category="test")
        assert len(test_checks) == 1
        assert test_checks[0].id == "PD-DUMMY-001"

    def test_run(self):
        engine = ScannerEngine()
        engine.register(DummyCheck())
        context = ScanContext(target="test", scan_type="test")
        result = engine.run(context)
        assert result.finding_count == 1
        assert result.findings[0].title == "Dummy Finding"

    def test_run_with_failing_check(self):
        engine = ScannerEngine()
        engine.register(FailingCheck())
        context = ScanContext(target="test", scan_type="test")
        result = engine.run(context)
        assert result.finding_count == 0
        assert len(result.errors) == 1

    def test_run_with_skipped_check(self):
        engine = ScannerEngine()
        engine.register(SkippedCheck())
        context = ScanContext(target="test", scan_type="test")
        result = engine.run(context)
        assert result.finding_count == 0
        assert len(result.warnings) == 1

    def test_categories(self):
        engine = ScannerEngine()
        engine.register(DummyCheck())
        engine.register(SkippedCheck())
        cats = engine.categories
        assert "test" in cats
        assert "other" in cats

    def test_run_with_category_filter(self):
        engine = ScannerEngine()
        engine.register(DummyCheck())
        engine.register(SkippedCheck())
        context = ScanContext(target="test", scan_type="test")
        result = engine.run(context, categories=["test"])
        assert result.finding_count == 1
