"""Tests for evidence collector and sanitizer."""

from __future__ import annotations

from phantomdroid.core.models import Evidence
from phantomdroid.evidence.collector import EvidenceCollector, EvidenceSanitizer


class TestEvidenceCollector:
    def test_add(self):
        collector = EvidenceCollector(redact_secrets=False)
        ev = collector.add("manifest", "test.xml", attribute="debug", value="true")
        assert ev.type == "manifest"
        assert ev.source == "test.xml"
        assert len(collector.get_all()) == 1

    def test_add_manifest_evidence(self):
        collector = EvidenceCollector(redact_secrets=False)
        ev = collector.add_manifest_evidence("debuggable", "true", "com.test")
        assert ev.component == "com.test"
        assert ev.attribute == "debuggable"

    def test_redaction(self):
        collector = EvidenceCollector(redact_secrets=True)
        ev = collector.add("file", "config.txt", value="password=secret123")
        assert "secret123" not in (ev.value or "")
        assert "********" in (ev.value or "")

    def test_no_redaction(self):
        collector = EvidenceCollector(redact_secrets=False)
        ev = collector.add("file", "config.txt", value="password=secret123")
        assert ev.value == "password=secret123"

    def test_clear(self):
        collector = EvidenceCollector()
        collector.add("test", "source")
        assert len(collector.get_all()) == 1
        collector.clear()
        assert len(collector.get_all()) == 0


class TestEvidenceSanitizer:
    def test_sanitize_with_sensitive(self):
        ev = Evidence(type="file", source="test", value="password=mysecretpassword")
        sanitized = EvidenceSanitizer.sanitize(ev, show_sensitive=False)
        assert "mysecretpassword" not in (sanitized.value or "")

    def test_sanitize_without_sensitive(self):
        ev = Evidence(type="file", source="test", value="password=mysecretpassword")
        sanitized = EvidenceSanitizer.sanitize(ev, show_sensitive=True)
        assert sanitized.value == "password=mysecretpassword"

    def test_sanitize_no_value(self):
        ev = Evidence(type="file", source="test")
        sanitized = EvidenceSanitizer.sanitize(ev, show_sensitive=False)
        assert sanitized.value is None
