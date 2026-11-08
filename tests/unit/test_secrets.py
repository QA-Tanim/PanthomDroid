"""Tests for secret scanner."""

from __future__ import annotations

from phantomdroid.analyzers.apk.secrets import (
    calculate_shannon_entropy,
    redact_secret,
    scan_for_secrets,
    secrets_to_findings,
)
from phantomdroid.core.models import Confidence, Severity


class TestShannonEntropy:
    def test_empty(self):
        assert calculate_shannon_entropy("") == 0.0

    def test_low_entropy(self):
        # Repeated character has low entropy
        entropy = calculate_shannon_entropy("aaaaaaaaaa")
        assert entropy < 1.0

    def test_high_entropy(self):
        # Random-looking string has higher entropy
        entropy = calculate_shannon_entropy("aB3$xK9!mN")
        assert entropy > 2.0

    def test_hex_string(self):
        entropy = calculate_shannon_entropy("0123456789abcdef")
        assert entropy > 3.0


class TestRedactSecret:
    def test_long_secret(self):
        redacted = redact_secret("AKIAIOSFODNN7EXAMPLE", keep_start=4, keep_end=4)
        assert redacted.startswith("AKIA")
        assert redacted.endswith("MPLE")
        assert "IOSFODNN7EXA" not in redacted

    def test_short_secret(self):
        redacted = redact_secret("short", keep_start=2, keep_end=2)
        assert len(redacted) == len("short")

    def test_exact_boundary(self):
        redacted = redact_secret("12345678", keep_start=4, keep_end=4)
        assert redacted == "********"


class TestScanForSecrets:
    def test_aws_key(self):
        content = 'aws_access_key = "AKIAIOSFODNN7EXAMPLE"'
        matches = scan_for_secrets(content, "test.txt", min_entropy=2.0)
        aws_matches = [m for m in matches if m.pattern_name == "aws_access_key"]
        assert len(aws_matches) >= 1
        assert aws_matches[0].severity == Severity.CRITICAL

    def test_private_key(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ..."
        matches = scan_for_secrets(content, "test.pem", min_entropy=2.0)
        key_matches = [m for m in matches if m.pattern_name == "private_key"]
        assert len(key_matches) >= 1

    def test_no_match(self):
        content = "This is a normal text file with no secrets."
        matches = scan_for_secrets(content, "readme.txt", min_entropy=5.0)
        # Should have no high-confidence matches
        high_matches = [m for m in matches if m.confidence == Confidence.HIGH]
        assert len(high_matches) == 0

    def test_redaction(self):
        content = 'api_key = "AKIAIOSFODNN7EXAMPLE"'
        matches = scan_for_secrets(content, "config.txt", min_entropy=2.0)
        for m in matches:
            assert m.redacted_text != "AKIAIOSFODNN7EXAMPLE"

    def test_url_with_creds(self):
        content = "db_url = http://admin:password123@localhost/mydb"
        matches = scan_for_secrets(content, "config.txt", min_entropy=2.0)
        url_matches = [m for m in matches if m.pattern_name == "url_creds"]
        assert len(url_matches) >= 1


class TestSecretsToFindings:
    def test_conversion(self):
        from phantomdroid.analyzers.apk.secrets import SecretMatch
        matches = [
            SecretMatch(
                secret_type="AWS Key",
                pattern_name="aws_access_key",
                file_path="config.txt",
                line_number=1,
                matched_text="AKIAIOSFODNN7EXAMPLE",
                redacted_text="AKIA************MPLE",
                entropy=4.5,
                confidence=Confidence.HIGH,
                severity=Severity.CRITICAL,
            )
        ]
        findings = secrets_to_findings(matches)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].confidence == Confidence.HIGH

    def test_deduplication(self):
        from phantomdroid.analyzers.apk.secrets import SecretMatch
        matches = [
            SecretMatch("AWS Key", "aws_access_key", "config.txt", 1, "key1", "key1_redacted", 4.5, Confidence.HIGH, Severity.CRITICAL),
            SecretMatch("AWS Key", "aws_access_key", "config.txt", 2, "key1", "key1_redacted", 4.5, Confidence.HIGH, Severity.CRITICAL),
        ]
        findings = secrets_to_findings(matches)
        assert len(findings) == 1
