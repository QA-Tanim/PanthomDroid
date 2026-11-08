"""PhantomDroid X - Evidence collection and management."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from phantomdroid.core.models import Evidence


class EvidenceCollector:
    """Collects and manages evidence for findings."""

    def __init__(self, redact_secrets: bool = True) -> None:
        self._evidence: list[Evidence] = []
        self._redact_secrets = redact_secrets

    def add(
        self,
        evidence_type: str,
        source: str,
        component: str | None = None,
        attribute: str | None = None,
        value: str | None = None,
    ) -> Evidence:
        """Add evidence and return it."""
        if self._redact_secrets and value:
            value = self._redact_value(value)
        ev = Evidence(
            type=evidence_type,
            source=source,
            component=component,
            attribute=attribute,
            value=value,
            timestamp=datetime.now(),
        )
        self._evidence.append(ev)
        return ev

    def add_manifest_evidence(
        self, attribute: str, value: str, package: str = ""
    ) -> Evidence:
        return self.add("manifest", "AndroidManifest.xml", package, attribute, value)

    def add_file_evidence(
        self, file_path: str, attribute: str, value: str
    ) -> Evidence:
        return self.add("file", file_path, attribute=attribute, value=value)

    def add_command_evidence(
        self, command: str, output: str, component: str | None = None
    ) -> Evidence:
        return self.add("command", command, component=component, value=output)

    def add_runtime_evidence(
        self, check: str, result: str, component: str | None = None
    ) -> Evidence:
        return self.add("runtime", check, component=component, value=result)

    def add_static_analysis_evidence(
        self, source: str, attribute: str, value: str
    ) -> Evidence:
        return self.add("static-analysis", source, attribute=attribute, value=value)

    def add_network_evidence(
        self, source: str, attribute: str, value: str
    ) -> Evidence:
        return self.add("network", source, attribute=attribute, value=value)

    def add_configuration_evidence(
        self, source: str, attribute: str, value: str
    ) -> Evidence:
        return self.add("configuration", source, attribute=attribute, value=value)

    def get_all(self) -> list[Evidence]:
        return list(self._evidence)

    def clear(self) -> None:
        self._evidence.clear()

    def _redact_value(self, value: str) -> str:
        """Redact sensitive information from evidence values."""
        if not self._redact_secrets:
            return value

        patterns = [
            (r"(AKIA[0-9A-Z]{16})", "AKIA************"),
            (r"(sk_live_[a-zA-Z0-9]{16})", "sk_live_************"),
            (r"(sk_test_[a-zA-Z0-9]{16})", "sk_test_************"),
            (r"(ghp_[a-zA-Z0-9]{36})", "ghp_************************************"),
            (r"(glpat-[a-zA-Z0-9\-]{20})", "glpat-*******************"),
            (r"(xox[bpoa]-[a-zA-Z0-9\-]+)", "xox***************"),
            (r"(eyJ[a-zA-Z0-9_-]{30,}\.[a-zA-Z0-9_-]{30,}\.[a-zA-Z0-9_-]{30,})", "eyJ***REDACTED***"),
            (r"(-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)", "-----BEGIN REDACTED KEY-----"),
            (r"(password\s*[:=]\s*\S{8,})", "password=********"),
            (r"(secret\s*[:=]\s*\S{8,})", "secret=********"),
            (r"(token\s*[:=]\s*\S{8,})", "token=********"),
        ]
        result = value
        for pattern, replacement in patterns:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        return result


class EvidenceSanitizer:
    """Sanitizes evidence for safe inclusion in reports."""

    SENSITIVE_PATTERNS = [
        re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+", re.IGNORECASE),
        re.compile(r"(?i)(secret|token|key)\s*[=:]\s*\S+", re.IGNORECASE),
        re.compile(r"(?i)(api_?key)\s*[=:]\s*\S+", re.IGNORECASE),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"sk_live_[a-zA-Z0-9]+"),
        re.compile(r"-----BEGIN.*PRIVATE KEY-----"),
    ]

    @classmethod
    def sanitize(cls, evidence: Evidence, show_sensitive: bool = False) -> Evidence:
        """Sanitize evidence for reporting."""
        if show_sensitive:
            return evidence
        if evidence.value:
            sanitized_value = evidence.value
            for pattern in cls.SENSITIVE_PATTERNS:
                sanitized_value = pattern.sub("REDACTED", sanitized_value)
            return Evidence(
                type=evidence.type,
                source=evidence.source,
                component=evidence.component,
                attribute=evidence.attribute,
                value=sanitized_value,
                timestamp=evidence.timestamp,
            )
        return evidence

    @classmethod
    def sanitize_findings(
        cls, findings: list[Any], show_sensitive: bool = False
    ) -> list[Any]:
        """Sanitize all findings' evidence."""
        for finding in findings:
            finding.evidence = [
                cls.sanitize(ev, show_sensitive) for ev in finding.evidence
            ]
        return findings
