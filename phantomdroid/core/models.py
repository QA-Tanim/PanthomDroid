"""PhantomDroid X - Core data models."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def order(self) -> int:
        return {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
        }[self.value]


class Confidence(StrEnum):
    """Detection confidence levels."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def order(self) -> int:
        return {
            "HIGH": 0,
            "MEDIUM": 1,
            "LOW": 2,
        }[self.value]


class FindingStatus(StrEnum):
    """Finding status."""
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    INFORMATIONAL = "INFORMATIONAL"
    HEURISTIC = "HEURISTIC"
    NOT_DETECTED = "NOT_DETECTED"
    UNKNOWN = "UNKNOWN"


class PermissionProtection(StrEnum):
    """Android permission protection levels."""
    NORMAL = "normal"
    DANGEROUS = "dangerous"
    SIGNATURE = "signature"
    SIGNATURE_OR_SYSTEM = "signatureOrSystem"
    SPECIAL = "special"
    UNKNOWN = "unknown"


class ExportedState(StrEnum):
    """Component exported state."""
    EXPORTED_TRUE = "exported_true"
    EXPORTED_FALSE = "exported_false"
    IMPLICITLY_EXPORTED = "implicitly_exported"
    UNKNOWN = "unknown"


class ComponentType(StrEnum):
    """Android component types."""
    ACTIVITY = "activity"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"


@dataclass
class Evidence:
    """Evidence supporting a finding."""
    type: str  # manifest, file, command, log, runtime, network, static-analysis, configuration
    source: str  # File path, command, or source identifier
    component: str | None = None
    attribute: str | None = None
    value: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "source": self.source,
            "component": self.component,
            "attribute": self.attribute,
            "value": self.value,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Finding:
    """A security finding with evidence."""
    id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    cwe: str | None = None
    owasp_masvs: str | None = None
    owasp_mobile_top10: str | None = None
    description: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    affected_component: str | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    scanner_version: str = "3.0.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "status": self.status.value,
            "cwe": self.cwe,
            "owasp_masvs": self.owasp_masvs,
            "owasp_mobile_top10": self.owasp_mobile_top10,
            "description": self.description,
            "evidence": [e.to_dict() for e in self.evidence],
            "affected_component": self.affected_component,
            "remediation": self.remediation,
            "references": self.references,
            "timestamp": self.timestamp.isoformat(),
            "scanner_version": self.scanner_version,
        }

    @property
    def has_cve(self) -> bool:
        return self.cwe is not None and "CVE" in (self.cwe or "")


@dataclass
class ManifestInfo:
    """Parsed Android manifest information."""
    package_name: str = ""
    version_name: str = ""
    version_code: int = 0
    min_sdk: int = 0
    target_sdk: int = 0
    debuggable: bool = False
    allow_backup: bool = True
    network_security_config: str | None = None
    permissions: list[str] = field(default_factory=list)
    features: list[str] = field(default_factory=list)
    queries: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "network_security_config": self.network_security_config,
            "permissions": self.permissions,
            "features": self.features,
            "queries": self.queries,
        }


@dataclass
class ComponentInfo:
    """Android component information."""
    name: str
    component_type: ComponentType
    exported: ExportedState = ExportedState.UNKNOWN
    permission: str | None = None
    intent_filters: list[dict[str, Any]] = field(default_factory=list)
    task_affinity: str | None = None
    launch_mode: str | None = None
    enabled: bool = True
    exported_explicit: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "component_type": self.component_type.value,
            "exported": self.exported.value,
            "permission": self.permission,
            "intent_filters": self.intent_filters,
            "task_affinity": self.task_affinity,
            "launch_mode": self.launch_mode,
            "enabled": self.enabled,
            "exported_explicit": self.exported_explicit,
        }


@dataclass
class PermissionInfo:
    """Android permission information."""
    name: str
    protection_level: PermissionProtection = PermissionProtection.UNKNOWN
    max_sdk: int | None = None
    requested: bool = True
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "protection_level": self.protection_level.value,
            "max_sdk": self.max_sdk,
            "requested": self.requested,
            "reason": self.reason,
        }


@dataclass
class DeviceInfo:
    """Android device information."""
    serial: str = ""
    model: str = ""
    brand: str = ""
    android_version: str = ""
    sdk_level: int = 0
    security_patch: str = ""
    build_id: str = ""
    fingerprint: str = ""
    state: str = ""
    is_emulator: bool = False
    is_rooted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "model": self.model,
            "brand": self.brand,
            "android_version": self.android_version,
            "sdk_level": self.sdk_level,
            "security_patch": self.security_patch,
            "build_id": self.build_id,
            "fingerprint": self.fingerprint,
            "state": self.state,
            "is_emulator": self.is_emulator,
            "is_rooted": self.is_rooted,
        }


@dataclass
class ScanResult:
    """Complete scan result."""
    target: str
    scan_type: str
    findings: list[Finding] = field(default_factory=list)
    manifest: ManifestInfo | None = None
    components: list[ComponentInfo] = field(default_factory=list)
    permissions: list[PermissionInfo] = field(default_factory=list)
    device: DeviceInfo | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            sev = f.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @property
    def confidence_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            conf = f.confidence.value
            counts[conf] = counts.get(conf, 0) + 1
        return counts

    @property
    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: f.severity.order).severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "findings": [f.to_dict() for f in self.findings],
            "manifest": self.manifest.to_dict() if self.manifest else None,
            "components": [c.to_dict() for c in self.components],
            "permissions": [p.to_dict() for p in self.permissions],
            "device": self.device.to_dict() if self.device else None,
            "metadata": self.metadata,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "errors": self.errors,
            "warnings": self.warnings,
            "summary": {
                "total_findings": self.finding_count,
                "severity_counts": self.severity_counts,
                "confidence_counts": self.confidence_counts,
            },
        }

    @staticmethod
    def compute_sha256(file_path: str) -> str:
        """Compute SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
