"""PhantomDroid X - Scanner base class and plugin architecture."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from phantomdroid.core.models import Finding, ScanResult


@dataclass
class ScanContext:
    """Context passed to security checks during scanning."""
    target: str
    scan_type: str  # apk, device, runtime, network
    apk_path: str | None = None
    device_serial: str | None = None
    package_name: str | None = None
    config: Any = None
    manifest_data: dict[str, Any] = field(default_factory=dict)
    components: list[Any] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class SecurityCheck(ABC):
    """Base class for security checks (plugin architecture)."""

    id: str = ""
    name: str = ""
    category: str = ""
    description: str = ""

    @abstractmethod
    def run(self, context: ScanContext) -> list[Finding]:
        """Run the security check and return findings."""
        ...

    def can_run(self, context: ScanContext) -> bool:
        """Check if this check can run given the context."""
        return True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self.id!r} name={self.name!r}>"


class ScannerEngine:
    """Orchestrates security checks and collects findings."""

    def __init__(self) -> None:
        self._checks: list[SecurityCheck] = []
        self._results: ScanResult | None = None

    def register(self, check: SecurityCheck) -> None:
        """Register a security check."""
        self._checks.append(check)

    def register_many(self, checks: list[SecurityCheck]) -> None:
        """Register multiple security checks."""
        self._checks.extend(checks)

    def get_checks(self, category: str | None = None) -> list[SecurityCheck]:
        """Get registered checks, optionally filtered by category."""
        if category:
            return [c for c in self._checks if c.category == category]
        return list(self._checks)

    def run(
        self,
        context: ScanContext,
        categories: list[str] | None = None,
        on_progress: Any = None,
    ) -> ScanResult:
        """Run all applicable security checks."""
        result = ScanResult(
            target=context.target,
            scan_type=context.scan_type,
            metadata=context.metadata,
        )

        checks_to_run = self._checks
        if categories:
            checks_to_run = [c for c in self._checks if c.category in categories]

        total = len(checks_to_run)
        for i, check in enumerate(checks_to_run):
            if not check.can_run(context):
                result.warnings.append(f"Skipped {check.name} - not applicable")
                continue

            try:
                findings = check.run(context)
                result.findings.extend(findings)
            except Exception as e:
                result.errors.append(f"Check {check.name} failed: {e}")

            if on_progress:
                on_progress(i + 1, total, check.name)

        return result

    @property
    def check_count(self) -> int:
        return len(self._checks)

    @property
    def categories(self) -> list[str]:
        return list({c.category for c in self._checks})
