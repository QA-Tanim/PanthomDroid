"""PhantomDroid X - Configuration management."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ScanConfig:
    """Scan configuration."""
    timeout: int = 30
    max_workers: int = 10
    port_scan_timeout: float = 0.8
    enable_caching: bool = True
    cache_dir: Path = field(default_factory=lambda: Path.home() / ".phantomdroid" / "cache")
    output_dir: Path = field(default_factory=lambda: Path.cwd())
    show_sensitive: bool = False
    verbose: bool = False
    quiet: bool = False
    no_color: bool = False
    format: str = "json"
    fail_on: str | None = None
    fail_on_confidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timeout": self.timeout,
            "max_workers": self.max_workers,
            "port_scan_timeout": self.port_scan_timeout,
            "enable_caching": self.enable_caching,
            "cache_dir": str(self.cache_dir),
            "output_dir": str(self.output_dir),
            "show_sensitive": self.show_sensitive,
            "verbose": self.verbose,
            "quiet": self.quiet,
            "no_color": self.no_color,
            "format": self.format,
            "fail_on": self.fail_on,
            "fail_on_confidence": self.fail_on_confidence,
        }


@dataclass
class ADBConfig:
    """ADB configuration."""
    adb_path: str = "adb"
    timeout: int = 30
    shell_timeout: int = 60

    @classmethod
    def from_env(cls) -> ADBConfig:
        return cls(
            adb_path=os.environ.get("PHANTOMDROID_ADB_PATH", "adb"),
            timeout=int(os.environ.get("PHANTOMDROID_ADB_TIMEOUT", "30")),
            shell_timeout=int(os.environ.get("PHANTOMDROID_ADB_SHELL_TIMEOUT", "60")),
        )


@dataclass
class SecretScanConfig:
    """Secret scanning configuration."""
    enable_entropy: bool = True
    min_entropy: float = 3.0
    min_length: int = 8
    redact_secrets: bool = True
    scan_dex: bool = True
    scan_xml: bool = True
    scan_json: bool = True
    scan_properties: bool = True
    scan_js: bool = True
    scan_html: bool = True
    max_file_size: int = 50 * 1024 * 1024  # 50MB


@dataclass
class ReportingConfig:
    """Report generation configuration."""
    include_evidence: bool = True
    include_remediation: bool = True
    include_references: bool = True
    max_findings_per_report: int = 1000
    html_theme: str = "dark"
    safe_html: bool = True


@dataclass
class PhantomDroidConfig:
    """Main configuration."""
    scan: ScanConfig = field(default_factory=ScanConfig)
    adb: ADBConfig = field(default_factory=ADBConfig)
    secrets: SecretScanConfig = field(default_factory=SecretScanConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)

    @classmethod
    def from_file(cls, path: str | Path) -> PhantomDroidConfig:
        config_path = Path(path)
        if not config_path.exists():
            return cls()
        with open(config_path) as f:
            data = json.load(f)
        config = cls()
        if "scan" in data:
            for k, v in data["scan"].items():
                if hasattr(config.scan, k):
                    setattr(config.scan, k, v)
        if "adb" in data:
            for k, v in data["adb"].items():
                if hasattr(config.adb, k):
                    setattr(config.adb, k, v)
        if "secrets" in data:
            for k, v in data["secrets"].items():
                if hasattr(config.secrets, k):
                    setattr(config.secrets, k, v)
        if "reporting" in data:
            for k, v in data["reporting"].items():
                if hasattr(config.reporting, k):
                    setattr(config.reporting, k, v)
        return config

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan": self.scan.to_dict(),
            "adb": {
                "adb_path": self.adb.adb_path,
                "timeout": self.adb.timeout,
                "shell_timeout": self.adb.shell_timeout,
            },
            "secrets": {
                "enable_entropy": self.secrets.enable_entropy,
                "min_entropy": self.secrets.min_entropy,
                "min_length": self.secrets.min_length,
                "redact_secrets": self.secrets.redact_secrets,
            },
            "reporting": {
                "include_evidence": self.reporting.include_evidence,
                "include_remediation": self.reporting.include_remediation,
                "safe_html": self.reporting.safe_html,
            },
        }

    def save(self, path: str | Path) -> None:
        config_path = Path(path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
