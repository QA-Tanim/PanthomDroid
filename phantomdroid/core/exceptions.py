"""PhantomDroid X - Core exceptions."""

from __future__ import annotations


class PhantomDroidError(Exception):
    """Base exception for PhantomDroid X."""

    def __init__(self, message: str = "", details: dict | None = None) -> None:
        super().__init__(message)
        self.details = details or {}


class ADBError(PhantomDroidError):
    """ADB operation failed."""


class ADBNotFoundError(ADBError):
    """ADB binary not found."""


class ADBDeviceNotFoundError(ADBError):
    """No device connected or specified device not found."""


class ADBCommandError(ADBError):
    """ADB command execution failed."""

    def __init__(self, message: str = "", returncode: int = -1, stderr: str = "") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


class APKError(PhantomDroidError):
    """APK analysis error."""


class ManifestParseError(APKError):
    """Failed to parse AndroidManifest.xml."""


class SecretScanError(APKError):
    """Secret scanning error."""


class ScanError(PhantomDroidError):
    """Scan engine error."""


class ReportError(PhantomDroidError):
    """Report generation error."""


class ConfigError(PhantomDroidError):
    """Configuration error."""


class ValidationError(PhantomDroidError):
    """Input validation error."""
