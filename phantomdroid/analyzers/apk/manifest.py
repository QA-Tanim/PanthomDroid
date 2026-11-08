"""PhantomDroid X - APK manifest analyzer."""

from __future__ import annotations

from phantomdroid.core.models import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    ManifestInfo,
    Severity,
)
from phantomdroid.core.scanner import ScanContext, SecurityCheck


def analyze_manifest(manifest: ManifestInfo) -> list[Finding]:
    """Analyze manifest for security issues.

    Args:
        manifest: Parsed manifest information.

    Returns:
        List of findings.
    """
    findings: list[Finding] = []

    # Debuggable flag
    if manifest.debuggable:
        findings.append(Finding(
            id="PD-MANIFEST-DEBUGGABLE",
            title="Application is Debuggable",
            category="Manifest Security",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            cwe="CWE-489",
            description=(
                "The application has android:debuggable=true set in the "
                "manifest. This allows attackers to attach a debugger, "
                "inspect memory, and extract sensitive data from the "
                "running application."
            ),
            evidence=[
                Evidence(
                    type="manifest",
                    source="AndroidManifest.xml",
                    attribute="android:debuggable",
                    value="true",
                )
            ],
            remediation=(
                "Set android:debuggable=false in the AndroidManifest.xml "
                "for release builds. Ensure ProGuard/R8 is enabled."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/489.html",
            ],
        ))

    # Backup configuration
    if manifest.allow_backup:
        findings.append(Finding(
            id="PD-MANIFEST-BACKUP",
            title="Application Backup Enabled",
            category="Manifest Security",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            status=FindingStatus.POTENTIAL,
            cwe="CWE-921",
            description=(
                "The application has android:allowBackup=true (or default). "
                "This allows full application data extraction via "
                "'adb backup' on devices with USB debugging enabled."
            ),
            evidence=[
                Evidence(
                    type="manifest",
                    source="AndroidManifest.xml",
                    attribute="android:allowBackup",
                    value="true",
                )
            ],
            remediation=(
                "Set android:allowBackup=false in the AndroidManifest.xml. "
                "If backup is needed, implement android:fullBackupContent "
                "and android:dataExtractionRules to control what is backed up."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/921.html",
            ],
        ))

    # Low target SDK
    if manifest.target_sdk > 0 and manifest.target_sdk < 28:
        findings.append(Finding(
            id="PD-MANIFEST-LOWSDK",
            title="Low Target SDK Version",
            category="Manifest Security",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            description=(
                f"The application targets SDK {manifest.target_sdk} (Android "
                f"{_sdk_to_android(manifest.target_sdk)}). Older target SDK "
                f"versions lack modern security protections and may be "
                f"vulnerable to known attacks."
            ),
            evidence=[
                Evidence(
                    type="manifest",
                    source="AndroidManifest.xml",
                    attribute="android:targetSdkVersion",
                    value=str(manifest.target_sdk),
                )
            ],
            remediation=(
                "Update targetSdkVersion to the latest stable API level. "
                "Test thoroughly after updating."
            ),
        ))

    # Very old min SDK
    if manifest.min_sdk > 0 and manifest.min_sdk < 21:
        findings.append(Finding(
            id="PD-MANIFEST-VERYOLD",
            title="Very Low Minimum SDK Version",
            category="Manifest Security",
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            status=FindingStatus.INFORMATIONAL,
            description=(
                f"The application supports API level {manifest.min_sdk} "
                f"(Android {_sdk_to_android(manifest.min_sdk)}). Older devices "
                f"may lack important security patches."
            ),
            evidence=[
                Evidence(
                    type="manifest",
                    source="AndroidManifest.xml",
                    attribute="android:minSdkVersion",
                    value=str(manifest.min_sdk),
                )
            ],
            remediation=(
                "Consider raising minSdkVersion to 24 (Android 7.0) or higher "
                "to benefit from modern security features."
            ),
        ))

    return findings


def _sdk_to_android(sdk: int) -> str:
    """Convert SDK level to Android version string."""
    sdk_map = {
        21: "5.0", 22: "5.1", 23: "6.0", 24: "7.0", 25: "7.1",
        26: "8.0", 27: "8.1", 28: "9", 29: "10", 30: "11",
        31: "12", 32: "12L", 33: "13", 34: "14", 35: "15",
    }
    return sdk_map.get(sdk, f"API {sdk}")


class ManifestAnalyzerCheck(SecurityCheck):
    """Security check for manifest analysis."""

    id = "PD-MANIFEST-001"
    name = "Manifest Security Analysis"
    category = "apk"
    description = "Analyze AndroidManifest.xml for security misconfigurations"

    def run(self, context: ScanContext) -> list[Finding]:
        manifest = ManifestInfo(**context.manifest_data) if context.manifest_data else ManifestInfo()
        return analyze_manifest(manifest)

    def can_run(self, context: ScanContext) -> bool:
        return context.scan_type == "apk" and bool(context.manifest_data)
