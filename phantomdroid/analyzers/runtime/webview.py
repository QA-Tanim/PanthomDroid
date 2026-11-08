"""PhantomDroid X - WebView security analyzer."""

from __future__ import annotations

from phantomdroid.android.adb import ADB
from phantomdroid.core.models import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
)
from phantomdroid.core.scanner import ScanContext, SecurityCheck


def analyze_webview(
    adb: ADB,
    device_id: str,
    package: str,
) -> list[Finding]:
    """Analyze WebView security configuration via runtime checks.

    Args:
        adb: ADB instance.
        device_id: Device serial.
        package: Target package name.

    Returns:
        List of findings.
    """
    findings: list[Finding] = []

    # Check WebView configuration via dumpsys
    try:
        webview_info = adb.shell(
            f"dumpsys package {package} | grep -i webview",
            device_id,
        )
    except Exception:
        webview_info = ""

    # Check for WebView-related settings
    try:
        settings_out = adb.shell(
            "settings list global | grep -i webview",
            device_id,
        )
    except Exception:
        settings_out = ""

    # Note: Runtime WebView analysis is limited without app cooperation.
    # Most WebView analysis should be done via static analysis of the APK.
    # This runtime check provides supplementary information.

    if webview_info and "file://" in webview_info.lower():
        findings.append(Finding(
                id="PD-WEBVIEW-FILEACCESS",
                title="WebView File Access Detected",
                category="WebView Security",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.POTENTIAL,
                cwe="CWE-200",
                description=(
                    "WebView file access was detected in the application's "
                    "configuration. This may allow reading local files via "
                    "file:// URLs."
                ),
                evidence=[
                    Evidence(
                        type="runtime",
                        source=f"dumpsys package {package}",
                        attribute="webview",
                        value="file:// access detected",
                    )
                ],
                remediation=(
                    "Disable file access in WebView using "
                    "setAllowFileAccess(false) and "
                    "setAllowFileAccessFromFileURLs(false)."
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/200.html",
                ],
            ))

    return findings


class WebViewCheck(SecurityCheck):
    """Security check for WebView security."""

    id = "PD-WEBVIEW-001"
    name = "WebView Security Analysis"
    category = "runtime"
    description = "Analyze WebView security configuration at runtime"

    def run(self, context: ScanContext) -> list[Finding]:
        if not context.device_serial or not context.package_name:
            return []
        adb = ADB()
        return analyze_webview(adb, context.device_serial, context.package_name)

    def can_run(self, context: ScanContext) -> bool:
        return (
            context.scan_type in ("runtime", "device")
            and context.device_serial is not None
            and context.package_name is not None
        )
