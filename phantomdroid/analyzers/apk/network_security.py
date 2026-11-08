"""PhantomDroid X - Network security configuration analyzer."""

from __future__ import annotations

from typing import Any

from phantomdroid.core.models import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    ManifestInfo,
    Severity,
)
from phantomdroid.core.scanner import ScanContext, SecurityCheck


def analyze_network_security(
    manifest: ManifestInfo,
    network_security_config: dict[str, Any] | None = None,
    urls: list[str] | None = None,
) -> list[Finding]:
    """Analyze network security configuration.

    Args:
        manifest: Parsed manifest information.
        network_security_config: Parsed network security config (if available).
        urls: List of URLs found in the APK.

    Returns:
        List of findings.
    """
    findings: list[Finding] = []

    # Check for cleartext traffic policy
    if network_security_config:
        cleartext = network_security_config.get("cleartextTrafficPermitted", None)
        if cleartext is True:
            findings.append(Finding(
                id="PD-NET-_CLEARTEXT",
                title="Cleartext Traffic Permitted",
                category="Network Security",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                cwe="CWE-319",
                description=(
                    "The network security configuration explicitly permits "
                    "cleartext (HTTP) traffic. This exposes data in transit "
                    "to interception and modification attacks."
                ),
                evidence=[
                    Evidence(
                        type="configuration",
                        source="network_security_config.xml",
                        attribute="cleartextTrafficPermitted",
                        value="true",
                    )
                ],
                remediation=(
                    "Set android:cleartextTrafficPermitted=\"false\" in the "
                    "network security configuration. Use HTTPS for all communications."
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/319.html",
                ],
            ))
    else:
        # No network security config defined
        # Only flag if targetSdk >= 28 (where cleartext is blocked by default)
        if manifest.target_sdk >= 28:
            findings.append(Finding(
                id="PD-NET-NOCONFIG",
                title="No Network Security Configuration",
                category="Network Security",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                status=FindingStatus.HEURISTIC,
                description=(
                    f"The application (targetSdk={manifest.target_sdk}) does not "
                    f"define a network_security_config.xml. While cleartext is "
                    f"blocked by default on API 28+, defining an explicit "
                    f"configuration is recommended for defense in depth."
                ),
                evidence=[
                    Evidence(
                        type="manifest",
                        source="AndroidManifest.xml",
                        attribute="android:networkSecurityConfig",
                        value="not defined",
                    )
                ],
                remediation=(
                    "Create a network_security_config.xml that explicitly "
                    "disables cleartext traffic and defines trust anchors."
                ),
                references=[
                    "https://developer.android.com/training/articles/security-config",
                ],
            ))
        elif manifest.target_sdk > 0:
            # targetSdk < 28 - informational
            findings.append(Finding(
                id="PD-NET-OLDSK",
                title="Low Target SDK - Cleartext Allowed by Default",
                category="Network Security",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.INFORMATIONAL,
                description=(
                    f"The application targets SDK {manifest.target_sdk} (< 28). "
                    f"Cleartext HTTP traffic is allowed by default on older "
                    f"SDK levels. Consider updating targetSdkVersion and "
                    f"adding a network security configuration."
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
                    "Update targetSdkVersion to 28 or higher and add a "
                    "network_security_config.xml."
                ),
            ))

    # Check for debug/trust-anchors in NSC
    if network_security_config:
        trust_anchors = network_security_config.get("trustAnchors", [])
        for anchor in trust_anchors:
            if anchor.get("includeUserCerts", False):
                findings.append(Finding(
                    id="PD-NET-USERCERTS",
                    title="User Certificates Trusted",
                    category="Network Security",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    cwe="CWE-295",
                    description=(
                        "The network security configuration trusts user-installed "
                        "certificates. This allows MitM attacks if a malicious "
                        "certificate is installed on the device."
                    ),
                    evidence=[
                        Evidence(
                            type="configuration",
                            source="network_security_config.xml",
                            attribute="trustAnchors",
                            value="includeUserCerts=true",
                        )
                    ],
                    remediation=(
                        "Remove trust for user-installed certificates in "
                        "production builds. Only trust system certificates."
                    ),
                    references=[
                        "https://cwe.mitre.org/data/definitions/295.html",
                    ],
                ))
            if anchor.get("includeDebugCerts", False):
                findings.append(Finding(
                    id="PD-NET-DEBUGCERTS",
                    title="Debug Certificates Trusted",
                    category="Network Security",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    cwe="CWE-295",
                    description=(
                        "The network security configuration trusts debug "
                        "certificates. This should not be enabled in production."
                    ),
                    evidence=[
                        Evidence(
                            type="configuration",
                            source="network_security_config.xml",
                            attribute="trustAnchors",
                            value="includeDebugCerts=true",
                        )
                    ],
                    remediation="Remove debug certificate trust from production builds.",
                ))

    # Analyze URLs for HTTP endpoints
    if urls:
        http_urls = [u for u in urls if u.startswith("http://") and not u.startswith("http://localhost")]
        if http_urls:
            findings.append(Finding(
                id="PD-NET-HTTPURLS",
                title="HTTP URLs Found in APK",
                category="Network Security",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.POTENTIAL,
                description=(
                    f"{len(http_urls)} HTTP (non-HTTPS) URL(s) were found in the "
                    f"APK. These endpoints may transmit data in cleartext."
                ),
                evidence=[
                    Evidence(
                        type="static-analysis",
                        source="APK contents",
                        attribute="http_urls",
                        value=u,
                    )
                    for u in http_urls[:5]
                ],
                remediation=(
                    "Use HTTPS for all network communications. "
                    "Update any hardcoded HTTP URLs to HTTPS."
                ),
            ))

    return findings


class NetworkSecurityCheck(SecurityCheck):
    """Security check for network security configuration."""

    id = "PD-NET-001"
    name = "Network Security Analysis"
    category = "apk"
    description = "Analyze network security configuration and cleartext traffic policies"

    def run(self, context: ScanContext) -> list[Finding]:
        manifest = ManifestInfo(**context.manifest_data) if context.manifest_data else ManifestInfo()
        nsc = context.metadata.get("network_security_config")
        urls = context.metadata.get("urls", [])
        return analyze_network_security(manifest, nsc, urls)

    def can_run(self, context: ScanContext) -> bool:
        return context.scan_type == "apk"
