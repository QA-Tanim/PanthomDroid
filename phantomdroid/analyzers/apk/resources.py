"""PhantomDroid X - APK resource analysis."""

from __future__ import annotations

from phantomdroid.core.models import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
)
from phantomdroid.core.scanner import ScanContext, SecurityCheck


def analyze_resources(
    file_contents: dict[str, str],
    native_libs: list[str],
) -> list[Finding]:
    """Analyze APK resources for security issues.

    Args:
        file_contents: Dictionary of file_path -> content.
        native_libs: List of native library paths.

    Returns:
        List of findings.
    """
    findings: list[Finding] = []

    # Check for native libraries
    if native_libs:
        findings.append(Finding(
            id="PD-RES-NATIVE",
            title="Native Libraries Detected",
            category="Resource Analysis",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            status=FindingStatus.INFORMATIONAL,
            description=(
                f"{len(native_libs)} native library/libraries detected. "
                f"Native code may contain vulnerabilities that are harder "
                f"to detect through static analysis."
            ),
            evidence=[
                Evidence(
                    type="static-analysis",
                    source="APK contents",
                    attribute="native_libs",
                    value=lib,
                )
                for lib in native_libs[:5]
            ],
            remediation=(
                "Ensure native libraries are obfuscated and do not "
                "contain hardcoded secrets or vulnerable code."
            ),
        ))

    # Check for debug symbols in native libs
    for lib_path in native_libs:
        content = file_contents.get(lib_path, "")
        if ".debug" in lib_path or "_debug" in lib_path:
            findings.append(Finding(
                id=f"PD-RES-DEBUGLIB-{lib_path.split('/')[-1][:20]}",
                title="Debug Native Library Detected",
                category="Resource Analysis",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description=(
                    f"Debug native library detected: {lib_path}. "
                    f"Debug libraries may contain symbols and debug "
                    f"information that aids reverse engineering."
                ),
                evidence=[
                    Evidence(
                        type="file",
                        source=lib_path,
                        attribute="type",
                        value="debug",
                    )
                ],
                remediation="Remove debug libraries from release builds.",
            ))

    # Check for exposed web resources
    web_extensions = {".html", ".js", ".css", ".php", ".asp", ".aspx"}
    for file_path in file_contents:
        ext = "." + file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
        if ext in web_extensions and "assets/" in file_path:
            findings.append(Finding(
                id=f"PD-RES-WEB-{file_path.split('/')[-1][:20]}",
                title="Web Resource in APK",
                category="Resource Analysis",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                status=FindingStatus.HEURISTIC,
                description=(
                    f"Web resource found in APK: {file_path}. "
                    f"Web resources may contain JavaScript that executes "
                    f"in a WebView context."
                ),
                evidence=[
                    Evidence(
                        type="file",
                        source=file_path,
                        attribute="type",
                        value="web_resource",
                    )
                ],
                remediation="Review web resources for security issues.",
            ))

    # Check for SQL database files
    for file_path in file_contents:
        if file_path.endswith(".db") or file_path.endswith(".sqlite"):
            findings.append(Finding(
                id=f"PD-RES-DB-{file_path.split('/')[-1][:20]}",
                title="Database File in APK",
                category="Resource Analysis",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                description=(
                    f"Database file bundled in APK: {file_path}. "
                    f"Bundled databases may contain sensitive data and "
                    f"are easily extractable."
                ),
                evidence=[
                    Evidence(
                        type="file",
                        source=file_path,
                        attribute="type",
                        value="database",
                    )
                ],
                remediation=(
                    "Do not bundle sensitive data in APK databases. "
                    "If pre-populated data is needed, encrypt the database."
                ),
            ))

    return findings


class ResourceAnalyzerCheck(SecurityCheck):
    """Security check for resource analysis."""

    id = "PD-RES-001"
    name = "Resource Analysis"
    category = "apk"
    description = "Analyze APK resources for security issues"

    def run(self, context: ScanContext) -> list[Finding]:
        file_contents = context.metadata.get("file_contents", {})
        native_libs = context.metadata.get("native_libs", [])
        return analyze_resources(file_contents, native_libs)

    def can_run(self, context: ScanContext) -> bool:
        return context.scan_type == "apk"
