"""PhantomDroid X - Exported components analyzer with context-aware detection."""

from __future__ import annotations

from phantomdroid.core.models import (
    ComponentInfo,
    Confidence,
    Evidence,
    ExportedState,
    Finding,
    FindingStatus,
    Severity,
)
from phantomdroid.core.scanner import ScanContext, SecurityCheck


def analyze_exported_components(
    components: list[ComponentInfo],
) -> list[Finding]:
    """Analyze exported components for security issues.

    Only flags components that represent actual security concerns.
    """
    findings: list[Finding] = []

    for comp in components:
        if comp.exported == ExportedState.EXPORTED_TRUE or comp.exported == ExportedState.IMPLICITLY_EXPORTED:
            # Skip if protected by a permission
            if comp.permission:
                findings.append(_create_protected_exported_finding(comp))
            else:
                findings.append(_create_unprotected_exported_finding(comp))

    return findings


def _create_unprotected_exported_finding(comp: ComponentInfo) -> Finding:
    """Create a finding for an exported component without permission protection."""
    severity_map = {
        "activity": Severity.MEDIUM,
        "service": Severity.HIGH,
        "receiver": Severity.HIGH,
        "provider": Severity.CRITICAL,
    }
    severity = severity_map.get(comp.component_type.value, Severity.MEDIUM)

    # Intent filter actions
    actions = []
    for filt in comp.intent_filters:
        actions.extend(filt.get("actions", []))

    description = (
        f"Component '{comp.name}' ({comp.component_type.value}) is exported "
        f"without a permission guard."
    )
    if actions:
        description += f" It responds to intent actions: {', '.join(actions[:5])}."

    if comp.component_type.value == "provider":
        description += (
            " Exported content providers can expose application data to "
            "other applications. Verify that the provider does not expose "
            "sensitive data and implements proper access controls."
        )
    elif comp.component_type.value == "service":
        description += (
            " Exported services can be invoked by other applications. "
            "Verify that the service does not perform sensitive operations "
            "without proper authorization."
        )
    elif comp.component_type.value == "receiver":
        description += (
            " Exported broadcast receivers can be triggered by other "
            "applications. Verify that the receiver handles untrusted "
            "input safely."
        )
    elif comp.component_type.value == "activity":
        description += (
            " Exported activities can be launched by other applications. "
            "Verify that the activity does not expose sensitive functionality."
        )

    remediation = (
        f"Add android:exported=\"false\" to the {comp.component_type.value} "
        f"if it does not need to be accessed by other applications. "
        f"If it must be exported, protect it with a custom permission."
    )

    evidence = [
        Evidence(
            type="manifest",
            source="AndroidManifest.xml",
            component=comp.name,
            attribute="android:exported",
            value="true" if comp.exported == ExportedState.EXPORTED_TRUE else "implicit",
        )
    ]
    if comp.permission:
        evidence.append(
            Evidence(
                type="manifest",
                source="AndroidManifest.xml",
                component=comp.name,
                attribute="android:permission",
                value=comp.permission,
            )
        )

    return Finding(
        id=f"PD-COMP-EXPORTED-{comp.name.split('.')[-1][:20]}",
        title=f"Exported {comp.component_type.value.title()} Without Permission",
        category="Component Security",
        severity=severity,
        confidence=Confidence.HIGH,
        status=FindingStatus.CONFIRMED,
        cwe="CWE-926",
        description=description,
        evidence=evidence,
        affected_component=comp.name,
        remediation=remediation,
        references=[
            "https://cwe.mitre.org/data/definitions/926.html",
            "https://masvs..mas.owasp.org/MASVS-STORAGE/",
        ],
    )


def _create_protected_exported_finding(comp: ComponentInfo) -> Finding:
    """Create an informational finding for exported component with permission."""
    return Finding(
        id=f"PD-COMP-PROTECTED-{comp.name.split('.')[-1][:20]}",
        title=f"Exported {comp.component_type.value.title()} With Permission",
        category="Component Security",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        status=FindingStatus.INFORMATIONAL,
        description=(
            f"Component '{comp.name}' ({comp.component_type.value}) is exported "
            f"but protected by permission '{comp.permission}'. "
            f"This reduces risk but the permission's protection level "
            f"should be verified."
        ),
        evidence=[
            Evidence(
                type="manifest",
                source="AndroidManifest.xml",
                component=comp.name,
                attribute="android:permission",
                value=comp.permission or "",
            )
        ],
        affected_component=comp.name,
        remediation=(
            "Verify that the protecting permission has SIGNATURE or "
            "SIGNATURE_OR_SYSTEM protection level."
        ),
    )


def analyze_component_configuration(comp: ComponentInfo) -> list[Finding]:
    """Analyze component configuration for additional security issues."""
    findings: list[Finding] = []

    # Task affinity (StrandHogg indicator)
    if comp.component_type.value == "activity" and comp.task_affinity and comp.task_affinity != "" and not comp.task_affinity.startswith("."):
        # Non-default task affinity could indicate task hijacking risk
        findings.append(Finding(
                id=f"PD-COMP-TASKAFF-{comp.name.split('.')[-1][:20]}",
                title="Non-Default Task Affinity",
                category="Component Security",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                status=FindingStatus.HEURISTIC,
                description=(
                    f"Activity '{comp.name}' has a non-default taskAffinity "
                    f"of '{comp.task_affinity}'. This could potentially be "
                    f"exploited for task hijacking (StrandHogg) if combined "
                    f"with other vulnerable configurations."
                ),
                evidence=[
                    Evidence(
                        type="manifest",
                        source="AndroidManifest.xml",
                        component=comp.name,
                        attribute="android:taskAffinity",
                        value=comp.task_affinity,
                    )
                ],
                affected_component=comp.name,
                remediation=(
                    "Set android:taskAffinity to an empty string or the "
                    "app's own package name. Use FLAG_ACTIVITY_NEW_DOCUMENT "
                    "for activities that should not be shared."
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/667.html",
                ],
            ))

    return findings


class ComponentAnalyzerCheck(SecurityCheck):
    """Security check for exported component analysis."""

    id = "PD-COMP-001"
    name = "Exported Component Analysis"
    category = "apk"
    description = "Analyze exported Android components for security issues"

    def run(self, context: ScanContext) -> list[Finding]:
        components = context.components
        findings = analyze_exported_components(components)

        # Also analyze component configuration
        for comp in components:
            findings.extend(analyze_component_configuration(comp))

        return findings

    def can_run(self, context: ScanContext) -> bool:
        return context.scan_type == "apk" and bool(context.components)
