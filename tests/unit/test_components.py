"""Tests for component analyzer."""

from __future__ import annotations

from phantomdroid.analyzers.apk.components import (
    analyze_component_configuration,
    analyze_exported_components,
)
from phantomdroid.core.models import (
    ComponentInfo,
    ComponentType,
    ExportedState,
    Severity,
)


class TestExportedComponents:
    def test_unprotected_exported_activity(self):
        comp = ComponentInfo(
            name=".MainActivity",
            component_type=ComponentType.ACTIVITY,
            exported=ExportedState.EXPORTED_TRUE,
        )
        findings = analyze_exported_components([comp])
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_unprotected_exported_provider(self):
        comp = ComponentInfo(
            name=".MyProvider",
            component_type=ComponentType.PROVIDER,
            exported=ExportedState.EXPORTED_TRUE,
        )
        findings = analyze_exported_components([comp])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_protected_exported(self):
        comp = ComponentInfo(
            name=".MyService",
            component_type=ComponentType.SERVICE,
            exported=ExportedState.EXPORTED_TRUE,
            permission="com.example.SECURE",
        )
        findings = analyze_exported_components([comp])
        # Protected exported components get INFO finding
        info_findings = [f for f in findings if f.severity == Severity.INFO]
        assert len(info_findings) == 1

    def test_unexported(self):
        comp = ComponentInfo(
            name=".Hidden",
            component_type=ComponentType.ACTIVITY,
            exported=ExportedState.EXPORTED_FALSE,
        )
        findings = analyze_exported_components([comp])
        assert len(findings) == 0

    def test_mixed(self):
        components = [
            ComponentInfo(name=".A", component_type=ComponentType.ACTIVITY, exported=ExportedState.EXPORTED_TRUE),
            ComponentInfo(name=".B", component_type=ComponentType.SERVICE, exported=ExportedState.EXPORTED_FALSE),
            ComponentInfo(name=".C", component_type=ComponentType.PROVIDER, exported=ExportedState.EXPORTED_TRUE),
        ]
        findings = analyze_exported_components(components)
        assert len(findings) == 2  # A and C are exported


class TestComponentConfiguration:
    def test_task_affinity(self):
        comp = ComponentInfo(
            name=".MainActivity",
            component_type=ComponentType.ACTIVITY,
            exported=ExportedState.EXPORTED_TRUE,
            task_affinity="com.evil.other",
        )
        findings = analyze_component_configuration(comp)
        task_findings = [f for f in findings if "affinity" in f.title.lower()]
        assert len(task_findings) == 1
        assert task_findings[0].severity == Severity.MEDIUM
