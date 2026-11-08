"""Tests for permission analyzer."""

from __future__ import annotations

from phantomdroid.analyzers.apk.permissions import (
    analyze_permissions,
    classify_permission,
    get_permission_description,
)
from phantomdroid.core.models import PermissionProtection, Severity


class TestClassifyPermission:
    def test_dangerous(self):
        assert classify_permission("android.permission.CAMERA") == PermissionProtection.DANGEROUS
        assert classify_permission("android.permission.READ_SMS") == PermissionProtection.DANGEROUS

    def test_normal(self):
        assert classify_permission("android.permission.INTERNET") == PermissionProtection.NORMAL
        assert classify_permission("android.permission.BLUETOOTH") == PermissionProtection.NORMAL

    def test_signature(self):
        assert classify_permission("android.permission.INSTALL_PACKAGES") == PermissionProtection.SIGNATURE

    def test_unknown(self):
        assert classify_permission("com.custom.PERMISSION") == PermissionProtection.UNKNOWN


class TestGetPermissionDescription:
    def test_known(self):
        desc = get_permission_description("android.permission.CAMERA")
        assert "camera" in desc.lower() or "picture" in desc.lower()

    def test_unknown(self):
        desc = get_permission_description("com.unknown.PERMISSION")
        assert isinstance(desc, str)


class TestAnalyzePermissions:
    def test_dangerous_permissions(self):
        perms = ["android.permission.CAMERA", "android.permission.READ_SMS"]
        perm_infos, findings = analyze_permissions(perms)
        assert len(perm_infos) == 2
        assert all(p.protection_level == PermissionProtection.DANGEROUS for p in perm_infos)
        assert len(findings) >= 2

    def test_normal_permissions(self):
        perms = ["android.permission.INTERNET", "android.permission.BLUETOOTH"]
        perm_infos, findings = analyze_permissions(perms)
        assert len(perm_infos) == 2
        # Normal permissions should not generate findings
        dangerous_findings = [f for f in findings if f.severity != Severity.INFO]
        assert len(dangerous_findings) == 0

    def test_risky_combination(self):
        perms = [
            "android.permission.READ_SMS",
            "android.permission.INTERNET",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
        ]
        _, findings = analyze_permissions(perms)
        combo_findings = [f for f in findings if "combination" in f.title.lower()]
        assert len(combo_findings) >= 1

    def test_empty(self):
        perm_infos, findings = analyze_permissions([])
        assert len(perm_infos) == 0
        assert len(findings) == 0
