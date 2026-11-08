"""Tests for manifest parsing."""

from __future__ import annotations

from phantomdroid.android.manifest import (
    parse_components,
    parse_manifest_fallback,
)


class TestManifestFallback:
    def test_parse_basic(self, sample_manifest_xml: bytes):
        text = sample_manifest_xml.decode("utf-8")
        info = parse_manifest_fallback(text)
        assert info.package_name == "com.example.app"
        assert info.min_sdk == 24
        assert info.target_sdk == 34
        assert info.debuggable is False
        assert info.allow_backup is False

    def test_parse_debuggable(self):
        text = '<manifest package="com.test"><application android:debuggable="true"/></manifest>'
        info = parse_manifest_fallback(text)
        assert info.debuggable is True

    def test_parse_permissions(self):
        text = """<manifest package="com.test">
        <uses-permission android:name="android.permission.INTERNET"/>
        <uses-permission android:name="android.permission.CAMERA"/>
        </manifest>"""
        info = parse_manifest_fallback(text)
        assert "android.permission.INTERNET" in info.permissions
        assert "android.permission.CAMERA" in info.permissions


class TestParseComponents:
    def test_parse_exported_activity(self):
        xml = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test">
<application>
    <activity android:name=".Main" android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
        </intent-filter>
    </activity>
</application>
</manifest>"""
        components = parse_components(xml)
        assert len(components) >= 1
        main = components[0]
        assert main.name == ".Main"
        assert main.exported.value == "exported_true"

    def test_parse_unexported(self):
        xml = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test">
<application>
    <activity android:name=".Hidden" android:exported="false"/>
</application>
</manifest>"""
        components = parse_components(xml)
        assert len(components) >= 1
        hidden = components[0]
        assert hidden.exported.value == "exported_false"
