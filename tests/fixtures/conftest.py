"""PhantomDroid X - Test fixtures and helpers."""

from __future__ import annotations

import tempfile
import zipfile
from collections.abc import Generator
from pathlib import Path

import pytest


@pytest.fixture
def tmp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def sample_apk(tmp_dir: Path) -> Path:
    """Create a minimal sample APK (ZIP) for testing."""
    apk_path = tmp_dir / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        # Minimal AndroidManifest.xml (plain XML for testing)
        manifest = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.testapp"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <application
        android:debuggable="true"
        android:allowBackup="true"
        android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service android:name=".MyService" android:exported="true" />
        <receiver android:name=".MyReceiver" android:exported="false" />
        <provider android:name=".MyProvider" android:exported="true"
            android:authorities="com.example.testapp.provider" />
    </application>
</manifest>"""
        zf.writestr("AndroidManifest.xml", manifest)

        # Add a DEX file with some patterns
        dex_content = b"some binary content with java.util.Random and MD5"
        zf.writestr("classes.dex", dex_content)

        # Add a properties file with a secret
        zf.writestr("assets/config.properties", "api_key=AKIA1234567890ABCDEF\npassword=supersecret123")

        # Add a network security config
        zf.writestr("res/xml/network_security_config.xml", """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>""")

    return apk_path


@pytest.fixture
def sample_apk_with_secrets(tmp_dir: Path) -> Path:
    """Create an APK with hardcoded secrets for testing."""
    apk_path = tmp_dir / "secrets.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b'<manifest package="com.secrets.test"><application/></manifest>')
        zf.writestr("assets/api_config.json", '{"api_key": "AKIAIOSFODNN7EXAMPLE", "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}')
        zf.writestr("assets/strings.xml", 'access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U')
    return apk_path


@pytest.fixture
def sample_manifest_xml() -> bytes:
    """Sample AndroidManifest.xml as plain XML bytes."""
    return b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app"
    android:versionCode="2"
    android:versionName="2.0">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <application
        android:debuggable="false"
        android:allowBackup="false">
        <activity android:name=".Home" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
            </intent-filter>
        </activity>
    </application>
</manifest>"""
