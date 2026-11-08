"""PhantomDroid X - Insecure storage analyzer."""

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


def analyze_storage(
    adb: ADB,
    device_id: str,
    package: str,
) -> list[Finding]:
    """Analyze application storage for security issues.

    Args:
        adb: ADB instance.
        device_id: Device serial.
        package: Target package name.

    Returns:
        List of findings.
    """
    findings: list[Finding] = []
    base = f"/data/data/{package}"

    # Check SharedPreferences
    prefs_out = adb.shell(
        f"ls {base}/shared_prefs/ 2>/dev/null", device_id
    )
    if prefs_out and "No such" not in prefs_out:
        # Check for sensitive data in SharedPreferences
        prefs_files = [
            f.strip() for f in prefs_out.splitlines()
            if f.strip().endswith(".xml")
        ]
        for pref_file in prefs_files[:10]:  # Limit to 10 files
            content = adb.shell(
                f"cat '{base}/shared_prefs/{pref_file}' 2>/dev/null",
                device_id,
            )
            if _contains_sensitive_data(content):
                findings.append(Finding(
                    id=f"PD-STORAGE-PREFS-{pref_file[:20]}",
                    title="Sensitive Data in SharedPreferences",
                    category="Insecure Storage",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    status=FindingStatus.POTENTIAL,
                    cwe="CWE-312",
                    description=(
                        f"Potential sensitive data found in SharedPreferences "
                        f"file: {pref_file}. SharedPreferences files are stored "
                        f"in XML format and may be readable on rooted devices "
                        f"or via adb backup."
                    ),
                    evidence=[
                        Evidence(
                            type="runtime",
                            source=f"{base}/shared_prefs/{pref_file}",
                            attribute="content",
                            value="Sensitive data detected",
                        )
                    ],
                    remediation=(
                        "Use EncryptedSharedPreferences or Android Keystore "
                        "for storing sensitive data. Do not store credentials "
                        "in plain SharedPreferences."
                    ),
                    references=[
                        "https://cwe.mitre.org/data/definitions/312.html",
                    ],
                ))

    # Check for world-readable/writable files
    files_out = adb.shell(f"find {base} -type f -perm /o+rw 2>/dev/null", device_id)
    if files_out and "No such" not in files_out:
        world_files = [f.strip() for f in files_out.splitlines() if f.strip()]
        if world_files:
            findings.append(Finding(
                id="PD-STORAGE-WORLDACCESS",
                title="World-Accessible Files",
                category="Insecure Storage",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                cwe="CWE-732",
                description=(
                    f"{len(world_files)} file(s) with world-readable or "
                    f"world-writable permissions found in app data directory. "
                    f"These files can be read or modified by any app on the device."
                ),
                evidence=[
                    Evidence(
                        type="runtime",
                        source=base,
                        attribute="world_readable_files",
                        value=f,
                    )
                    for f in world_files[:5]
                ],
                remediation=(
                    "Ensure app files have appropriate permissions (MODE_PRIVATE). "
                    "Use file-level encryption for sensitive data."
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/732.html",
                ],
            ))

    # Check for database files
    db_out = adb.shell(f"ls {base}/databases/ 2>/dev/null", device_id)
    if db_out and "No such" not in db_out:
        db_files = [f.strip() for f in db_out.splitlines() if f.strip()]
        if db_files:
            findings.append(Finding(
                id="PD-STORAGE-DATABASES",
                title="SQLite Databases Found",
                category="Insecure Storage",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                description=(
                    f"{len(db_files)} SQLite database(s) found in app data. "
                    f"Verify that databases do not contain unencrypted "
                    f"sensitive data."
                ),
                evidence=[
                    Evidence(
                        type="runtime",
                        source=f"{base}/databases/",
                        attribute="database_files",
                        value=db,
                    )
                    for db in db_files[:5]
                ],
                remediation=(
                    "Use SQLCipher or Android's built-in encryption for "
                    "databases containing sensitive data."
                ),
            ))

    return findings


def _contains_sensitive_data(content: str) -> bool:
    """Check if content contains potential sensitive data."""
    if not content:
        return False
    patterns = [
        "password", "token", "secret", "api_key", "apikey",
        "access_token", "auth_token", "credential", "private_key",
    ]
    content_lower = content.lower()
    return any(p in content_lower for p in patterns)


class InsecureStorageCheck(SecurityCheck):
    """Security check for insecure storage."""

    id = "PD-STORAGE-001"
    name = "Insecure Storage Analysis"
    category = "runtime"
    description = "Analyze application storage for insecure data handling"

    def run(self, context: ScanContext) -> list[Finding]:
        if not context.device_serial or not context.package_name:
            return []
        adb = ADB()
        return analyze_storage(adb, context.device_serial, context.package_name)

    def can_run(self, context: ScanContext) -> bool:
        return (
            context.scan_type in ("runtime", "device")
            and context.device_serial is not None
            and context.package_name is not None
        )
