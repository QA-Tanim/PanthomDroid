"""PhantomDroid X - Permission analyzer with proper classification."""

from __future__ import annotations

from phantomdroid.core.models import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    PermissionInfo,
    PermissionProtection,
    Severity,
)
from phantomdroid.core.scanner import ScanContext, SecurityCheck

# Android permission classification (API 34)
ANDROID_PERMISSIONS: dict[str, tuple[PermissionProtection, str]] = {
    # Normal permissions
    "android.permission.ACCESS_NETWORK_STATE": (PermissionProtection.NORMAL, "View network status"),
    "android.permission.ACCESS_WIFI_STATE": (PermissionProtection.NORMAL, "View WiFi status"),
    "android.permission.CHANGE_NETWORK_STATE": (PermissionProtection.NORMAL, "Change network connectivity"),
    "android.permission.CHANGE_WIFI_STATE": (PermissionProtection.NORMAL, "Change WiFi connectivity"),
    "android.permission.BLUETOOTH": (PermissionProtection.NORMAL, "Use Bluetooth"),
    "android.permission.BLUETOOTH_ADMIN": (PermissionProtection.NORMAL, "Administer Bluetooth"),
    "android.permission.BLUETOOTH_SCAN": (PermissionProtection.NORMAL, "Scan for Bluetooth devices"),
    "android.permission.BLUETOOTH_ADVERTISE": (PermissionProtection.NORMAL, "Advertise Bluetooth"),
    "android.permission.BLUETOOTH_CONNECT": (PermissionProtection.NORMAL, "Connect to Bluetooth devices"),
    "android.permission.NFC": (PermissionProtection.NORMAL, "Use NFC"),
    "android.permission.INTERNET": (PermissionProtection.NORMAL, "Full network access"),
    "android.permission.RECEIVE_BOOT_COMPLETED": (PermissionProtection.NORMAL, "Run at startup"),
    "android.permission.VIBRATE": (PermissionProtection.NORMAL, "Control vibration"),
    "android.permission.WAKE_LOCK": (PermissionProtection.NORMAL, "Prevent device from sleeping"),
    "android.permission.FOREGROUND_SERVICE": (PermissionProtection.NORMAL, "Run foreground service"),
    "android.permission.FOREGROUND_SERVICE_DATA_SYNC": (PermissionProtection.NORMAL, "Data sync foreground service"),
    "android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK": (PermissionProtection.NORMAL, "Media playback foreground service"),
    "android.permission.FOREGROUND_SERVICE_SPECIAL_USE": (PermissionProtection.NORMAL, "Special use foreground service"),
    "android.permission.USE_FULL_SCREEN_INTENT": (PermissionProtection.NORMAL, "Use full screen intents"),
    "android.permission.SCHEDULE_EXACT_ALARM": (PermissionProtection.NORMAL, "Schedule exact alarms"),
    "android.permission.POST_NOTIFICATIONS": (PermissionProtection.NORMAL, "Post notifications"),
    "android.permission.READ_MEDIA_IMAGES": (PermissionProtection.NORMAL, "Read media images"),
    "android.permission.READ_MEDIA_VIDEO": (PermissionProtection.NORMAL, "Read media video"),
    "android.permission.READ_MEDIA_AUDIO": (PermissionProtection.NORMAL, "Read media audio"),

    # Dangerous permissions
    "android.permission.READ_CONTACTS": (PermissionProtection.DANGEROUS, "Read contacts"),
    "android.permission.WRITE_CONTACTS": (PermissionProtection.DANGEROUS, "Modify contacts"),
    "android.permission.GET_ACCOUNTS": (PermissionProtection.DANGEROUS, "Find accounts on device"),
    "android.permission.READ_CALENDAR": (PermissionProtection.DANGEROUS, "Read calendar events"),
    "android.permission.WRITE_CALENDAR": (PermissionProtection.DANGEROUS, "Create calendar events"),
    "android.permission.READ_SMS": (PermissionProtection.DANGEROUS, "Read SMS messages"),
    "android.permission.RECEIVE_SMS": (PermissionProtection.DANGEROUS, "Receive SMS"),
    "android.permission.RECEIVE_MMS": (PermissionProtection.DANGEROUS, "Receive MMS"),
    "android.permission.RECEIVE_WAP_PUSH": (PermissionProtection.DANGEROUS, "Receive WAP push"),
    "android.permission.SEND_SMS": (PermissionProtection.DANGEROUS, "Send SMS"),
    "android.permission.READ_PHONE_STATE": (PermissionProtection.DANGEROUS, "Read phone state"),
    "android.permission.READ_PHONE_NUMBERS": (PermissionProtection.DANGEROUS, "Read phone numbers"),
    "android.permission.CALL_PHONE": (PermissionProtection.DANGEROUS, "Make phone calls"),
    "android.permission.ANSWER_PHONE_CALLS": (PermissionProtection.DANGEROUS, "Answer phone calls"),
    "android.permission.ADD_VOICEMAIL": (PermissionProtection.DANGEROUS, "Add voicemail"),
    "android.permission.USE_SIP": (PermissionProtection.DANGEROUS, "Use SIP"),
    "android.permission.READ_CALL_LOG": (PermissionProtection.DANGEROUS, "Read call log"),
    "android.permission.WRITE_CALL_LOG": (PermissionProtection.DANGEROUS, "Modify call log"),
    "android.permission.PROCESS_OUTGOING_CALLS": (PermissionProtection.DANGEROUS, "Process outgoing calls"),
    "android.permission.BODY_SENSORS": (PermissionProtection.DANGEROUS, "Read body sensors"),
    "android.permission.ACTIVITY_RECOGNITION": (PermissionProtection.DANGEROUS, "Activity recognition"),
    "android.permission.ACCESS_FINE_LOCATION": (PermissionProtection.DANGEROUS, "Precise location"),
    "android.permission.ACCESS_COARSE_LOCATION": (PermissionProtection.DANGEROUS, "Approximate location"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": (PermissionProtection.DANGEROUS, "Background location"),
    "android.permission.READ_EXTERNAL_STORAGE": (PermissionProtection.DANGEROUS, "Read external storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE": (PermissionProtection.DANGEROUS, "Write external storage"),
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED": (PermissionProtection.DANGEROUS, "Read selected visual media"),
    "android.permission.CAMERA": (PermissionProtection.DANGEROUS, "Take pictures and record video"),
    "android.permission.RECORD_AUDIO": (PermissionProtection.DANGEROUS, "Record audio"),

    # Signature permissions
    "android.permission.INSTALL_PACKAGES": (PermissionProtection.SIGNATURE, "Install packages"),
    "android.permission.DELETE_PACKAGES": (PermissionProtection.SIGNATURE, "Delete packages"),
    "android.permission.CLEAR_APP_CACHE": (PermissionProtection.SIGNATURE, "Clear app cache"),
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": (PermissionProtection.SIGNATURE, "Mount/unmount filesystems"),
    "android.permission.ACCESS_CACHE_FILESYSTEM": (PermissionProtection.SIGNATURE, "Access cache filesystem"),
    "android.permission.ACCESS_SURFACE_FLINGER": (PermissionProtection.SIGNATURE, "Access SurfaceFlinger"),
    "android.permission.READ_LOGS": (PermissionProtection.SIGNATURE, "Read system logs"),
    "android.permission.DUMP": (PermissionProtection.SIGNATURE, "Dump system state"),
    "android.permission.SET_DEBUG_APP": (PermissionProtection.SIGNATURE, "Set debug app"),
    "android.permission.SET_ANIMATION_SCALE": (PermissionProtection.SIGNATURE, "Set animation scale"),
    "android.permission.CHANGE_CONFIGURATION": (PermissionProtection.SIGNATURE, "Change configuration"),
    "android.permission.STATUS_BAR": (PermissionProtection.SIGNATURE, "Control status bar"),
    "android.permission.EXPAND_STATUS_BAR": (PermissionProtection.NORMAL, "Expand status bar"),
    "android.permission.MASTER_CLEAR": (PermissionProtection.SIGNATURE, "Factory reset"),
    "android.permission.BIND_DEVICE_ADMIN": (PermissionProtection.SIGNATURE, "Bind device admin"),
    "android.permission.INTERACT_ACROSS_USERS": (PermissionProtection.SIGNATURE, "Interact across users"),
    "android.permission.MANAGE_USERS": (PermissionProtection.SIGNATURE, "Manage users"),
    "android.permission.MOUNT_FORMAT_FILESYSTEMS": (PermissionProtection.SIGNATURE, "Format filesystems"),
    "android.permission.PACKAGE_USAGE_STATS": (PermissionProtection.SIGNATURE, "Package usage stats"),
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": (PermissionProtection.SIGNATURE, "Bind notification listener"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (PermissionProtection.SIGNATURE, "Bind accessibility service"),
    "android.permission.BIND_VPN_SERVICE": (PermissionProtection.SIGNATURE, "Bind VPN service"),
    "android.permission.BIND_PRINT_SERVICE": (PermissionProtection.SIGNATURE, "Bind print service"),
    "android.permission.BIND_INPUT_METHOD": (PermissionProtection.SIGNATURE, "Bind input method"),
    "android.permission.BIND_TEXT_SERVICE": (PermissionProtection.SIGNATURE, "Bind text service"),
    "android.permission.BIND_WALLPAPER_SERVICE": (PermissionProtection.SIGNATURE, "Bind Wallpaper service"),
    "android.permission.BIND_WIDGET_SERVICE": (PermissionProtection.SIGNATURE, "Bind Widget service"),
    "android.permission.SET_TIME": (PermissionProtection.SIGNATURE, "Set time"),
    "android.permission.SET_TIME_ZONE": (PermissionProtection.SIGNATURE, "Set time zone"),
    "android.permission.REBOOT": (PermissionProtection.SIGNATURE, "Reboot device"),
    "android.permission.SHUTDOWN": (PermissionProtection.SIGNATURE, "Shutdown device"),
    "android.permission.STOP_APP": (PermissionProtection.SIGNATURE, "Stop apps"),
    "android.permission.FORCE_STOP_PACKAGES": (PermissionProtection.SIGNATURE, "Force stop packages"),
    "android.permission.KILL_BACKGROUND_PROCESSES": (PermissionProtection.NORMAL, "Kill background processes"),
}

# High-risk permission combinations
RISKY_COMBINATIONS: list[tuple[list[str], str, Severity]] = [
    (
        ["android.permission.READ_SMS", "android.permission.INTERNET"],
        "App can read SMS and send data over network",
        Severity.HIGH,
    ),
    (
        ["android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.INTERNET"],
        "App can capture photo/video/audio and upload",
        Severity.HIGH,
    ),
    (
        ["android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.INTERNET"],
        "App can track location in background",
        Severity.HIGH,
    ),
    (
        ["android.permission.READ_CONTACTS", "android.permission.INTERNET"],
        "App can read contacts and upload",
        Severity.MEDIUM,
    ),
    (
        ["android.permission.READ_CALL_LOG", "android.permission.INTERNET"],
        "App can read call history and upload",
        Severity.MEDIUM,
    ),
    (
        ["android.permission.PROCESS_OUTGOING_CALLS", "android.permission.READ_PHONE_STATE"],
        "App can intercept and monitor calls",
        Severity.HIGH,
    ),
    (
        ["android.permission.BIND_DEVICE_ADMIN", "android.permission.DELETE_PACKAGES"],
        "App has device admin and can delete packages",
        Severity.CRITICAL,
    ),
]


def classify_permission(permission: str) -> PermissionProtection:
    """Classify a permission by its protection level."""
    if permission in ANDROID_PERMISSIONS:
        return ANDROID_PERMISSIONS[permission][0]
    # Unknown permissions (not in Android's standard set)
    return PermissionProtection.UNKNOWN


def get_permission_description(permission: str) -> str:
    """Get human-readable description of a permission."""
    if permission in ANDROID_PERMISSIONS:
        return ANDROID_PERMISSIONS[permission][1]
    return permission.split(".")[-1].replace("_", " ").title()


def analyze_permissions(permissions: list[str]) -> tuple[list[PermissionInfo], list[Finding]]:
    """Analyze permissions and generate findings.

    Returns:
        Tuple of (permission infos, findings).
    """
    perm_infos: list[PermissionInfo] = []
    findings: list[Finding] = []

    for perm in permissions:
        protection = classify_permission(perm)
        desc = get_permission_description(perm)
        info = PermissionInfo(
            name=perm,
            protection_level=protection,
            reason=desc,
        )
        perm_infos.append(info)

        # Generate findings for dangerous/signature permissions
        if protection == PermissionProtection.DANGEROUS:
            finding = Finding(
                id=f"PD-PERM-{perm.split('.')[-1][:20]}",
                title=f"Requested Permission: {perm.split('.')[-1]}",
                category="Permissions",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                description=(
                    f"Application requests the dangerous permission '{perm}' "
                    f"({desc}). This permission grants access to sensitive data "
                    f"or functionality. Verify that the permission is necessary "
                    f"for the application's documented functionality."
                ),
                evidence=[
                    Evidence(
                        type="manifest",
                        source="AndroidManifest.xml",
                        attribute="uses-permission",
                        value=perm,
                    )
                ],
                affected_component=perm,
                remediation=(
                    f"Ensure the app needs '{desc}' functionality. "
                    f"Request this permission at runtime only when needed."
                ),
                references=[
                    "https://developer.android.com/guide/topics/permissions/overview",
                ],
            )
            findings.append(finding)

        elif protection == PermissionProtection.SIGNATURE:
            finding = Finding(
                id=f"PD-PERM-SIG-{perm.split('.')[-1][:15]}",
                title=f"Signature Permission: {perm.split('.')[-1]}",
                category="Permissions",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                description=(
                    f"Application requests the signature-level permission '{perm}' "
                    f"({desc}). This permission is only granted to apps signed "
                    f"with the same certificate as the system."
                ),
                evidence=[
                    Evidence(
                        type="manifest",
                        source="AndroidManifest.xml",
                        attribute="uses-permission",
                        value=perm,
                    )
                ],
                affected_component=perm,
            )
            findings.append(finding)

    # Check for risky permission combinations
    perm_set = set(permissions)
    for combo_perms, reason, severity in RISKY_COMBINATIONS:
        if all(p in perm_set for p in combo_perms):
            finding = Finding(
                id=f"PD-PERM-COMBO-{hash(frozenset(combo_perms)) % 10000:04d}",
                title="Risky Permission Combination",
                category="Permissions",
                severity=severity,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.POTENTIAL,
                description=(
                    f"{reason}. "
                    f"Permissions: {', '.join(combo_perms)}"
                ),
                evidence=[
                    Evidence(
                        type="manifest",
                        source="AndroidManifest.xml",
                        attribute="uses-permission",
                        value=p,
                    )
                    for p in combo_perms
                ],
                remediation=(
                    "Review whether this permission combination is necessary. "
                    "Request permissions at runtime only when needed."
                ),
            )
            findings.append(finding)

    return perm_infos, findings


class PermissionAnalyzerCheck(SecurityCheck):
    """Security check for permission analysis."""

    id = "PD-PERM-001"
    name = "Permission Analysis"
    category = "apk"
    description = "Analyze requested Android permissions for security implications"

    def run(self, context: ScanContext) -> list[Finding]:
        permissions = context.manifest_data.get("permissions", [])
        _, findings = analyze_permissions(permissions)
        return findings

    def can_run(self, context: ScanContext) -> bool:
        return context.scan_type == "apk" and bool(context.manifest_data.get("permissions"))
