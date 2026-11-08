"""PhantomDroid X - DEX/code analysis for security patterns."""

from __future__ import annotations

import re

from phantomdroid.core.models import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
)
from phantomdroid.core.scanner import ScanContext, SecurityCheck

# Sensitive API patterns in DEX code
SENSITIVE_API_PATTERNS: list[tuple[str, str, str, Severity]] = [
    # Insecure storage
    (r"getSharedPreferences", "SharedPreferences", "Uses SharedPreferences for storage", Severity.INFO),
    (r"MODE_WORLD_READABLE", "WorldReadable", "World-readable file mode", Severity.HIGH),
    (r"MODE_WORLD_WRITABLE", "WorldWritable", "World-writable file mode", Severity.CRITICAL),
    (r"MODE_PRIVATE", "ModePrivate", "Private file mode (OK)", Severity.INFO),

    # WebView
    (r"setJavaScriptEnabled", "JavaScriptEnabled", "Enables JavaScript in WebView", Severity.INFO),
    (r"addJavascriptInterface", "JavascriptInterface", "Adds JavaScript interface to WebView", Severity.MEDIUM),
    (r"setAllowFileAccessFromFileURLs", "FileAccessFromFileURLs", "Allows file access from file URLs", Severity.HIGH),
    (r"setAllowUniversalAccessFromFileURLs", "UniversalFileAccess", "Universal file access from file URLs", Severity.CRITICAL),
    (r"loadDataWithBaseURL", "LoadDataWithBaseURL", "Loads data with base URL in WebView", Severity.INFO),
    (r"setWebViewClient", "WebViewClient", "Sets WebView client", Severity.INFO),

    # Crypto
    (r"javax\.crypto\.Cipher.getInstance\(\"AES/ECB", "AESECB", "AES in ECB mode", Severity.HIGH),
    (r"javax\.crypto\.Cipher.getInstance\(\"DES", "DES", "DES encryption", Severity.HIGH),
    (r"java\.util\.Random", "InsecureRandom", "Insecure random number generator", Severity.HIGH),
    (r"Math\.random\(\)", "MathRandom", "Insecure Math.random()", Severity.HIGH),

    # SQL
    (r"rawQuery.*\+", "SQLInjection", "Potential SQL injection (string concat in query)", Severity.HIGH),
    (r"execSQL.*\+", "SQLInjection", "Potential SQL injection (string concat in execSQL)", Severity.HIGH),

    # Network
    (r"TrustAllCertificates", "TrustAll", "Trust-all certificates", Severity.CRITICAL),
    (r"ALLOW_ALL_HOSTNAME_VERIFIER", "AllowAllHostnames", "Accept all hostnames", Severity.CRITICAL),
    (r"SSLSocketFactory", "SSLSocketFactory", "Custom SSL socket factory", Severity.INFO),

    # Logging
    (r"android\.util\.Log\.(d|v|i|w|e)\(", "LogStatements", "Log statements in code", Severity.LOW),
    (r"System\.out\.println", "SystemOut", "System.out.println statements", Severity.LOW),

    # Clipboard
    (r"ClipboardManager", "Clipboard", "Uses clipboard (may expose sensitive data)", Severity.LOW),

    # Intent
    (r"PendingIntent\.getActivity.*FLAG_MUTABLE", "MutablePendingIntent", "Mutable PendingIntent", Severity.HIGH),
    (r"Intent\(.*\)\.setClassName", "IntentRedirection", "Potential intent redirection", Severity.MEDIUM),
]


def analyze_code_patterns(
    file_contents: dict[str, str],
) -> list[Finding]:
    """Analyze file contents for sensitive API patterns.

    Args:
        file_contents: Dictionary of file_path -> content.

    Returns:
        List of findings.
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    for file_path, content in file_contents.items():
        # Only analyze DEX-like and Java/Kotlin files
        if not any(file_path.endswith(ext) for ext in [".dex", ".class", ".java", ".kt"]) and "classes" not in file_path.lower():
            continue

        for pattern, pattern_name, description, severity in SENSITIVE_API_PATTERNS:
            try:
                matches = list(re.finditer(pattern, content))
                if not matches:
                    continue

                dedup_key = f"{file_path}:{pattern_name}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Get first match context
                m = matches[0]
                start = max(0, m.start() - 30)
                end = min(len(content), m.end() + 30)
                context_text = content[start:end].replace("\n", " ").strip()

                finding = Finding(
                    id=f"PD-CODE-{pattern_name.upper()[:15]}",
                    title=f"Sensitive API: {description}",
                    category="Code Analysis",
                    severity=severity,
                    confidence=Confidence.LOW,
                    status=FindingStatus.HEURISTIC,
                    description=(
                        f"Sensitive API pattern detected in {file_path}: "
                        f"{description}. Found {len(matches)} occurrence(s). "
                        f"This is a heuristic finding and may require manual "
                        f"verification."
                    ),
                    evidence=[
                        Evidence(
                            type="static-analysis",
                            source=file_path,
                            attribute=pattern_name,
                            value=context_text[:200],
                        )
                    ],
                    affected_component=file_path,
                    remediation=_get_code_remediation(pattern_name),
                    references=[],
                )
                findings.append(finding)
            except re.error:
                continue

    return findings


def _get_code_remediation(pattern_name: str) -> str:
    remediations = {
        "WorldReadable": "Use MODE_PRIVATE instead of MODE_WORLD_READABLE.",
        "WorldWritable": "Use MODE_PRIVATE instead of MODE_WORLD_WRITABLE.",
        "JavascriptInterface": "Ensure JavaScript interfaces do not expose sensitive functionality. Use @JavascriptInterface annotation.",
        "FileAccessFromFileURLs": "Disable file access from file URLs unless absolutely necessary.",
        "UniversalFileAccess": "Disable universal file access from file URLs.",
        "AESECB": "Use AES in CBC or GCM mode with proper IVs.",
        "DES": "Use AES-256 instead of DES.",
        "InsecureRandom": "Use java.security.SecureRandom for cryptographic operations.",
        "MathRandom": "Use java.security.SecureRandom instead of Math.random().",
        "SQLInjection": "Use parameterized queries instead of string concatenation.",
        "TrustAll": "Implement proper certificate validation.",
        "AllowAllHostnames": "Implement proper hostname verification.",
        "MutablePendingIntent": "Use FLAG_IMMUTABLE for PendingIntents.",
        "IntentRedirection": "Validate and sanitize intent targets before forwarding.",
    }
    return remediations.get(pattern_name, "Review and apply secure coding practices.")


class CodeAnalysisCheck(SecurityCheck):
    """Security check for code pattern analysis."""

    id = "PD-CODE-001"
    name = "Code Pattern Analysis"
    category = "apk"
    description = "Analyze DEX code for sensitive API patterns"

    def run(self, context: ScanContext) -> list[Finding]:
        file_contents = context.metadata.get("file_contents", {})
        return analyze_code_patterns(file_contents)

    def can_run(self, context: ScanContext) -> bool:
        return context.scan_type == "apk" and bool(context.metadata.get("file_contents"))
