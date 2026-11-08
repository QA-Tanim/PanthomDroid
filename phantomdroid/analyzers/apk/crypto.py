"""PhantomDroid X - Cryptographic analysis of APK content."""

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

# Weak cryptographic patterns
WEAK_CRYPTO_PATTERNS: list[tuple[str, str, str, Severity]] = [
    # Hash algorithms
    (r"(?i)\bMD5\b", "MD5", "MD5 hash algorithm", Severity.MEDIUM),
    (r"(?i)\bSHA[_\-]?1\b", "SHA-1", "SHA-1 hash algorithm", Severity.MEDIUM),

    # Symmetric encryption
    (r"(?i)\bDES\b", "DES", "DES encryption (weak)", Severity.HIGH),
    (r"(?i)\bDESede\b", "3DES", "3DES encryption (deprecated)", Severity.MEDIUM),
    (r"(?i)\bBlowfish\b", "Blowfish", "Blowfish encryption", Severity.LOW),

    # Modes
    (r"(?i)\bECB\b", "ECB", "ECB mode (insecure)", Severity.HIGH),
    (r"(?i)\bNO.Padding\b", "NoPadding", "No padding mode", Severity.MEDIUM),

    # Hardcoded IVs/keys
    (r"(?i)(?:iv|initialization[_\-]?vector)\s*[:=]\s*['\"]([a-zA-Z0-9+/=]{8,})", "Hardcoded IV", "Hardcoded initialization vector", Severity.HIGH),
    (r"(?i)(?:secret[_\-]?key|encryption[_\-]?key)\s*[:=]\s*['\"]([a-zA-Z0-9+/=]{8,})", "Hardcoded Key", "Hardcoded encryption key", Severity.CRITICAL),

    # Insecure random
    (r"(?i)\bjava\.util\.Random\b", "java.util.Random", "Insecure random number generator", Severity.HIGH),
    (r"(?i)\bMath\.random\b", "Math.random()", "Insecure random number generator", Severity.HIGH),

    # SSL/TLS
    (r"(?i)SSLv3\b", "SSLv3", "SSLv3 protocol (deprecated, POODLE)", Severity.CRITICAL),
    (r"(?i)TLSv1\.0\b", "TLSv1.0", "TLS 1.0 (deprecated)", Severity.HIGH),
    (r"(?i)TLSv1\.1\b", "TLSv1.1", "TLS 1.1 (deprecated)", Severity.MEDIUM),

    # Trust all
    (r"(?i)TrustAll|ALLOW_ALL|NullTrustManager|X509TrustManager", "TrustAll", "Trust-all certificate manager", Severity.CRITICAL),
    (r"(?i)HostnameVerifier\s*=\s*(?:[^{]*)?\{[^}]*return\s*true", "HostnameVerifier", "Accept-all hostname verifier", Severity.CRITICAL),

    # Backup
    (r"(?i)android:allowBackup\s*=\s*['\"]true['\"]", "allowBackup", "Backup enabled", Severity.MEDIUM),

    # WebView
    (r"(?i)setJavaScriptEnabled\s*\(\s*true\s*\)", "JavaScriptEnabled", "WebView JavaScript enabled", Severity.INFO),
    (r"(?i)setAllowFileAccess\s*\(\s*true\s*\)", "FileAccess", "WebView file access enabled", Severity.HIGH),
    (r"(?i)setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)", "UniversalFileAccess", "WebView universal file access", Severity.CRITICAL),
    (r"(?i)setMixedContentMode\s*\(\s*MIXED_CONTENT_ALWAYS_ALLOW\s*\)", "MixedContent", "WebView mixed content allowed", Severity.HIGH),
    (r"(?i)addJavascriptInterface", "JavascriptInterface", "WebView JavaScript interface exposed", Severity.MEDIUM),
]


def analyze_crypto(
    file_contents: dict[str, str],
) -> list[Finding]:
    """Analyze file contents for weak cryptographic usage.

    Args:
        file_contents: Dictionary of file_path -> content.

    Returns:
        List of findings.
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    for file_path, content in file_contents.items():
        for pattern, pattern_name, description, severity in WEAK_CRYPTO_PATTERNS:
            try:
                for m in re.finditer(pattern, content):
                    dedup_key = f"{file_path}:{pattern_name}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    # Get context
                    start = max(0, m.start() - 50)
                    end = min(len(content), m.end() + 50)
                    context_text = content[start:end].replace("\n", " ").strip()

                    finding = Finding(
                        id=f"PD-CRYPTO-{pattern_name.upper()[:15]}",
                        title=f"Weak Cryptography: {description}",
                        category="Cryptographic Analysis",
                        severity=severity,
                        confidence=Confidence.MEDIUM,
                        status=FindingStatus.POTENTIAL,
                        description=(
                            f"Weak cryptographic practice detected in "
                            f"{file_path}: {description}. "
                            f"Context: ...{context_text}..."
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
                        remediation=_get_remediation(pattern_name),
                        references=_get_references(pattern_name),
                    )
                    findings.append(finding)
            except re.error:
                continue

    return findings


def _get_remediation(pattern_name: str) -> str:
    remediations = {
        "MD5": "Use SHA-256 or SHA-3 for hashing. For password hashing, use bcrypt, scrypt, or Argon2.",
        "SHA-1": "Use SHA-256 or SHA-3 for hashing.",
        "DES": "Use AES-256 or ChaCha20 for symmetric encryption.",
        "3DES": "Use AES-256 for symmetric encryption.",
        "ECB": "Use CBC, GCM, or CTR mode with proper IVs.",
        "Hardcoded IV": "Generate IVs randomly for each encryption operation.",
        "Hardcoded Key": "Store encryption keys in Android Keystore, never hardcode them.",
        "java.util.Random": "Use java.security.SecureRandom for cryptographic operations.",
        "Math.random()": "Use java.security.SecureRandom for cryptographic operations.",
        "SSLv3": "Use TLS 1.2 or higher.",
        "TLSv1.0": "Use TLS 1.2 or higher.",
        "TLSv1.1": "Use TLS 1.2 or higher.",
        "TrustAll": "Implement proper certificate validation with CertificatePinner or TrustManager.",
        "HostnameVerifier": "Implement proper hostname verification.",
        "JavaScriptEnabled": "Evaluate if JavaScript is necessary; be cautious with untrusted content.",
        "FileAccess": "Disable file access in WebView unless specifically needed.",
        "UniversalFileAccess": "Disable universal file access; it allows reading any file via file:// URLs.",
        "MixedContent": "Use MIXED_CONTENT_NEVER_ALLOW to prevent loading HTTP resources in HTTPS pages.",
        "JavascriptInterface": "Ensure JavaScript interfaces do not expose sensitive functionality.",
    }
    return remediations.get(pattern_name, "Review and apply secure cryptographic practices.")


def _get_references(pattern_name: str) -> list[str]:
    refs = [
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://cwe.mitre.org/data/definitions/330.html",
    ]
    return refs


class CryptoAnalyzerCheck(SecurityCheck):
    """Security check for cryptographic analysis."""

    id = "PD-CRYPTO-001"
    name = "Cryptographic Analysis"
    category = "apk"
    description = "Analyze APK for weak cryptographic practices"

    def run(self, context: ScanContext) -> list[Finding]:
        file_contents = context.metadata.get("file_contents", {})
        return analyze_crypto(file_contents)

    def can_run(self, context: ScanContext) -> bool:
        return context.scan_type == "apk" and bool(context.metadata.get("file_contents"))
