"""PhantomDroid X - Secret detection engine with entropy analysis."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from phantomdroid.core.models import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
)
from phantomdroid.core.scanner import ScanContext, SecurityCheck


@dataclass
class SecretMatch:
    """A detected secret match."""
    secret_type: str
    pattern_name: str
    file_path: str
    line_number: int
    matched_text: str
    redacted_text: str
    entropy: float
    confidence: Confidence
    severity: Severity


# Secret detection patterns with metadata
SECRET_PATTERNS: list[tuple[str, str, str, Severity]] = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "aws_access_key", Severity.CRITICAL),
    (r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})", "AWS Secret Access Key", "aws_secret_key", Severity.CRITICAL),

    # Google
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", "google_api_key", Severity.HIGH),
    (r"(?i)google[_\-]?maps[_\-]?key\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{35})", "Google Maps Key", "google_maps_key", Severity.HIGH),
    (r"(?i)(gh[ps]_[A-Za-z0-9_]{36,})", "GitHub Token", "github_token", Severity.CRITICAL),

    # Firebase
    (r"https?://[a-z0-9\-]+\.firebaseio\.com", "Firebase Realtime Database URL", "firebase_url", Severity.HIGH),
    (r"(?i)firebase[_\-]?key\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "Firebase Key", "firebase_key", Severity.HIGH),

    # JWT
    (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "JSON Web Token (JWT)", "jwt", Severity.HIGH),

    # Private keys
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key", "private_key", Severity.CRITICAL),

    # OAuth / Tokens
    (r"(?i)(client[_\-]?secret|client[_\-]?id)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})", "OAuth Credential", "oauth_credential", Severity.HIGH),
    (r"(?i)(access[_\-]?token|auth[_\-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{16,})", "Access Token", "access_token", Severity.HIGH),

    # Stripe
    (r"sk_live_[a-zA-Z0-9]{24,}", "Stripe Live Secret Key", "stripe_live_key", Severity.CRITICAL),
    (r"pk_live_[a-zA-Z0-9]{24,}", "Stripe Live Publishable Key", "stripe_live_pubkey", Severity.HIGH),
    (r"rk_live_[a-zA-Z0-9]{24,}", "Stripe Restricted Key", "stripe_restricted_key", Severity.CRITICAL),

    # Twilio
    (r"AC[a-f0-9]{32}", "Twilio Account SID", "twilio_sid", Severity.HIGH),
    (r"(?i)twilio[_\-]?auth[_\-]?token\s*[:=]\s*['\"]?([a-zA-Z0-9]{32})", "Twilio Auth Token", "twilio_auth", Severity.CRITICAL),

    # SendGrid
    (r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", "SendGrid API Key", "sendgrid_key", Severity.CRITICAL),

    # Slack
    (r"xox[bpoa]-[0-9]{10,}-[a-zA-Z0-9\-]+", "Slack Token", "slack_token", Severity.CRITICAL),

    # Database URLs
    (r"(?i)(mysql|postgresql|mongodb|redis|amqp)://[^\s'\"<>{}[\]]+", "Database Connection URL", "db_url", Severity.HIGH),

    # URLs with credentials
    (r"https?://[^:]+:[^@]+@[^\s]+", "URL with Embedded Credentials", "url_creds", Severity.HIGH),

    # Generic API keys
    (r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})", "API Key", "generic_api_key", Severity.MEDIUM),

    # Passwords
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?(\S{8,})", "Password", "password", Severity.HIGH),
    (r"(?i)(secret|secret[_\-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-/+=]{16,})", "Secret Key", "secret_key", Severity.HIGH),

    # Bearer tokens
    (r"(?i)(bearer)\s+[a-zA-Z0-9_\-\.]{20,}", "Bearer Token", "bearer_token", Severity.HIGH),

    # Heroku
    (r"(?i)heroku[_\-]?api[_\-]?key\s*[:=]\s*['\"]?([a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12})", "Heroku API Key", "heroku_key", Severity.HIGH),

    # Mailgun
    (r"key-[0-9a-zA-Z]{32}", "Mailgun API Key", "mailgun_key", Severity.HIGH),

    # Algolia
    (r"(?i)algolia[_\-]?api[_\-]?key\s*[:=]\s*['\"]?([a-f0-9]{32})", "Algolia API Key", "algolia_key", Severity.MEDIUM),
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string.

    Higher entropy suggests more randomness, which is characteristic
    of secrets vs. regular text.
    """
    if not data:
        return 0.0

    freq: dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def redact_secret(text: str, keep_start: int = 4, keep_end: int = 4) -> str:
    """Redact a secret value, keeping some characters for identification.

    Args:
        text: The secret text to redact.
        keep_start: Number of characters to keep at start.
        keep_end: Number of characters to keep at end.

    Returns:
        Redacted string.
    """
    if len(text) <= keep_start + keep_end + 4:
        return "*" * len(text)
    return text[:keep_start] + "*" * (len(text) - keep_start - keep_end) + text[-keep_end:]


def scan_for_secrets(
    content: str,
    file_path: str,
    min_entropy: float = 3.0,
    min_length: int = 8,
) -> list[SecretMatch]:
    """Scan content for hardcoded secrets.

    Args:
        content: Text content to scan.
        file_path: Source file path.
        min_entropy: Minimum entropy threshold.
        min_length: Minimum match length.

    Returns:
        List of SecretMatch objects.
    """
    matches: list[SecretMatch] = []

    for pattern, secret_type, pattern_name, severity in SECRET_PATTERNS:
        try:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                matched = m.group(0)
                if len(matched) < min_length:
                    continue

                # Calculate entropy
                entropy = calculate_shannon_entropy(matched)

                # Determine confidence based on entropy and pattern specificity
                if entropy >= min_entropy and severity in (Severity.CRITICAL, Severity.HIGH):
                    confidence = Confidence.HIGH
                elif entropy >= min_entropy or severity in (Severity.CRITICAL, Severity.HIGH):
                    confidence = Confidence.MEDIUM
                else:
                    confidence = Confidence.LOW

                # Get line number
                start = m.start()
                line_number = content[:start].count("\n") + 1

                match = SecretMatch(
                    secret_type=secret_type,
                    pattern_name=pattern_name,
                    file_path=file_path,
                    line_number=line_number,
                    matched_text=matched,
                    redacted_text=redact_secret(matched),
                    entropy=entropy,
                    confidence=confidence,
                    severity=severity,
                )
                matches.append(match)
        except re.error:
            continue

    return matches


def secrets_to_findings(matches: list[SecretMatch]) -> list[Finding]:
    """Convert secret matches to Finding objects."""
    findings: list[Finding] = []
    seen: set[str] = set()

    for match in matches:
        # Deduplicate by file + type + redacted value
        dedup_key = f"{match.file_path}:{match.pattern_name}:{match.redacted_text}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        finding = Finding(
            id=f"PD-SECRET-{match.pattern_name.upper()[:15]}",
            title=f"Hardcoded {match.secret_type}",
            category="Secret Detection",
            severity=match.severity,
            confidence=match.confidence,
            status=FindingStatus.POTENTIAL,
            description=(
                f"A potential {match.secret_type} was detected in "
                f"{match.file_path} at line {match.line_number}. "
                f"Entropy: {match.entropy:.2f}. "
                f"This could expose sensitive credentials if the APK "
                f"is decompiled."
            ),
            evidence=[
                Evidence(
                    type="file",
                    source=match.file_path,
                    attribute=match.pattern_name,
                    value=match.redacted_text,
                )
            ],
            affected_component=match.file_path,
            remediation=(
                "Remove hardcoded secrets from the APK. Use Android Keystore, "
                "encrypted SharedPreferences, or a secure secrets management "
                "solution. Consider using BuildConfig fields injected at build time."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/798.html",
            ],
        )
        findings.append(finding)

    return findings


class SecretScannerCheck(SecurityCheck):
    """Security check for hardcoded secret detection."""

    id = "PD-SECRET-001"
    name = "Hardcoded Secret Detection"
    category = "apk"
    description = "Scan for hardcoded API keys, tokens, passwords, and other secrets"

    def run(self, context: ScanContext) -> list[Finding]:
        all_matches: list[SecretMatch] = []
        files_to_scan = context.metadata.get("scannable_files", {})

        for file_path, content in files_to_scan.items():
            matches = scan_for_secrets(
                content,
                file_path,
                min_entropy=context.config.secrets.min_entropy if context.config else 3.0,
                min_length=context.config.secrets.min_length if context.config else 8,
            )
            all_matches.extend(matches)

        return secrets_to_findings(all_matches)

    def can_run(self, context: ScanContext) -> bool:
        return context.scan_type == "apk" and bool(context.metadata.get("scannable_files"))
