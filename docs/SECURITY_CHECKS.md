# Security Checks Reference

## APK Analysis Checks

### PD-MANIFEST-001: Manifest Security Analysis
| Attribute | Value |
|-----------|-------|
| Category | Manifest Security |
| Evidence Required | AndroidManifest.xml |
| CWE | CWE-489 (Debuggable), CWE-921 (Backup) |
| False Positive Conditions | Debug builds, intentional debug config |

### PD-PERM-001: Permission Analysis
| Attribute | Value |
|-----------|-------|
| Category | Permissions |
| Evidence Required | AndroidManifest.xml uses-permission |
| CWE | Varies by permission |
| False Positive Conditions | Permissions may be required for legitimate functionality |

### PD-COMP-001: Exported Component Analysis
| Attribute | Value |
|-----------|-------|
| Category | Component Security |
| Evidence Required | AndroidManifest.xml component declarations |
| CWE | CWE-926 |
| False Positive Conditions | Components with custom permissions, intent-filter-only exports |

### PD-SECRET-001: Hardcoded Secret Detection
| Attribute | Value |
|-----------|-------|
| Category | Secret Detection |
| Evidence Required | APK file contents |
| CWE | CWE-798 |
| False Positive Conditions | Test files, documentation, example code |

### PD-CRYPTO-001: Cryptographic Analysis
| Attribute | Value |
|-----------|-------|
| Category | Cryptographic Analysis |
| Evidence Required | APK source code / DEX |
| CWE | CWE-327, CWE-330 |
| False Positive Conditions | Deprecated code paths, test code |

### PD-NET-001: Network Security Analysis
| Attribute | Value |
|-----------|-------|
| Category | Network Security |
| Evidence Required | network_security_config.xml, manifest |
| CWE | CWE-319, CWE-295 |
| False Positive Conditions | Development builds, internal apps |

### PD-CODE-001: Code Pattern Analysis
| Attribute | Value |
|-----------|-------|
| Category | Code Analysis |
| Evidence Required | DEX bytecode |
| CWE | Varies |
| False Positive Conditions | Heuristic detection, requires manual verification |

### PD-RES-001: Resource Analysis
| Attribute | Value |
|-----------|-------|
| Category | Resource Analysis |
| Evidence Required | APK resources |
| CWE | Varies |
| False Positive Conditions | Intentional bundled data |

## Runtime Analysis Checks

### PD-STORAGE-001: Insecure Storage Analysis
| Attribute | Value |
|-----------|-------|
| Category | Insecure Storage |
| Evidence Required | Device access via ADB |
| CWE | CWE-312, CWE-732 |
| False Positive Conditions | Requires rooted device or backup access |

### PD-WEBVIEW-001: WebView Security Analysis
| Attribute | Value |
|-----------|-------|
| Category | WebView Security |
| Evidence Required | Device access via ADB |
| CWE | CWE-200 |
| False Positive Conditions | Runtime detection is limited |

## Network Analysis Checks

### PD-NET-PORT-001: Port Scanning
| Attribute | Value |
|-----------|-------|
| Category | Network Security |
| Evidence Required | Network access to target |
| CWE | CWE-16 |
| False Positive Conditions | Services may be intentional |

## Remediation Summary

| Finding | Remediation |
|---------|-------------|
| Debuggable | Set android:debuggable=false |
| Backup Enabled | Set android:allowBackup=false |
| Exported Component | Add permission or set exported=false |
| Hardcoded Secret | Use Android Keystore or encrypted storage |
| Weak Crypto | Use AES-GCM, SHA-256, SecureRandom |
| Cleartext Traffic | Use network_security_config.xml |
| Open Port | Restrict network access |
