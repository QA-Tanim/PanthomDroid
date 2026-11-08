# PhantomDroid X

<div align="center">
  <img src="https://img.shields.io/badge/Android-Security%20Automation-blueviolet?style=for-the-badge" alt="Android Security Automation" />
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge" alt="Status Active" />
</div>

<h2 align="center">Android Security & QA Automation Framework</h2>

PhantomDroid X is a modular, evidence-driven Android security testing framework that distinguishes between confirmed vulnerabilities, potential issues, and heuristic observations.

> **For authorized security testing and educational purposes only.**

## ✨ What it does

- 🔍 APK static analysis with manifest, permission, component, crypto, and secret checks
- 📱 Runtime/device inspection using ADB and Android runtime metadata
- 🌐 Network assessment with port risk classification and config review
- 🧾 Evidence-backed findings with severity, confidence, and remediation guidance
- 📄 Multi-format reporting in JSON, HTML, and SARIF
- 🛡️ CI/CD gate checks for security policy enforcement

## 🧩 Feature highlights

### Security analysis
- Binary XML manifest parsing
- Exported component detection
- Dangerous permission classification
- Secret scanning with entropy analysis and redaction
- Weak crypto pattern detection
- WebView and runtime configuration checks

### Reporting and automation
- JSON, HTML, SARIF output
- CLI-first workflow
- CI/CD gate thresholds
- Structured evidence model for downstream automation

## 🚀 Quick start

### 1) Install

```bash
# Clone the repository
git clone https://github.com/phantomdroid/phantomdroid-x.git
cd phantomdroid-x

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install in development mode
pip install -e ".[dev]"
```

### 2) Run the CLI

```bash
# Show version
phantomdroid version

# List connected devices
phantomdroid devices

# Analyze an APK
phantomdroid apk analyze app.apk

# Generate HTML report
phantomdroid apk analyze app.apk --format html

# Generate SARIF report for CI
phantomdroid apk analyze app.apk --format sarif --output results/

# Scan a connected device
phantomdroid scan device

# CI/CD security gate
phantomdroid gate results.json --fail-on high
```

## 🏗️ Architecture

```text
phantomdroid/
├── cli/              # Command-line interface
├── core/             # Core models, config, scanner engine
├── android/          # ADB wrapper, device, manifest parser
├── analyzers/        # Security analyzers (APK, runtime, network)
├── evidence/         # Evidence collection and sanitization
├── reporting/        # Report generators (JSON, HTML, SARIF)
├── utils/            # Utilities (subprocess, filesystem)
├── tests/            # Regression and unit tests
└── README.md         # Project overview
```

## 📊 Finding model

Every finding includes:

- **ID** — Unique identifier, such as `PD-MANIFEST-DEBUGGABLE`
- **Title** — Human-readable summary
- **Severity** — `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- **Confidence** — `HIGH`, `MEDIUM`, `LOW`
- **Status** — `CONFIRMED`, `POTENTIAL`, `INFORMATIONAL`, `HEURISTIC`
- **CWE** — CWE mapping where available
- **Evidence** — Source and context for the finding
- **Remediation** — Recommended fix

## 🛡️ Security model

PhantomDroid X explicitly separates findings by certainty:

- **CONFIRMED** — Evidence directly supports the issue
- **POTENTIAL** — Evidence suggests an issue may exist
- **INFORMATIONAL** — Notable configuration, not necessarily a vulnerability
- **HEURISTIC** — Pattern-based detection that needs manual confirmation

## 🧪 Development

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=phantomdroid

# Lint
ruff check .

# Type check
mypy .
```

## 📦 Requirements

- Python 3.11+
- ADB (optional, for device scanning)

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer

This tool is intended for authorized security testing only. Unauthorized use against systems you do not own or have permission to test is illegal and unethical.
