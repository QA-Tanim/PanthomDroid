# Changelog

## [3.0.0] - 2026-09-28

### Added
- Complete rewrite as PhantomDroid X
- Modular architecture with clean separation of concerns
- Binary XML manifest parser (Android Binary XML format)
- Evidence-based finding model with confidence levels
- Secret detection engine with entropy analysis and redaction
- Permission analyzer with proper Android permission classification
- Exported component analyzer with context-aware detection
- Network security configuration analyzer
- Cryptographic analysis for weak crypto patterns
- Code pattern analysis for sensitive API usage
- SARIF 2.1.0 report output for CI/CD integration
- HTML report with safe HTML escaping
- JSON report with structured output
- CI/CD security gate command
- Comprehensive pytest test suite
- Type hints throughout codebase
- Structured logging
- Cross-platform support (Windows, Linux, macOS)

### Changed
- Architecture: Monolithic modules -> Modular package structure
- Finding model: Dict-based -> Typed dataclass with evidence
- Manifest parsing: UTF-8 text decode -> Binary XML parser
- Secret detection: Regex only -> Regex + entropy + context
- HTML reports: Raw injection -> HTML-escaped output
- ADB wrapper: 4 duplicated implementations -> Single safe wrapper
- Permission classification: Arbitrary severity -> Proper Android classification

### Fixed
- AndroidManifest.xml parsing now handles binary XML format
- HTML reports no longer vulnerable to XSS via finding content
- Secret snippets are now redacted by default
- CVE mapping now considers security patch level
- Exported component detection considers intent-filter implications
- SSL pinning detection no longer relies on logcat word matching

### Security
- All user input is HTML-escaped in reports
- Secrets are redacted in evidence by default
- Subprocess calls use argument lists (no shell injection)
- File extraction prevents path traversal (Zip Slip)
- No credentials or secrets logged

## [2.0.0] - Previous Version
- Original PhantomDroid release
- Interactive menu-driven UI
- Basic APK static analysis
- Network scanning
- Exploit engine
- Payload generation
