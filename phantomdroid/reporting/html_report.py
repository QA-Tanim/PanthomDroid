"""PhantomDroid X - Safe HTML report generator."""

from __future__ import annotations

from datetime import datetime
from html import escape

from phantomdroid.core.models import Finding, ScanResult

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#ff2d55",
    "HIGH": "#ff6b35",
    "MEDIUM": "#f7b731",
    "LOW": "#2ecc71",
    "INFO": "#74b9ff",
}

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4
}


def generate_html_report(
    result: ScanResult,
    output_path: str,
    show_sensitive: bool = False,
) -> str:
    """Generate a safe HTML report from scan results.

    All user-provided content is HTML-escaped to prevent XSS.

    Args:
        result: ScanResult to report on.
        output_path: Path to write the HTML file.
        show_sensitive: Whether to show sensitive data.

    Returns:
        Path to the generated report.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = result.severity_counts

    sorted_findings = sorted(
        result.findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity.value, 99)
    )

    findings_html = _render_findings(sorted_findings, show_sensitive)
    manifest_html = _render_manifest(result)
    permissions_html = _render_permissions(result)
    components_html = _render_components(result)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhantomDroid X - Security Report</title>
<style>
  :root {{
    --bg: #0a0a0f; --surface: #12121a; --surface2: #1a1a26;
    --border: #2a2a3d; --accent: #8b5cf6; --accent2: #ec4899;
    --text: #e4e4f0; --dim: #6b6b8a;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    line-height: 1.6;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
  header {{
    background: linear-gradient(135deg, #1a0533, #0d0d1a, #1a0533);
    border-bottom: 2px solid var(--accent);
    padding: 2rem; text-align: center;
  }}
  h1 {{ font-size: 2rem; color: var(--accent); }}
  .subtitle {{ color: var(--dim); margin-top: 0.5rem; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 2rem 0; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; text-align: center; }}
  .stat-num {{ font-size: 2rem; font-weight: 700; }}
  .stat-label {{ color: var(--dim); font-size: 0.85rem; text-transform: uppercase; }}
  section {{ margin: 2rem 0; }}
  h2 {{ color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; margin-bottom: 1rem; }}
  .finding {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }}
  .finding:hover {{ border-color: var(--accent); }}
  .finding-header {{ display: flex; justify-content: space-between; align-items: center; }}
  .finding-title {{ font-weight: 700; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }}
  .finding-detail {{ color: var(--dim); font-size: 0.9rem; margin-top: 0.5rem; }}
  .evidence {{ background: var(--surface2); border-radius: 4px; padding: 0.5rem; margin-top: 0.5rem; font-family: monospace; font-size: 0.8rem; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ padding: 0.5rem; text-align: left; border-bottom: 1px solid var(--border); }}
  th {{ background: var(--surface2); color: var(--dim); text-transform: uppercase; font-size: 0.75rem; }}
  .disclaimer {{ background: rgba(255,45,85,0.1); border: 1px solid rgba(255,45,85,0.3); border-radius: 8px; padding: 1rem; margin-bottom: 2rem; color: #ff6b6b; }}
  footer {{ text-align: center; color: var(--dim); padding: 2rem; border-top: 1px solid var(--border); margin-top: 2rem; }}
</style>
</head>
<body>
<header>
  <h1>PhantomDroid X Security Report</h1>
  <div class="subtitle">Target: {escape(result.target)} | Generated: {escape(timestamp)}</div>
</header>
<div class="container">
  <div class="disclaimer">
    This report is intended for authorized security testing only.
    Unauthorized use is illegal and unethical.
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-num" style="color:{SEVERITY_COLORS.get('CRITICAL', '#fff')}">{counts.get('CRITICAL', 0)}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-num" style="color:{SEVERITY_COLORS.get('HIGH', '#fff')}">{counts.get('HIGH', 0)}</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-num" style="color:{SEVERITY_COLORS.get('MEDIUM', '#fff')}">{counts.get('MEDIUM', 0)}</div><div class="stat-label">Medium</div></div>
    <div class="stat"><div class="stat-num" style="color:{SEVERITY_COLORS.get('LOW', '#fff')}">{counts.get('LOW', 0)}</div><div class="stat-label">Low</div></div>
    <div class="stat"><div class="stat-num" style="color:{SEVERITY_COLORS.get('INFO', '#fff')}">{counts.get('INFO', 0)}</div><div class="stat-label">Info</div></div>
    <div class="stat"><div class="stat-num" style="color:var(--accent)">{result.finding_count}</div><div class="stat-label">Total</div></div>
  </div>

  <section>
    <h2>Security Findings</h2>
    {findings_html}
  </section>

  {manifest_html}
  {permissions_html}
  {components_html}
</div>
<footer>
  <p>PhantomDroid X v3.0.0 | For authorized use only</p>
</footer>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path


def _render_findings(findings: list[Finding], show_sensitive: bool) -> str:
    if not findings:
        return "<p>No findings.</p>"

    parts: list[str] = []
    for f in findings:
        color = SEVERITY_COLORS.get(f.severity.value, "#fff")
        badge = f'<span class="badge" style="background:{color}22;color:{color};border:1px solid {color}55">{escape(f.severity.value)}</span>'
        conf_badge = f'<span class="badge" style="background:#8b5cf622;color:#8b5cf6;border:1px solid #8b5cf655">{escape(f.confidence.value)}</span>'

        evidence_html = ""
        if f.evidence:
            ev_items = []
            for ev in f.evidence:
                val = escape(ev.value) if ev.value and show_sensitive else (escape(ev.value) if ev.value else "")
                ev_items.append(f'<div>{escape(ev.type)}: {escape(ev.source)} - {escape(ev.attribute or "")} = {val}</div>')
            evidence_html = f'<div class="evidence">{"".join(ev_items)}</div>'

        cwe_html = f' | <span>{escape(f.cwe)}</span>' if f.cwe else ""

        parts.append(f"""<div class="finding">
  <div class="finding-header">
    <span class="finding-title">{escape(f.title)}{cwe_html}</span>
    <span>{badge} {conf_badge}</span>
  </div>
  <div class="finding-detail">{escape(f.description)}</div>
  {evidence_html}
  {"<div class='finding-detail'><strong>Remediation:</strong> " + escape(f.remediation) + "</div>" if f.remediation else ""}
</div>""")

    return "\n".join(parts)


def _render_manifest(result: ScanResult) -> str:
    if not result.manifest:
        return ""
    m = result.manifest
    return f"""<section>
<h2>Manifest Information</h2>
<table>
<tr><th>Package</th><td>{escape(m.package_name)}</td></tr>
<tr><th>Version</th><td>{escape(m.version_name)} ({m.version_code})</td></tr>
<tr><th>Min SDK</th><td>{m.min_sdk}</td></tr>
<tr><th>Target SDK</th><td>{m.target_sdk}</td></tr>
<tr><th>Debuggable</th><td>{"Yes" if m.debuggable else "No"}</td></tr>
<tr><th>Allow Backup</th><td>{"Yes" if m.allow_backup else "No"}</td></tr>
</table>
</section>"""


def _render_permissions(result: ScanResult) -> str:
    if not result.permissions:
        return ""
    rows = []
    for p in result.permissions:
        rows.append(f"<tr><td>{escape(p.name)}</td><td>{escape(p.protection_level.value)}</td></tr>")
    return f"""<section>
<h2>Permissions ({len(result.permissions)})</h2>
<table><thead><tr><th>Permission</th><th>Protection Level</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table>
</section>"""


def _render_components(result: ScanResult) -> str:
    if not result.components:
        return ""
    rows = []
    for c in result.components:
        rows.append(f"<tr><td>{escape(c.component_type.value)}</td><td>{escape(c.name)}</td><td>{escape(c.exported.value)}</td></tr>")
    return f"""<section>
<h2>Components ({len(result.components)})</h2>
<table><thead><tr><th>Type</th><th>Name</th><th>Exported</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table>
</section>"""
