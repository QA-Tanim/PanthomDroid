"""PhantomDroid X - CLI commands."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from phantomdroid.analyzers.apk.code_analysis import CodeAnalysisCheck
from phantomdroid.analyzers.apk.components import ComponentAnalyzerCheck
from phantomdroid.analyzers.apk.crypto import CryptoAnalyzerCheck
from phantomdroid.analyzers.apk.manifest import ManifestAnalyzerCheck
from phantomdroid.analyzers.apk.network_security import NetworkSecurityCheck
from phantomdroid.analyzers.apk.permissions import PermissionAnalyzerCheck
from phantomdroid.analyzers.apk.resources import ResourceAnalyzerCheck
from phantomdroid.analyzers.apk.secrets import SecretScannerCheck
from phantomdroid.analyzers.network.ports import PortScanCheck
from phantomdroid.android.adb import ADB
from phantomdroid.android.device import AndroidDevice
from phantomdroid.android.manifest import (
    parse_components,
    parse_manifest,
    parse_manifest_fallback,
)
from phantomdroid.core.config import PhantomDroidConfig
from phantomdroid.core.exceptions import ADBNotFoundError
from phantomdroid.core.models import (
    ScanResult,
    Severity,
)
from phantomdroid.core.scanner import ScanContext, ScannerEngine
from phantomdroid.reporting.html_report import generate_html_report
from phantomdroid.reporting.json_report import generate_json_report
from phantomdroid.reporting.sarif_report import generate_sarif_report
from phantomdroid.utils.filesystem import compute_file_hash


def cmd_version() -> None:
    """Print version information."""
    from rich.console import Console
    console = Console()
    console.print("[bold magenta]PhantomDroid X[/] v[bold cyan]3.0.0[/]")
    console.print("[dim]Android Security & QA Automation Framework[/]")


def cmd_devices(args: Any) -> None:
    """List connected devices."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    adb = ADB()

    try:
        version = adb.check_available()
        console.print(f"[green]ADB:[/] {version}")
    except ADBNotFoundError:
        console.print("[red]ADB not found. Install Android Debug Bridge.[/]")
        return

    devices = adb.list_devices()
    if not devices:
        console.print("[yellow]No devices connected.[/]")
        return

    table = Table(title="Connected Devices")
    table.add_column("Serial", style="cyan")
    table.add_column("State", style="green")
    table.add_column("Model", style="yellow")
    table.add_column("Android", style="white")

    for dev in devices:
        try:
            device = AndroidDevice(adb, dev["serial"])
            info = device.info
            table.add_row(
                dev["serial"],
                dev.get("state", "unknown"),
                info.model,
                info.android_version,
            )
        except Exception:
            table.add_row(
                dev["serial"],
                dev.get("state", "unknown"),
                "Unknown",
                "Unknown",
            )

    console.print(table)


def cmd_apk_analyze(args: Any) -> None:
    """Analyze an APK file."""
    from rich.console import Console

    console = Console()
    apk_path = args.apk

    if not Path(apk_path).exists():
        console.print(f"[red]File not found: {apk_path}[/]")
        return

    console.print(f"[cyan]Analyzing:[/] {apk_path}")

    # Compute hashes
    with console.status("[cyan]Computing file hashes...[/]"):
        hashes = compute_file_hash(apk_path)

    # Read APK contents
    import zipfile
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            namelist = zf.namelist()

            # Parse manifest
            manifest_data = {}
            components = []
            if "AndroidManifest.xml" in namelist:
                try:
                    raw = zf.read("AndroidManifest.xml")
                    manifest_info = parse_manifest(raw)
                    manifest_data = manifest_info.to_dict()
                    components = parse_components(raw)
                except Exception:
                    # Fallback to text parsing
                    try:
                        text = zf.read("AndroidManifest.xml").decode("utf-8", errors="ignore")
                        manifest_info = parse_manifest_fallback(text)
                        manifest_data = manifest_info.to_dict()
                    except Exception:
                        console.print("[yellow]Warning: Could not parse manifest[/]")

            # Read scannable files
            scannable_extensions = {".xml", ".json", ".properties", ".js", ".html", ".txt"}
            file_contents: dict[str, str] = {}
            for entry in namelist:
                if any(entry.endswith(ext) for ext in scannable_extensions) or entry.endswith(".dex"):
                    try:
                        content = zf.read(entry).decode("utf-8", errors="ignore")
                        file_contents[entry] = content
                    except Exception:
                        pass

            native_libs = [n for n in namelist if n.endswith(".so")]

    except zipfile.BadZipFile:
        console.print("[red]Not a valid APK file.[/]")
        return

    # Build scan context
    context = ScanContext(
        target=apk_path,
        scan_type="apk",
        apk_path=apk_path,
        manifest_data=manifest_data,
        components=components,
        config=PhantomDroidConfig(),
        metadata={
            "hashes": hashes,
            "file_contents": file_contents,
            "scannable_files": file_contents,
            "native_libs": native_libs,
            "namelist": namelist,
        },
    )

    # Run analyzers
    engine = ScannerEngine()
    engine.register_many([
        ManifestAnalyzerCheck(),
        PermissionAnalyzerCheck(),
        ComponentAnalyzerCheck(),
        SecretScannerCheck(),
        CryptoAnalyzerCheck(),
        NetworkSecurityCheck(),
        ResourceAnalyzerCheck(),
        CodeAnalysisCheck(),
    ])

    with console.status("[cyan]Running security checks...[/]"):
        result = engine.run(context)

    result.manifest = manifest_info if "manifest_info" in dir() else None
    result.end_time = __import__("datetime").datetime.now()

    # Print summary
    _print_scan_summary(console, result)

    # Generate reports
    output_dir = Path(args.output) if hasattr(args, "output") and args.output else Path.cwd()

    if args.format in ("json", "both", "all"):
        json_path = output_dir / "phantomdroid_report.json"
        generate_json_report(result, str(json_path))
        console.print(f"[green]JSON report:[/] {json_path}")

    if args.format in ("html", "both", "all"):
        html_path = output_dir / "phantomdroid_report.html"
        generate_html_report(result, str(html_path))
        console.print(f"[green]HTML report:[/] {html_path}")

    if args.format in ("sarif", "all"):
        sarif_path = output_dir / "phantomdroid_report.sarif"
        generate_sarif_report(result, str(sarif_path))
        console.print(f"[green]SARIF report:[/] {sarif_path}")

    if args.format == "table":
        _print_findings_table(console, result)


def _resolve_device_id(args: Any) -> str | None:
    """Resolve the device serial from either the current or legacy CLI flag."""
    candidate = getattr(args, "serial", None)
    if candidate:
        return candidate
    return getattr(args, "device", None)


def cmd_scan_device(args: Any) -> None:
    """Scan a connected device."""
    from rich.console import Console

    console = Console()
    adb = ADB()
    device_id = _resolve_device_id(args)

    if not device_id:
        devices = adb.list_devices()
        if not devices:
            console.print("[red]No devices connected.[/]")
            return
        device_id = devices[0]["serial"]

    console.print(f"[cyan]Scanning device:[/] {device_id}")

    device = AndroidDevice(adb, device_id)
    info = device.info

    # Build scan context
    context = ScanContext(
        target=device_id,
        scan_type="device",
        device_serial=device_id,
        config=PhantomDroidConfig(),
        metadata={"device_info": info.to_dict()},
    )

    engine = ScannerEngine()
    engine.register(PortScanCheck())

    result = engine.run(context)
    result.device = info
    result.end_time = __import__("datetime").datetime.now()

    _print_scan_summary(console, result)


def cmd_gate(args: Any) -> None:
    """CI/CD security gate."""
    from rich.console import Console

    console = Console()
    results_path = args.results

    if not Path(results_path).exists():
        console.print(f"[red]Results file not found: {results_path}[/]")
        sys.exit(2)

    import json
    with open(results_path) as f:
        data = json.load(f)

    summary = data.get("summary", {})
    severity_counts = summary.get("severity_counts", {})

    fail_on = args.fail_on.upper() if args.fail_on else "HIGH"
    fail_on_confidence = args.confidence.upper() if args.confidence else None

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    threshold = severity_order.get(fail_on, 1)

    failed = False
    for sev, count in severity_counts.items():
        if count > 0 and severity_order.get(sev, 99) <= threshold:
            console.print(f"[red]FAIL: {count} {sev} finding(s) found[/]")
            failed = True

    if failed:
        console.print(f"[red]Gate failed: findings >= {fail_on} severity[/]")
        sys.exit(1)
    else:
        console.print(f"[green]Gate passed: no findings >= {fail_on} severity[/]")
        sys.exit(0)


def _print_scan_summary(console: Any, result: ScanResult) -> None:
    """Print scan summary."""
    from rich.panel import Panel

    counts = result.severity_counts
    summary_text = (
        f"Findings: {result.finding_count} total | "
        f"CRITICAL: {counts.get('CRITICAL', 0)} | "
        f"HIGH: {counts.get('HIGH', 0)} | "
        f"MEDIUM: {counts.get('MEDIUM', 0)} | "
        f"LOW: {counts.get('LOW', 0)} | "
        f"INFO: {counts.get('INFO', 0)}"
    )
    console.print(Panel(summary_text, title="[bold]Scan Summary[/]", border_style="cyan"))

    if result.errors:
        console.print(f"[yellow]Warnings: {len(result.errors)}[/]")


def _print_findings_table(console: Any, result: ScanResult) -> None:
    """Print findings as a table."""
    from rich.table import Table

    if not result.findings:
        console.print("[green]No findings.[/]")
        return

    sev_color = {
        "CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
        "LOW": "green", "INFO": "cyan",
    }

    t = Table(title="Security Findings")
    t.add_column("#", style="dim", width=4)
    t.add_column("Finding", style="white", min_width=30)
    t.add_column("Severity", width=12)
    t.add_column("Confidence", width=12)
    t.add_column("Status", width=12)

    sorted_findings = sorted(
        result.findings,
        key=lambda f: Severity[f.severity.value].order if hasattr(f.severity, "order") else 99,
    )

    for i, f in enumerate(sorted_findings, 1):
        sev = f.severity.value
        clr = sev_color.get(sev, "white")
        t.add_row(
            str(i),
            f.title,
            f"[{clr}]{sev}[/]",
            f.confidence.value,
            f.status.value,
        )

    console.print(t)
