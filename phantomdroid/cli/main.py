"""PhantomDroid X - CLI main entry point."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from phantomdroid import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    p = argparse.ArgumentParser(
        prog="phantomdroid",
        description=f"PhantomDroid X v{__version__} - Android Security & QA Automation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  phantomdroid devices
  phantomdroid apk analyze app.apk
  phantomdroid apk analyze app.apk --format html
  phantomdroid scan device
  phantomdroid scan device --serial DEVICE_ID
  phantomdroid gate results.json --fail-on high
  phantomdroid version
        """,
    )

    p.add_argument("--version", "-v", action="version", version=f"PhantomDroid X {__version__}")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    p.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    p.add_argument("--verbose", action="store_true", help="Verbose output")

    subparsers = p.add_subparsers(dest="command", help="Available commands")

    # Version command
    subparsers.add_parser("version", help="Show version information")

    # Devices command
    devices_parser = subparsers.add_parser("devices", help="List connected devices")
    devices_parser.add_argument("--serial", "-s", help="Device serial number")

    # APK commands
    apk_parser = subparsers.add_parser("apk", help="APK analysis commands")
    apk_sub = apk_parser.add_subparsers(dest="apk_command")

    analyze_parser = apk_sub.add_parser("analyze", help="Analyze an APK file")
    analyze_parser.add_argument("apk", help="Path to APK file")
    analyze_parser.add_argument(
        "--format", "-f",
        choices=["json", "html", "sarif", "both", "all", "table"],
        default="html",
        help="Output format (default: html)",
    )
    analyze_parser.add_argument("--output", "-o", help="Output directory")
    analyze_parser.add_argument("--show-sensitive", action="store_true", help="Show sensitive data in reports")

    # Scan commands
    scan_parser = subparsers.add_parser("scan", help="Scan commands")
    scan_sub = scan_parser.add_subparsers(dest="scan_command")

    device_scan = scan_sub.add_parser("device", help="Scan a connected device")
    device_scan.add_argument("--serial", "-s", "--device", help="Device serial number")
    device_scan.add_argument(
        "--format", "-f",
        choices=["json", "html", "sarif", "both", "all", "table"],
        default="table",
        help="Output format",
    )
    device_scan.add_argument("--output", "-o", help="Output directory")

    # Gate command
    gate_parser = subparsers.add_parser("gate", help="CI/CD security gate")
    gate_parser.add_argument("results", help="Path to results JSON file")
    gate_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default="high",
        help="Fail if findings at or above this severity (default: high)",
    )
    gate_parser.add_argument(
        "--confidence",
        choices=["high", "medium", "low"],
        help="Additional confidence threshold",
    )

    return p


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    try:
        if args.command == "version":
            from phantomdroid.cli.commands import cmd_version
            cmd_version()
        elif args.command == "devices":
            from phantomdroid.cli.commands import cmd_devices
            cmd_devices(args)
        elif args.command == "apk":
            if args.apk_command == "analyze":
                from phantomdroid.cli.commands import cmd_apk_analyze
                cmd_apk_analyze(args)
            else:
                parser.parse_args(["apk", "--help"])
        elif args.command == "scan":
            if args.scan_command == "device":
                from phantomdroid.cli.commands import cmd_scan_device
                cmd_scan_device(args)
            else:
                parser.parse_args(["scan", "--help"])
        elif args.command == "gate":
            from phantomdroid.cli.commands import cmd_gate
            cmd_gate(args)
        else:
            parser.print_help()
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
