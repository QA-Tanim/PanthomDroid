"""Tests for CLI."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from phantomdroid.cli import commands
from phantomdroid.cli.main import build_parser, main


class TestBuildParser:
    def test_version(self):
        parser = build_parser()
        args = parser.parse_args(["version"])
        assert args.command == "version"

    def test_devices(self):
        parser = build_parser()
        args = parser.parse_args(["devices"])
        assert args.command == "devices"

    def test_apk_analyze(self):
        parser = build_parser()
        args = parser.parse_args(["apk", "analyze", "test.apk"])
        assert args.command == "apk"
        assert args.apk == "test.apk"
        assert args.format == "html"

    def test_scan_device(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "device"])
        assert args.command == "scan"
        assert args.scan_command == "device"

    def test_gate(self):
        parser = build_parser()
        args = parser.parse_args(["gate", "results.json", "--fail-on", "high"])
        assert args.command == "gate"
        assert args.fail_on == "high"

    def test_scan_device_serial(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "device", "--serial", "abc123"])
        assert args.command == "scan"
        assert args.scan_command == "device"
        assert args.serial == "abc123"

    def test_apk_format(self):
        parser = build_parser()
        args = parser.parse_args(["apk", "analyze", "test.apk", "--format", "sarif"])
        assert args.format == "sarif"


class TestMain:
    def test_no_args(self):
        # Should print help and return 0
        result = main([])
        assert result == 0

    def test_version(self, capsys):
        result = main(["version"])
        assert result == 0

    def test_invalid_command(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["nonexistent"])
        assert exc_info.value.code == 2


def test_scan_device_accepts_serial_option_only(monkeypatch):
    class DummyADB:
        def __init__(self):
            self.calls = []

        def list_devices(self):
            return [{"serial": "abc123"}]

    class DummyInfo:
        def to_dict(self):
            return {"serial": "abc123"}

    class DummyDevice:
        def __init__(self, adb, serial):
            self.info = DummyInfo()

    class DummyScanner:
        def register(self, *args, **kwargs):
            return None

        def run(self, context):
            return SimpleNamespace(
                findings=[],
                severity_counts={},
                errors=[],
                finding_count=0,
                device=None,
                end_time=None,
            )

    monkeypatch.setattr(commands, "ADB", DummyADB)
    monkeypatch.setattr(commands, "AndroidDevice", DummyDevice)
    monkeypatch.setattr(commands, "ScannerEngine", DummyScanner)
    monkeypatch.setattr(commands, "ScanContext", lambda **kwargs: SimpleNamespace(**kwargs))

    args = SimpleNamespace(serial="abc123")
    commands.cmd_scan_device(args)
