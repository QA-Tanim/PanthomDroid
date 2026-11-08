"""Tests for configuration management."""

from __future__ import annotations

from pathlib import Path

from phantomdroid.core.config import (
    ADBConfig,
    PhantomDroidConfig,
    ScanConfig,
    SecretScanConfig,
)


class TestScanConfig:
    def test_defaults(self):
        config = ScanConfig()
        assert config.timeout == 30
        assert config.enable_caching is True
        assert config.show_sensitive is False

    def test_to_dict(self):
        config = ScanConfig(timeout=60)
        d = config.to_dict()
        assert d["timeout"] == 60


class TestADBConfig:
    def test_from_env(self):
        config = ADBConfig.from_env()
        assert isinstance(config.adb_path, str)
        assert config.timeout > 0


class TestSecretScanConfig:
    def test_defaults(self):
        config = SecretScanConfig()
        assert config.enable_entropy is True
        assert config.min_entropy == 3.0
        assert config.redact_secrets is True


class TestPhantomDroidConfig:
    def test_defaults(self):
        config = PhantomDroidConfig()
        assert config.scan.timeout == 30
        assert config.secrets.enable_entropy is True

    def test_save_and_load(self, tmp_path: Path):
        config = PhantomDroidConfig()
        config.scan.timeout = 60
        config_path = tmp_path / "config.json"
        config.save(config_path)

        loaded = PhantomDroidConfig.from_file(config_path)
        assert loaded.scan.timeout == 60

    def test_load_nonexistent(self):
        config = PhantomDroidConfig.from_file("/nonexistent/config.json")
        assert config.scan.timeout == 30  # defaults

    def test_to_dict(self):
        config = PhantomDroidConfig()
        d = config.to_dict()
        assert "scan" in d
        assert "adb" in d
        assert "secrets" in d
