"""Tests for subprocess utilities."""

from __future__ import annotations

import sys

from phantomdroid.utils.subprocess import CommandResult, run_command


class TestCommandResult:
    def test_success(self):
        result = CommandResult(command=["echo", "hello"], stdout="hello", stderr="", returncode=0)
        assert result.success is True

    def test_failure(self):
        result = CommandResult(command=["false"], stdout="", stderr="error", returncode=1)
        assert result.success is False

    def test_command_str(self):
        result = CommandResult(command=["ls", "-la"], stdout="", stderr="", returncode=0)
        assert result.command_str == "ls -la"


class TestRunCommand:
    def test_echo(self):
        if sys.platform == "win32":
            result = run_command(["cmd", "/c", "echo", "hello"], timeout=5)
        else:
            result = run_command(["echo", "hello"], timeout=5)
        assert result.success
        assert "hello" in result.stdout

    def test_timeout(self):
        if sys.platform != "win32":
            result = run_command(["sleep", "10"], timeout=1)
            assert result.timed_out
            assert result.returncode == -2

    def test_not_found(self):
        result = run_command(["nonexistent_command_xyz"], timeout=5)
        assert not result.success
        assert result.returncode == -1
