"""PhantomDroid X - Safe subprocess execution."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass


@dataclass
class CommandResult:
    """Result of a subprocess command."""
    command: list[str]
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.returncode == 0

    @property
    def command_str(self) -> str:
        return " ".join(self.command)


def run_command(
    command: list[str],
    timeout: int = 30,
    capture_output: bool = True,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Execute a command safely with timeout and error handling.

    Args:
        command: Command and arguments as a list (no shell injection).
        timeout: Timeout in seconds.
        capture_output: Whether to capture stdout/stderr.
        cwd: Working directory.
        env: Environment variables.

    Returns:
        CommandResult with stdout, stderr, returncode.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
        )
        return CommandResult(
            command=command,
            stdout=result.stdout.strip() if result.stdout else "",
            stderr=result.stderr.strip() if result.stderr else "",
            returncode=result.returncode,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            command=command,
            stdout="",
            stderr=f"Command timed out after {timeout}s",
            returncode=-2,
            timed_out=True,
        )
    except FileNotFoundError:
        return CommandResult(
            command=command,
            stdout="",
            stderr=f"Command not found: {command[0]}",
            returncode=-1,
        )
    except Exception as e:
        return CommandResult(
            command=command,
            stdout="",
            stderr=str(e),
            returncode=-3,
        )


def run_adb_command(
    args: list[str],
    device_id: str | None = None,
    adb_path: str = "adb",
    timeout: int = 30,
) -> CommandResult:
    """Execute an ADB command safely.

    Args:
        args: ADB command arguments (e.g., ["shell", "ls"]).
        device_id: Target device serial.
        adb_path: Path to adb binary.
        timeout: Timeout in seconds.

    Returns:
        CommandResult.
    """
    cmd = [adb_path]
    if device_id:
        cmd.extend(["-s", device_id])
    cmd.extend(args)
    return run_command(cmd, timeout=timeout)


def is_command_available(command: str) -> bool:
    """Check if a command is available on the system."""
    try:
        result = subprocess.run(
            [command, "--version"] if sys.platform != "win32" else [command, "/?"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
