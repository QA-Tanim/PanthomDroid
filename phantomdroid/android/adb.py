"""PhantomDroid X - ADB wrapper with safe command execution."""

from __future__ import annotations

from phantomdroid.core.exceptions import ADBCommandError, ADBNotFoundError
from phantomdroid.utils.subprocess import CommandResult, run_adb_command


class ADB:
    """Safe ADB wrapper with structured output."""

    def __init__(self, adb_path: str = "adb", timeout: int = 30) -> None:
        self.adb_path = adb_path
        self.timeout = timeout

    def _run(
        self,
        args: list[str],
        device_id: str | None = None,
        timeout: int | None = None,
    ) -> CommandResult:
        """Run an ADB command."""
        result = run_adb_command(
            args,
            device_id=device_id,
            adb_path=self.adb_path,
            timeout=timeout or self.timeout,
        )
        if result.returncode == -1:
            raise ADBNotFoundError(f"ADB not found at: {self.adb_path}")
        return result

    def check_available(self) -> str:
        """Check if ADB is available and return version."""
        result = self._run(["version"])
        if not result.success:
            raise ADBNotFoundError("ADB not available")
        return result.stdout.splitlines()[0] if result.stdout else "Unknown"

    def list_devices(self) -> list[dict[str, str]]:
        """List connected devices."""
        result = self._run(["devices", "-l"])
        devices: list[dict[str, str]] = []

        for line in result.stdout.splitlines()[1:]:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            device: dict[str, str] = {
                "serial": parts[0],
                "state": parts[1],
            }
            for part in parts[2:]:
                if ":" in part:
                    key, value = part.split(":", 1)
                    device[key] = value
            devices.append(device)

        return devices

    def shell(
        self,
        command: str,
        device_id: str | None = None,
        timeout: int | None = None,
    ) -> str:
        """Run a shell command on the device."""
        result = self._run(
            ["shell", command],
            device_id=device_id,
            timeout=timeout,
        )
        if not result.success and result.stderr:
            raise ADBCommandError(
                f"Shell command failed: {command}",
                returncode=result.returncode,
                stderr=result.stderr,
            )
        return result.stdout

    def get_prop(self, prop: str, device_id: str | None = None) -> str:
        """Get a device property."""
        return self.shell(f"getprop {prop}", device_id)

    def device_info(self, device_id: str) -> dict[str, str]:
        """Get comprehensive device information."""
        props = {
            "serial": "ro.serialno",
            "model": "ro.product.model",
            "brand": "ro.product.brand",
            "android_version": "ro.build.version.release",
            "sdk_level": "ro.build.version.sdk",
            "security_patch": "ro.build.version.security_patch",
            "build_id": "ro.build.id",
            "fingerprint": "ro.build.fingerprint",
            "cpu_abi": "ro.product.cpu.abi",
        }
        info: dict[str, str] = {}
        for key, prop in props.items():
            try:
                info[key] = self.get_prop(prop, device_id)
            except ADBCommandError:
                info[key] = "Unknown"
        return info

    def is_rooted(self, device_id: str | None = None) -> bool:
        """Check if device is rooted."""
        checks = [
            "which su",
            "ls /system/xbin/su",
            "ls /system/bin/su",
            "ls /sbin/su",
        ]
        for cmd in checks:
            try:
                out = self.shell(cmd, device_id)
                if out and "not found" not in out.lower() and "no such" not in out.lower():
                    return True
            except ADBCommandError:
                continue
        return False

    def list_packages(
        self,
        device_id: str | None = None,
        filter_type: str = "all",
    ) -> list[str]:
        """List installed packages."""
        flags = {
            "all": [],
            "system": ["-s"],
            "third_party": ["-3"],
            "disabled": ["-d"],
        }
        args = ["pm", "list", "packages"] + flags.get(filter_type, [])
        out = self.shell(" ".join(args), device_id)
        return [
            line.replace("package:", "").strip()
            for line in out.splitlines()
            if line.startswith("package:")
        ]

    def dumpsys(self, service: str, device_id: str | None = None) -> str:
        """Run dumpsys for a service."""
        return self.shell(f"dumpsys {service}", device_id, timeout=60)

    def screenshot(self, device_id: str, remote_path: str = "/sdcard/phantomdroid_screen.png") -> bytes:
        """Take a screenshot and return the bytes."""
        self.shell(f"screencap -p {remote_path}", device_id)
        result = self._run(["exec-out", "cat", remote_path], device_id)
        self.shell(f"rm {remote_path}", device_id)
        return result.stdout.encode("latin-1") if result.stdout else b""

    def pull(self, remote: str, local: str, device_id: str | None = None) -> bool:
        """Pull a file from the device."""
        result = self._run(["pull", remote, local], device_id)
        return result.success

    def push(self, local: str, remote: str, device_id: str | None = None) -> bool:
        """Push a file to the device."""
        result = self._run(["push", local, remote], device_id)
        return result.success

    def logcat(
        self,
        device_id: str | None = None,
        lines: int = 200,
        grep: str | None = None,
    ) -> str:
        """Capture logcat output."""
        cmd = f"logcat -d -t {lines}"
        if grep:
            cmd += f" | grep -i '{grep}'"
        return self.shell(cmd, device_id)
