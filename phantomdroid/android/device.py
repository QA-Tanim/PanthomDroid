"""PhantomDroid X - Android device information."""

from __future__ import annotations

from phantomdroid.android.adb import ADB
from phantomdroid.core.models import DeviceInfo


class AndroidDevice:
    """Represents a connected Android device."""

    def __init__(self, adb: ADB, serial: str) -> None:
        self.adb = adb
        self.serial = serial
        self._info: DeviceInfo | None = None

    @property
    def info(self) -> DeviceInfo:
        if self._info is None:
            self._info = self._fetch_info()
        return self._info

    def _fetch_info(self) -> DeviceInfo:
        raw = self.adb.device_info(self.serial)
        sdk_str = raw.get("sdk_level", "0")
        try:
            sdk = int(sdk_str)
        except ValueError:
            sdk = 0

        is_emulator = self._detect_emulator(raw)
        is_rooted = self.adb.is_rooted(self.serial)

        return DeviceInfo(
            serial=self.serial,
            model=raw.get("model", "Unknown"),
            brand=raw.get("brand", "Unknown"),
            android_version=raw.get("android_version", "Unknown"),
            sdk_level=sdk,
            security_patch=raw.get("security_patch", "Unknown"),
            build_id=raw.get("build_id", "Unknown"),
            fingerprint=raw.get("fingerprint", "Unknown"),
            state="device",
            is_emulator=is_emulator,
            is_rooted=is_rooted,
        )

    def _detect_emulator(self, info: dict[str, str]) -> bool:
        """Detect if device is an emulator."""
        indicators = [
            "goldfish" in info.get("fingerprint", "").lower(),
            "ranchu" in info.get("fingerprint", "").lower(),
            "generic" in info.get("model", "").lower(),
            "emulator" in info.get("model", "").lower(),
            "sdk" in info.get("model", "").lower(),
        ]
        return any(indicators)

    def get_installed_packages(self, filter_type: str = "all") -> list[str]:
        return self.adb.list_packages(self.serial, filter_type)

    def get_logcat(self, lines: int = 200, grep: str | None = None) -> str:
        return self.adb.logcat(self.serial, lines, grep)

    def pull_file(self, remote: str, local: str) -> bool:
        return self.adb.pull(remote, local, self.serial)

    def push_file(self, local: str, remote: str) -> bool:
        return self.adb.push(local, remote, self.serial)

    def __repr__(self) -> str:
        return f"<AndroidDevice serial={self.serial!r} model={self.info.model!r}>"
