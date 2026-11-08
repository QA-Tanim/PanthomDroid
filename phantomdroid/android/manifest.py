"""PhantomDroid X - Android Binary XML manifest parser."""

from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from phantomdroid.core.exceptions import ManifestParseError
from phantomdroid.core.models import (
    ComponentInfo,
    ComponentType,
    ExportedState,
    ManifestInfo,
)


class AXMLError(Exception):
    """Android Binary XML parsing error."""


@dataclass
class AXMLStringPool:
    """AXML string pool."""
    strings: list[str] = field(default_factory=list)


class AndroidBinaryXMLParser:
    """Parser for Android Binary XML (AXML) format.

    This parser handles the compiled binary XML format used in APK files
    for AndroidManifest.xml and other XML resources.
    """

    # AXML constants
    AXML_MAGIC = 0x00080003
    CHUNK_TYPE_STRING_POOL = 0x001C0001
    CHUNK_TYPE_START_NAMESPACE = 0x00100100
    CHUNK_TYPE_END_NAMESPACE = 0x00100101
    CHUNK_TYPE_START_ELEMENT = 0x00100102
    CHUNK_TYPE_END_ELEMENT = 0x00100103
    CHUNK_TYPE_TEXT = 0x00100104

    # Attribute value types
    TYPE_NULL = 0x00
    TYPE_REFERENCE = 0x01
    TYPE_ATTRIBUTE = 0x02
    TYPE_STRING = 0x03
    TYPE_FLOAT = 0x04
    TYPE_DIMENSION = 0x05
    TYPE_FRACTION = 0x06
    TYPE_INT_DEC = 0x10
    TYPE_INT_HEX = 0x11
    TYPE_INT_BOOLEAN = 0x12

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self.string_pool: list[str] = []
        self.namespaces: dict[str, str] = {}

    def parse(self) -> ET.Element:
        """Parse AXML data and return an ElementTree Element."""
        try:
            return self._parse_axml()
        except Exception as err:
            raise ManifestParseError(f"Failed to parse Android Binary XML: {err}") from err

    def _read_uint32(self) -> int:
        if self.pos + 4 > len(self.data):
            raise AXMLError("Unexpected end of data")
        value = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return value

    def _read_int32(self) -> int:
        if self.pos + 4 > len(self.data):
            raise AXMLError("Unexpected end of data")
        value = struct.unpack_from("<i", self.data, self.pos)[0]
        self.pos += 4
        return value

    def _read_uint16(self) -> int:
        if self.pos + 2 > len(self.data):
            raise AXMLError("Unexpected end of data")
        value = struct.unpack_from("<H", self.data, self.pos)[0]
        self.pos += 2
        return value

    def _parse_axml(self) -> ET.Element:
        """Parse the AXML structure."""
        # File header
        magic = self._read_uint32()
        if magic != self.AXML_MAGIC:
            # Try to detect if this is plain XML instead
            raise AXMLError(f"Invalid AXML magic: 0x{magic:08X}")

        file_size = self._read_uint32()
        string_pool_chunk_type = self._read_uint32()

        if string_pool_chunk_type != self.CHUNK_TYPE_STRING_POOL:
            raise AXMLError(f"Expected string pool chunk, got 0x{string_pool_chunk_type:08X}")

        # Parse string pool
        self._parse_string_pool()

        # Parse remaining chunks
        root_element: ET.Element | None = None
        element_stack: list[ET.Element] = []

        while self.pos < len(self.data) - 8:
            try:
                chunk_type = self._read_uint32()
                chunk_size = self._read_uint32()
            except AXMLError:
                break

            if chunk_type == self.CHUNK_TYPE_START_ELEMENT:
                element = self._parse_start_element(chunk_size)
                if element_stack:
                    element_stack[-1].append(element)
                element_stack.append(element)
                if root_element is None:
                    root_element = element

            elif chunk_type == self.CHUNK_TYPE_END_ELEMENT:
                if element_stack:
                    element_stack.pop()

            elif chunk_type == self.CHUNK_TYPE_TEXT:
                # Skip text chunk
                self.pos += chunk_size - 8

            elif chunk_type == self.CHUNK_TYPE_START_NAMESPACE:
                self._parse_namespace()

            elif chunk_type == self.CHUNK_TYPE_END_NAMESPACE:
                self.pos += chunk_size - 8

            else:
                # Unknown chunk, skip
                self.pos += chunk_size - 8

        if root_element is None:
            raise AXMLError("No root element found in AXML")

        return root_element

    def _parse_string_pool(self) -> None:
        """Parse the string pool chunk."""
        chunk_size = self._read_uint32()
        string_count = self._read_uint32()
        style_count = self._read_uint32()
        flags = self._read_uint32()
        strings_start = self._read_uint32()
        styles_start = self._read_uint32()

        is_utf8 = bool(flags & (1 << 8))

        # Read string offsets
        offsets: list[int] = []
        for _ in range(string_count):
            offsets.append(self._read_uint32())

        # Read strings
        string_data_start = self.pos
        for offset in offsets:
            self.pos = string_data_start + offset
            string = self._read_utf8_string() if is_utf8 else self._read_utf16_string()
            self.string_pool.append(string)

        # Move past string pool
        self.pos = string_data_start + (chunk_size - 8 - string_count * 4 - 16)

    def _read_utf8_string(self) -> str:
        """Read a UTF-8 string from the string pool."""
        # Skip character count (1 or 2 bytes)
        byte_count = self._read_uint16()
        if byte_count & 0x80:
            byte_count = ((byte_count & 0x7F) << 8) | self._read_uint16()

        # Read byte count
        str_byte_count = self._read_uint16()
        if str_byte_count & 0x80:
            str_byte_count = ((str_byte_count & 0x7F) << 8) | self._read_uint16()

        # Read string bytes
        if self.pos + str_byte_count > len(self.data):
            return ""
        string_bytes = self.data[self.pos : self.pos + str_byte_count]
        self.pos += str_byte_count

        try:
            return string_bytes.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _read_utf16_string(self) -> str:
        """Read a UTF-16 string from the string pool."""
        # Read character count (2 bytes)
        char_count = self._read_uint16()
        if char_count & 0x8000:
            char_count = ((char_count & 0x7FFF) << 16) | self._read_uint16()

        # Read string data (char_count * 2 bytes + null terminator)
        byte_count = char_count * 2
        if self.pos + byte_count > len(self.data):
            return ""
        string_bytes = self.data[self.pos : self.pos + byte_count]
        self.pos += byte_count

        # Skip null terminator
        if self.pos < len(self.data) and self.data[self.pos : self.pos + 2] == b"\x00\x00":
            self.pos += 2

        try:
            return string_bytes.decode("utf-16-le", errors="replace")
        except Exception:
            return ""

    def _parse_start_element(self, chunk_size: int) -> ET.Element:
        """Parse a start element chunk."""
        line_number = self._read_int32()
        comment = self._read_int32()

        # NS and name indices
        ns_idx = self._read_int32()
        name_idx = self._read_int32()

        # Attribute start, size, count
        attr_start = self._read_uint16()
        attr_size = self._read_uint16()
        attr_count = self._read_uint16()
        id_index = self._read_uint16()
        class_index = self._read_uint16()
        style_index = self._read_uint16()

        name = self._get_string(name_idx)
        namespace = self._get_string(ns_idx) if ns_idx >= 0 else None

        # Parse attributes
        attributes: dict[str, str] = {}
        for _ in range(attr_count):
            attr_ns_idx = self._read_int32()
            attr_name_idx = self._read_uint32()
            attr_value_idx = self._read_uint32()
            attr_type = self._read_uint8()
            attr_res0 = self._read_uint8()
            attr_data = self._read_uint32()

            attr_name = self._get_string(attr_name_idx)
            attr_ns = self._get_string(attr_ns_idx) if attr_ns_idx >= 0 else None

            # Get attribute value
            if attr_type == self.TYPE_STRING:
                attr_value = self._get_string(attr_value_idx)
            elif attr_type == self.TYPE_INT_DEC:
                attr_value = str(attr_data)
            elif attr_type == self.TYPE_INT_HEX:
                attr_value = f"0x{attr_data:08x}"
            elif attr_type == self.TYPE_INT_BOOLEAN:
                attr_value = "true" if attr_data != 0 else "false"
            elif attr_type == self.TYPE_REFERENCE:
                attr_value = f"@0x{attr_data:08x}"
            else:
                attr_value = self._get_string(attr_value_idx) if attr_value_idx >= 0 else ""

            # Build full attribute name with namespace
            if attr_ns:
                # Extract prefix from namespace
                prefix = None
                for p, uri in self.namespaces.items():
                    if uri == attr_ns:
                        prefix = p
                        break
                if prefix:
                    attr_name = f"{prefix}:{attr_name}"

            attributes[attr_name] = attr_value

        # Create element
        tag = name
        if namespace:
            tag = f"{{{namespace}}}{name}"

        element = ET.Element(tag, attributes)
        return element

    def _parse_namespace(self) -> None:
        """Parse a namespace chunk."""
        line_number = self._read_int32()
        comment = self._read_int32()
        prefix_idx = self._read_int32()
        uri_idx = self._read_int32()

        prefix = self._get_string(prefix_idx)
        uri = self._get_string(uri_idx)
        self.namespaces[prefix] = uri

    def _get_string(self, index: int) -> str:
        """Get string from pool by index."""
        if 0 <= index < len(self.string_pool):
            return self.string_pool[index]
        return ""


def parse_manifest(xml_data: bytes) -> ManifestInfo:
    """Parse AndroidManifest.xml from binary XML data.

    Args:
        xml_data: Raw bytes of AndroidManifest.xml.

    Returns:
        ManifestInfo with parsed manifest data.
    """
    info = ManifestInfo()

    try:
        parser = AndroidBinaryXMLParser(xml_data)
        root = parser.parse()
    except (ManifestParseError, AXMLError):
        # Fallback: try parsing as plain text XML
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_data)
        except Exception as err:
            raise ManifestParseError("Cannot parse manifest - not valid binary or text XML") from err

    # Extract package name
    info.package_name = root.get("package", "")

    # Extract SDK versions
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        info.min_sdk = int(uses_sdk.get("android:minSdkVersion", "0") or "0")
        info.target_sdk = int(uses_sdk.get("android:targetSdkVersion", "0") or "0")

    # Extract application attributes
    app = root.find("application")
    if app is not None:
        info.debuggable = app.get("android:debuggable", "false").lower() == "true"
        info.allow_backup = app.get("android:allowBackup", "true").lower() == "true"
        nsc = app.get("android:networkSecurityConfig", "")
        if nsc:
            info.network_security_config = nsc

    # Extract permissions
    for perm in root.findall("uses-permission"):
        perm_name = perm.get("android:name", "")
        if perm_name:
            info.permissions.append(perm_name)

    # Extract features
    for feature in root.findall("uses-feature"):
        feat_name = feature.get("android:name", "")
        if feat_name:
            info.features.append(feat_name)

    # Extract queries
    for query in root.findall("queries"):
        for pkg in query.findall("package"):
            pkg_name = pkg.get("name", "")
            if pkg_name:
                info.queries.append(pkg_name)

    return info


def parse_components(xml_data: bytes) -> list[ComponentInfo]:
    """Parse components from AndroidManifest.xml binary data.

    Args:
        xml_data: Raw bytes of AndroidManifest.xml.

    Returns:
        List of ComponentInfo.
    """
    components: list[ComponentInfo] = []

    try:
        parser = AndroidBinaryXMLParser(xml_data)
        root = parser.parse()
    except (ManifestParseError, AXMLError):
        try:
            import xml.etree.ElementTree as ET
            # Register Android namespace for proper attribute parsing
            ET.register_namespace("android", "http://schemas.android.com/apk/res/android")
            root = ET.fromstring(xml_data)
        except Exception:
            return components

    app = root.find("application")
    if app is None:
        # Also try without namespace
        for child in root:
            if child.tag.endswith("application") or child.tag == "application":
                app = child
                break
    if app is None:
        return components

    component_map = {
        "activity": ComponentType.ACTIVITY,
        "service": ComponentType.SERVICE,
        "receiver": ComponentType.RECEIVER,
        "provider": ComponentType.PROVIDER,
    }

    component_tags = {
        "activity": ComponentType.ACTIVITY,
        "service": ComponentType.SERVICE,
        "receiver": ComponentType.RECEIVER,
        "provider": ComponentType.PROVIDER,
    }

    ns = "http://schemas.android.com/apk/res/android"

    for comp_type_str, comp_type in component_tags.items():
        # Try both with and without namespace
        elements = app.findall(comp_type_str)
        if not elements:
            elements = app.findall(f"{{{ns}}}{comp_type_str}")
        for elem in elements:
            name = elem.get("android:name") or elem.get(f"{{{ns}}}name", "")
            if not name:
                continue

            exported_str = elem.get("android:exported") or elem.get(f"{{{ns}}}exported", "")
            permission = elem.get("android:permission") or elem.get(f"{{{ns}}}permission", "")
            task_affinity = elem.get("android:taskAffinity") or elem.get(f"{{{ns}}}taskAffinity", "")
            launch_mode = elem.get("android:launchMode") or elem.get(f"{{{ns}}}launchMode", "")
            enabled_str = elem.get("android:enabled") or elem.get(f"{{{ns}}}enabled", "true")
            enabled = enabled_str.lower() == "true" if enabled_str else True

            # Determine exported state
            if exported_str.lower() == "true":
                exported = ExportedState.EXPORTED_TRUE
            elif exported_str.lower() == "false":
                exported = ExportedState.EXPORTED_FALSE
            elif exported_str == "":
                # No explicit exported attribute
                # For components with intent-filters, exported defaults to true (API 31+)
                intent_filters = elem.findall("intent-filter")
                if intent_filters:
                    exported = ExportedState.IMPLICITLY_EXPORTED
                else:
                    exported = ExportedState.UNKNOWN
            else:
                exported = ExportedState.UNKNOWN

            # Parse intent filters
            intent_filters = []
            for intent_filter in elem.findall("intent-filter") or elem.findall(f"{{{ns}}}intent-filter"):
                filter_info: dict[str, Any] = {}
                actions = [a.get("android:name") or a.get(f"{{{ns}}}name", "") for a in (intent_filter.findall("action") or intent_filter.findall(f"{{{ns}}}action"))]
                categories = [c.get("android:name") or c.get(f"{{{ns}}}name", "") for c in (intent_filter.findall("category") or intent_filter.findall(f"{{{ns}}}category"))]
                data_elements = []
                for data in (intent_filter.findall("data") or intent_filter.findall(f"{{{ns}}}data")):
                    data_info: dict[str, str] = {}
                    for attr in ["android:scheme", "android:host", "android:path", "android:pathPrefix", "android:pathPattern", "android:mimeType"]:
                        ns_attr = f"{{{ns}}}{attr.split(':')[-1]}"
                        val = data.get(attr) or data.get(ns_attr, "")
                        if val:
                            data_info[attr.split(":")[-1]] = val
                    if data_info:
                        data_elements.append(data_info)

                filter_info["actions"] = actions
                filter_info["categories"] = categories
                if data_elements:
                    filter_info["data"] = data_elements
                intent_filters.append(filter_info)

            comp = ComponentInfo(
                name=name,
                component_type=comp_type,
                exported=exported,
                permission=permission or None,
                intent_filters=intent_filters,
                task_affinity=task_affinity or None,
                launch_mode=launch_mode or None,
                enabled=enabled,
                exported_explicit=exported_str.lower() == "true" if exported_str else None,
            )
            components.append(comp)

    return components


def parse_manifest_fallback(manifest_text: str) -> ManifestInfo:
    """Parse manifest from text (for non-binary XML or degraded mode).

    This is a fallback parser that works on raw text when binary parsing fails.
    It is less reliable than the binary parser.
    """
    import re

    info = ManifestInfo()

    pkg_match = re.search(r'package="([^"]+)"', manifest_text)
    if pkg_match:
        info.package_name = pkg_match.group(1)

    min_sdk_match = re.search(r'android:minSdkVersion="(\d+)"', manifest_text)
    if min_sdk_match:
        info.min_sdk = int(min_sdk_match.group(1))

    target_sdk_match = re.search(r'android:targetSdkVersion="(\d+)"', manifest_text)
    if target_sdk_match:
        info.target_sdk = int(target_sdk_match.group(1))

    info.debuggable = "android:debuggable=\"true\"" in manifest_text
    info.allow_backup = "android:allowBackup=\"true\"" in manifest_text

    nsc_match = re.search(r'android:networkSecurityConfig="([^"]+)"', manifest_text)
    if nsc_match:
        info.network_security_config = nsc_match.group(1)

    perms = re.findall(r'android\.permission\.(\w+)', manifest_text)
    info.permissions = list(set(f"android.permission.{p}" for p in perms))

    return info
