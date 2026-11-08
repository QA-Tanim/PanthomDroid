"""PhantomDroid X - Port scanning with structured results."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from phantomdroid.core.models import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
)
from phantomdroid.core.scanner import ScanContext, SecurityCheck

COMMON_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5555: "ADB",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 9200: "Elasticsearch", 4444: "Metasploit",
}

RISKY_PORTS: dict[int, Severity] = {
    21: Severity.HIGH,      # FTP
    23: Severity.HIGH,      # Telnet
    5555: Severity.HIGH,    # ADB
    4444: Severity.CRITICAL,# Metasploit
    5900: Severity.HIGH,    # VNC
    6379: Severity.HIGH,    # Redis
    27017: Severity.HIGH,   # MongoDB
    3389: Severity.MEDIUM,  # RDP
}


@dataclass
class OpenPort:
    """Represents an open port."""
    port: int
    service: str
    is_open: bool


def scan_port(host: str, port: int, timeout: float = 0.8) -> bool:
    """Check if a single port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (TimeoutError, ConnectionRefusedError, OSError):
        return False


def port_scan(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 0.8,
    max_workers: int = 100,
) -> list[OpenPort]:
    """Scan ports on a host.

    Args:
        host: Target host.
        ports: Ports to scan (default: common ports).
        timeout: Connection timeout.
        max_workers: Maximum concurrent threads.

    Returns:
        List of OpenPort objects.
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports: list[OpenPort] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(OpenPort(
                        port=port,
                        service=COMMON_PORTS.get(port, "Unknown"),
                        is_open=True,
                    ))
            except Exception:
                continue

    open_ports.sort(key=lambda p: p.port)
    return open_ports


def open_ports_to_findings(open_ports: list[OpenPort], host: str) -> list[Finding]:
    """Convert open ports to findings."""
    findings: list[Finding] = []

    for op in open_ports:
        severity = RISKY_PORTS.get(op.port, Severity.INFO)
        if severity == Severity.INFO:
            continue  # Skip non-risky ports

        finding = Finding(
            id=f"PD-NET-PORT-{op.port}",
            title=f"Open Port: {op.port}/{op.service}",
            category="Network Security",
            severity=severity,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            cwe="CWE-16",
            description=(
                f"Port {op.port} ({op.service}) is open on {host}. "
                f"This service may expose sensitive functionality or data."
            ),
            evidence=[
                Evidence(
                    type="network",
                    source=host,
                    attribute="open_port",
                    value=f"{op.port}/{op.service}",
                )
            ],
            remediation=_get_port_remediation(op.port),
            references=[],
        )
        findings.append(finding)

    return findings


def _get_port_remediation(port: int) -> str:
    remediations = {
        21: "Replace FTP with SFTP or SCP for secure file transfer.",
        23: "Replace Telnet with SSH for secure remote access.",
        5555: "Disable ADB over WiFi when not needed. Use USB debugging instead.",
        4444: "Investigate Metasploit listener. This may indicate a compromise.",
        5900: "Secure VNC with strong passwords and encryption, or use SSH tunneling.",
        6379: "Bind Redis to localhost and require authentication.",
        27017: "Bind MongoDB to localhost and enable authentication.",
        3389: "Use Network Level Authentication and strong passwords for RDP.",
    }
    return remediations.get(port, "Review if this service needs to be exposed.")


class PortScanCheck(SecurityCheck):
    """Security check for port scanning."""

    id = "PD-NET-PORT-001"
    name = "Port Scanning"
    category = "network"
    description = "Scan for open ports and identify risky services"

    def run(self, context: ScanContext) -> list[Finding]:
        target = context.target
        open_ports = port_scan(target, timeout=context.config.port_scan_timeout if context.config else 0.8)
        return open_ports_to_findings(open_ports, target)

    def can_run(self, context: ScanContext) -> bool:
        return context.scan_type in ("network", "device")
