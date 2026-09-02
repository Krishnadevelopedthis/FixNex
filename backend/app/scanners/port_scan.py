"""Built-in TCP connect port sweep.

The always-available fallback for Nmap. Performs a plain, non-invasive TCP
connect against a small list of well-known ports — no OS fingerprinting, no
raw sockets and therefore no elevated privileges.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from app.models.enums import ScannerName, ScanProfile, Severity, TargetType
from app.scanners.base import (
    NormalizedFinding,
    ScanContext,
    ScannerAdapter,
    ScannerAvailability,
    ScanResult,
)

# port -> (service, risk when exposed, cvss vector or None)
_COMMON_PORTS: dict[int, tuple[str, str, str | None]] = {
    21: ("FTP", Severity.MEDIUM, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    22: ("SSH", Severity.INFORMATIONAL, None),
    23: ("Telnet", Severity.HIGH, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    25: ("SMTP", Severity.INFORMATIONAL, None),
    53: ("DNS", Severity.INFORMATIONAL, None),
    80: ("HTTP", Severity.INFORMATIONAL, None),
    110: ("POP3", Severity.LOW, None),
    143: ("IMAP", Severity.LOW, None),
    443: ("HTTPS", Severity.INFORMATIONAL, None),
    445: ("SMB", Severity.HIGH, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    3306: ("MySQL", Severity.HIGH, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    3389: ("RDP", Severity.HIGH, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    5432: ("PostgreSQL", Severity.HIGH, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    6379: ("Redis", Severity.CRITICAL, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    3000: ("HTTP application", Severity.INFORMATIONAL, None),
    5000: ("HTTP application", Severity.INFORMATIONAL, None),
    8000: ("HTTP application", Severity.INFORMATIONAL, None),
    8080: ("HTTP alternate", Severity.INFORMATIONAL, None),
    8888: ("HTTP application", Severity.INFORMATIONAL, None),
    8443: ("HTTPS alternate", Severity.INFORMATIONAL, None),
    9200: ("Elasticsearch", Severity.CRITICAL, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    27017: ("MongoDB", Severity.CRITICAL, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
}

_COMPREHENSIVE_EXTRA = {
    111: ("RPCbind", Severity.MEDIUM, None),
    135: ("MSRPC", Severity.MEDIUM, None),
    139: ("NetBIOS", Severity.MEDIUM, None),
    1433: ("MSSQL", Severity.HIGH, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    1521: ("Oracle DB", Severity.HIGH, None),
    2375: ("Docker API", Severity.CRITICAL, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    5900: ("VNC", Severity.HIGH, None),
    11211: ("Memcached", Severity.HIGH, None),
}


class PortScanAdapter(ScannerAdapter):
    name = ScannerName.PORT_SCAN
    label = "TCP Port Discovery"
    description = (
        "Non-invasive TCP connect sweep of well-known ports. Built into FixNex as the "
        "fallback for Nmap — always available."
    )
    kind = "builtin"
    profiles = (ScanProfile.STANDARD, ScanProfile.COMPREHENSIVE)
    target_types = (TargetType.WEB_APP, TargetType.REST_API, TargetType.HOST)
    weight = 2

    def availability(self) -> ScannerAvailability:
        return ScannerAvailability(True, "Built-in adapter (TCP connect, no privileges required).")

    def run(self, ctx: ScanContext) -> ScanResult:
        host = ctx.hostname
        ports = dict(_COMMON_PORTS)
        if ctx.profile == ScanProfile.COMPREHENSIVE:
            ports.update(_COMPREHENSIVE_EXTRA)

        # The target's own port must always be probed. Without this a service
        # on an unlisted port - 8081, 9443, anything bespoke - produced a sweep
        # that never touched the one port the assessment is actually about.
        own_port = ctx.effective_port
        if own_port and own_port not in ports:
            ports[own_port] = ("Target service", Severity.INFORMATIONAL, None)

        result = ScanResult(
            scanner=self.name,
            command_summary=f"TCP connect sweep of {len(ports)} ports on {host}",
        )
        ip = ctx.resolve_ip()
        if ip is None:
            result.error = f"Could not resolve hostname {host}."
            result.exit_code = 1
            return result

        ctx.progress(f"Sweeping {len(ports)} TCP ports on {host}", 15)
        open_ports: list[int] = []

        def probe(port: int) -> int | None:
            if ctx.is_cancelled():
                return None
            try:
                with socket.create_connection((ip, port), timeout=1.5):
                    return port
            except OSError:
                return None

        with ThreadPoolExecutor(max_workers=32) as pool:
            for index, found in enumerate(pool.map(probe, sorted(ports))):
                if found:
                    open_ports.append(found)
                if index % 5 == 0:
                    ctx.progress(
                        f"Sweeping TCP ports on {host} ({index + 1}/{len(ports)})",
                        15 + int(70 * (index + 1) / len(ports)),
                    )

        result.exit_code = 0
        result.metrics = {"resolved_ip": ip, "ports_probed": len(ports), "open_ports": open_ports}

        ctx.progress("Classifying exposed services", 92)
        findings: list[NormalizedFinding] = []
        for port in sorted(open_ports):
            service, severity, vector = ports[port]
            if severity == Severity.INFORMATIONAL:
                description = (
                    f"TCP port {port} ({service}) is open on {host} ({ip}). This is expected "
                    "for this service type and is recorded as reconnaissance data."
                )
                remediation = "No action required if this service is intentionally exposed."
            else:
                description = (
                    f"TCP port {port} ({service}) is reachable on {host} ({ip}). Exposing "
                    f"{service} to untrusted networks materially increases attack surface — "
                    "these services are routinely targeted for brute-force, unauthenticated "
                    "access and known exploits."
                )
                remediation = (
                    f"Restrict access to port {port} with a firewall or security group so that "
                    "only trusted management networks can reach it, and require authentication."
                )
            findings.append(
                NormalizedFinding(
                    title=f"Open port {port}/tcp ({service})",
                    description=description,
                    severity=severity,
                    target=ctx.target_value,
                    endpoint=f"{host}:{port}",
                    source=self.name,
                    category="Network Exposure",
                    cwe="CWE-668" if severity != Severity.INFORMATIONAL else None,
                    cvss_vector=vector,
                    evidence=f"TCP connect to {ip}:{port} succeeded.",
                    remediation=remediation,
                    confidence=0.95,
                    raw={"port": port, "service": service, "ip": ip},
                )
            )

        result.findings = findings
        return result
