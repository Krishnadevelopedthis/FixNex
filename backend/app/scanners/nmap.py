"""Nmap adapter — port and service discovery."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from app.core.config import settings
from app.models.enums import ScannerName, ScanProfile, Severity, TargetType
from app.scanners.base import (
    NormalizedFinding,
    ScanContext,
    ScannerAdapter,
    ScannerAvailability,
    ScanResult,
    extract_cves,
)
from app.scanners.process import run_command, tool_version, which

_RISKY_SERVICES = {
    "telnet": (Severity.HIGH, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "ftp": (Severity.MEDIUM, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "microsoft-ds": (Severity.HIGH, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "ms-wbt-server": (Severity.HIGH, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "mysql": (Severity.HIGH, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "postgresql": (Severity.HIGH, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "redis": (Severity.CRITICAL, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "mongodb": (Severity.CRITICAL, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "vnc": (Severity.HIGH, None),
}


class NmapAdapter(ScannerAdapter):
    name = ScannerName.NMAP
    label = "Nmap"
    description = "Port discovery, service and version detection via the Nmap binary."
    kind = "external"
    requires = "the `nmap` binary on PATH"
    profiles = (ScanProfile.STANDARD, ScanProfile.COMPREHENSIVE)
    target_types = (TargetType.WEB_APP, TargetType.REST_API, TargetType.HOST)
    weight = 3

    def availability(self) -> ScannerAvailability:
        path = which(settings.NMAP_PATH)
        if not path:
            return ScannerAvailability(
                False,
                "The `nmap` binary was not found on PATH. FixNex falls back to its "
                "built-in TCP port sweep.",
            )
        return ScannerAvailability(True, f"Found at {path}", tool_version(settings.NMAP_PATH, "--version"))

    def run(self, ctx: ScanContext) -> ScanResult:
        binary = which(settings.NMAP_PATH)
        result = ScanResult(scanner=self.name)
        if not binary:
            result.skipped_reason = "nmap is not installed."
            return result

        # -Pn: do not ping (many hosts filter ICMP).  -sV: service/version detection.
        # No OS detection or raw-socket scan types, so no privileges are needed.
        args = [binary, "-Pn", "-sV", "--open", "-oX", "-"]
        if ctx.profile == ScanProfile.COMPREHENSIVE:
            args += ["--top-ports", "1000", "-T4", "--script", "banner,http-headers"]
        else:
            args += ["--top-ports", "200", "-T4"]
        args.append(ctx.hostname)

        result.command_summary = " ".join(args)
        ctx.progress(f"Running Nmap service discovery against {ctx.hostname}", 20)

        completed = run_command(args, timeout=min(ctx.timeout, settings.SCANNER_TIMEOUT_SECONDS))
        result.exit_code = completed.exit_code
        result.tool_version = tool_version(settings.NMAP_PATH, "--version")

        if completed.timed_out:
            result.error = completed.stderr
            return result
        if completed.exit_code != 0 and not completed.stdout.strip():
            result.error = (completed.stderr or "Nmap exited with an error.")[:500]
            return result

        ctx.progress("Parsing Nmap XML output", 75)
        try:
            result.findings = self._parse(ctx, completed.stdout)
        except ET.ParseError as exc:
            result.error = f"Could not parse the Nmap XML output: {exc}"
            return result

        result.metrics = {"open_ports": len(result.findings)}
        return result

    def _parse(self, ctx: ScanContext, xml_output: str) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        if not xml_output.strip():
            return findings
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            address_el = host.find("address")
            address = address_el.get("addr") if address_el is not None else ctx.hostname
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                port_id = port.get("portid", "?")
                protocol = port.get("protocol", "tcp")
                service_el = port.find("service")
                service = service_el.get("name", "unknown") if service_el is not None else "unknown"
                product = service_el.get("product") if service_el is not None else None
                version = service_el.get("version") if service_el is not None else None
                banner = " ".join(filter(None, [product, version]))

                severity, vector = _RISKY_SERVICES.get(service, (Severity.INFORMATIONAL, None))
                scripts = " ".join(
                    (s.get("output") or "") for s in port.findall("script")
                )

                findings.append(
                    NormalizedFinding(
                        title=f"Open port {port_id}/{protocol} ({service})"
                        + (f" — {banner}" if banner else ""),
                        description=(
                            f"Nmap reports {service} listening on {address}:{port_id}/{protocol}"
                            + (f", identified as {banner}" if banner else "")
                            + ". "
                            + (
                                "This service is frequently targeted when exposed to untrusted "
                                "networks."
                                if severity != Severity.INFORMATIONAL
                                else "Recorded as reconnaissance data."
                            )
                        ),
                        severity=severity,
                        target=ctx.target_value,
                        endpoint=f"{address}:{port_id}",
                        source=self.name,
                        category="Network Exposure",
                        cwe="CWE-668" if severity != Severity.INFORMATIONAL else None,
                        cvss_vector=vector,
                        cve=extract_cves(scripts),
                        evidence=f"{port_id}/{protocol} {service} {banner}".strip()
                        + (f"\n{scripts.strip()}" if scripts.strip() else ""),
                        remediation=(
                            "Restrict network access to this port to trusted sources and keep the "
                            "service patched."
                            if severity != Severity.INFORMATIONAL
                            else "No action required if this service is intentionally exposed."
                        ),
                        confidence=0.95,
                        raw={
                            "port": port_id,
                            "protocol": protocol,
                            "service": service,
                            "product": product,
                            "version": version,
                            "address": address,
                        },
                    )
                )
        return findings
