"""Nuclei adapter — template-driven vulnerability and misconfiguration detection."""
from __future__ import annotations

import json

from app.core.config import settings
from app.models.enums import ScannerName, ScanProfile, TargetType
from app.scanners.base import (
    NormalizedFinding,
    ScanContext,
    ScannerAdapter,
    ScannerAvailability,
    ScanResult,
    extract_cwe,
    normalize_severity,
    truncate,
)
from app.scanners.process import run_command, tool_version, which


class NucleiAdapter(ScannerAdapter):
    name = ScannerName.NUCLEI
    label = "Nuclei"
    description = (
        "Template-based detection of known vulnerabilities, exposures and "
        "misconfigurations using the ProjectDiscovery Nuclei engine."
    )
    kind = "external"
    requires = "the `nuclei` binary on PATH"
    profiles = (ScanProfile.STANDARD, ScanProfile.COMPREHENSIVE)
    target_types = (TargetType.WEB_APP, TargetType.REST_API, TargetType.HOST)
    weight = 4

    def availability(self) -> ScannerAvailability:
        path = which(settings.NUCLEI_PATH)
        if not path:
            return ScannerAvailability(
                False,
                "The `nuclei` binary was not found on PATH. Install it from "
                "https://github.com/projectdiscovery/nuclei to enable template scanning.",
            )
        return ScannerAvailability(True, f"Found at {path}", tool_version(settings.NUCLEI_PATH, "-version"))

    def run(self, ctx: ScanContext) -> ScanResult:
        binary = which(settings.NUCLEI_PATH)
        result = ScanResult(scanner=self.name)
        if not binary:
            result.skipped_reason = "nuclei is not installed."
            return result

        args = [binary, "-u", ctx.url, "-jsonl", "-silent", "-no-color", "-disable-update-check"]
        if ctx.profile == ScanProfile.COMPREHENSIVE:
            # Broader template set, still excluding anything intrusive/destructive.
            args += ["-severity", "info,low,medium,high,critical", "-rate-limit", "50"]
            args += ["-exclude-tags", "dos,fuzz,intrusive,brute-force"]
        else:
            args += ["-severity", "low,medium,high,critical", "-rate-limit", "30"]
            args += ["-exclude-tags", "dos,fuzz,intrusive,brute-force"]

        result.command_summary = " ".join(args)
        ctx.progress(f"Running Nuclei templates against {ctx.url}", 20)

        completed = run_command(args, timeout=min(ctx.timeout, settings.SCANNER_TIMEOUT_SECONDS))
        result.exit_code = completed.exit_code
        result.tool_version = tool_version(settings.NUCLEI_PATH, "-version")

        if completed.timed_out:
            result.error = completed.stderr
            return result
        # Nuclei exits non-zero with no output when nothing matched; that is not an error.
        if completed.exit_code not in (0, 1) and not completed.stdout.strip():
            result.error = (completed.stderr or "Nuclei exited with an error.")[:500]
            return result

        ctx.progress("Parsing Nuclei results", 80)
        result.findings = self._parse(ctx, completed.stdout)
        result.metrics = {"matches": len(result.findings)}
        return result

    def _parse(self, ctx: ScanContext, output: str) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for line in output.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = entry.get("info", {})
            classification = info.get("classification", {}) or {}

            cves = [c.upper() for c in (classification.get("cve-id") or []) if c]
            cwe_ids = classification.get("cwe-id") or []
            cwe = None
            if cwe_ids:
                cwe = str(cwe_ids[0]).upper()
                if not cwe.startswith("CWE-"):
                    cwe = f"CWE-{cwe}"
            cwe = cwe or extract_cwe(info.get("description"), info.get("name"))

            cvss_score = classification.get("cvss-score")
            try:
                cvss_score = float(cvss_score) if cvss_score is not None else None
            except (TypeError, ValueError):
                cvss_score = None

            findings.append(
                NormalizedFinding(
                    title=info.get("name") or entry.get("template-id") or "Nuclei detection",
                    description=(info.get("description") or "").strip()
                    or f"Nuclei template `{entry.get('template-id')}` matched on this target.",
                    severity=normalize_severity(info.get("severity")),
                    target=ctx.target_value,
                    endpoint=entry.get("matched-at") or entry.get("host") or ctx.url,
                    source=self.name,
                    category=(info.get("tags") or ["Vulnerability"])[0].replace("-", " ").title()
                    if info.get("tags")
                    else "Vulnerability",
                    http_method=entry.get("type", "").upper() if entry.get("type") == "http" else None,
                    cwe=cwe,
                    cve=cves,
                    cvss=cvss_score,
                    cvss_vector=classification.get("cvss-metrics"),
                    evidence=truncate(
                        entry.get("extracted-results")
                        and ", ".join(map(str, entry["extracted-results"]))
                        or entry.get("matcher-name")
                        or entry.get("matched-at"),
                        2000,
                    ),
                    request_snippet=truncate(entry.get("request"), 4000),
                    response_snippet=truncate(entry.get("response"), 4000),
                    remediation=info.get("remediation")
                    or "Review the referenced template guidance and apply the vendor's fix.",
                    references=[r for r in (info.get("reference") or []) if r][:8],
                    confidence=0.85,
                    raw={
                        "template_id": entry.get("template-id"),
                        "matcher": entry.get("matcher-name"),
                        "type": entry.get("type"),
                        "tags": info.get("tags"),
                    },
                )
            )
        return findings
