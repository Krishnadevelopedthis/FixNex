"""WhatWeb adapter — web technology fingerprinting."""
from __future__ import annotations

import json
import re

from app.core.config import settings
from app.models.enums import ScannerName, ScanProfile, Severity, TargetType
from app.scanners.base import (
    NormalizedFinding,
    ScanContext,
    ScannerAdapter,
    ScannerAvailability,
    ScanResult,
    truncate,
)
from app.scanners.process import run_command, tool_version, which


# WhatWeb plugins that report the presence of something noteworthy rather than
# a plain technology name.
_NOTABLE_PLUGINS = {
    "Directory-Listing": (
        Severity.MEDIUM,
        "CWE-548",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "Directory listing is enabled, exposing the contents of a web-accessible directory.",
        "Disable automatic directory indexing on the web server.",
    ),
    "Access-Control-Allow-Origin": (
        Severity.LOW,
        "CWE-942",
        None,
        "A cross-origin resource sharing header was observed.",
        "Restrict CORS to an explicit list of trusted origins.",
    ),
}


class WhatWebAdapter(ScannerAdapter):
    name = ScannerName.WHATWEB
    label = "WhatWeb"
    description = "Web server, framework and CMS fingerprinting using the WhatWeb scanner."
    kind = "external"
    requires = "the `whatweb` binary on PATH"
    profiles = (
        ScanProfile.LIGHT,
        ScanProfile.STANDARD,
        ScanProfile.COMPREHENSIVE,
    )
    target_types = (TargetType.WEB_APP, TargetType.REST_API)
    weight = 2

    def availability(self) -> ScannerAvailability:
        path = which(settings.WHATWEB_PATH)

        if not path:
            return ScannerAvailability(
                False,
                "The `whatweb` binary was not found on PATH. FixNex falls back to its "
                "built-in technology fingerprinting adapter.",
            )

        return ScannerAvailability(
            True,
            f"Found at {path}",
            tool_version(settings.WHATWEB_PATH, "--version"),
        )

    def run(self, ctx: ScanContext) -> ScanResult:
        binary = which(settings.WHATWEB_PATH)
        result = ScanResult(scanner=self.name)

        if not binary:
            result.skipped_reason = "whatweb is not installed."
            return result

        aggression = (
            "3"
            if ctx.profile == ScanProfile.COMPREHENSIVE
            else "1"
        )

        args = [
            binary,
            "-a",
            aggression,
            "--log-json=-",
            "--no-errors",
            ctx.url,
        ]

        result.command_summary = " ".join(args)

        ctx.progress(
            f"Fingerprinting {ctx.url} with WhatWeb",
            25,
        )

        completed = run_command(
            args,
            timeout=min(ctx.timeout, 180),
        )

        result.exit_code = completed.exit_code
        result.tool_version = tool_version(
            settings.WHATWEB_PATH,
            "--version",
        )

        if completed.timed_out:
            result.error = completed.stderr
            return result

        if not completed.stdout.strip():
            result.error = (
                completed.stderr
                or "WhatWeb produced no output."
            )[:400]
            return result

        ctx.progress(
            "Parsing WhatWeb output",
            80,
        )

        result.findings, technologies = self._parse(
            ctx,
            completed.stdout,
        )

        result.metrics = {
            "technologies": technologies,
        }

        return result

    def _parse(
        self,
        ctx: ScanContext,
        output: str,
    ) -> tuple[list[NormalizedFinding], list[dict]]:

        findings: list[NormalizedFinding] = []
        technologies: list[dict] = []

        entries: list[dict] = []

        # ---------------------------------------------------------
        # WhatWeb 0.5.5 with --log-json=- produces output similar to:
        #
        # [
        # {"target":"http://...", "plugins": {...}}
        # http://... [200 OK] Apache[...]
        # ]
        #
        # Therefore the entire stdout cannot be passed directly to
        # json.loads(). We extract the JSON object lines instead.
        # ---------------------------------------------------------

        for line in output.splitlines():
            line = line.strip()

            if not line:
                continue

            # Ignore the JSON array delimiters.
            if line in ("[", "]"):
                continue

            # Remove a trailing comma if WhatWeb adds one.
            line = line.rstrip(",")

            if not line.startswith("{"):
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            if isinstance(data, dict):
                entries.append(data)

        # ---------------------------------------------------------
        # Process every WhatWeb result.
        # ---------------------------------------------------------

        for entry in entries:
            plugins = entry.get("plugins") or {}
            target_url = entry.get("target") or ctx.url

            for plugin_name, data in plugins.items():
                if not isinstance(data, dict):
                    data = {}

                versions = data.get("version") or []
                strings = data.get("string") or []

                version = None

                if versions:
                    version = str(versions[0])
                elif strings:
                    version = str(strings[0])

                technologies.append(
                    {
                        "name": plugin_name,
                        "version": version,
                        "category": "WhatWeb",
                    }
                )

                # -------------------------------------------------
                # Security-relevant WhatWeb plugins
                # -------------------------------------------------

                if plugin_name in _NOTABLE_PLUGINS:
                    (
                        severity,
                        cwe,
                        vector,
                        description,
                        remediation,
                    ) = _NOTABLE_PLUGINS[plugin_name]

                    findings.append(
                        NormalizedFinding(
                            title=(
                                f"{plugin_name.replace('-', ' ')} "
                                "detected by WhatWeb"
                            ),
                            description=description,
                            severity=severity,
                            target=ctx.target_value,
                            endpoint=target_url,
                            source=self.name,
                            category="Security Misconfiguration",
                            cwe=cwe,
                            cvss_vector=vector,
                            evidence=truncate(
                                json.dumps(data),
                                1000,
                            ),
                            remediation=remediation,
                            confidence=0.85,
                            raw={
                                "plugin": plugin_name,
                            },
                        )
                    )

        # ---------------------------------------------------------
        # Create ONE technology-stack finding after all plugins
        # have been processed.
        # ---------------------------------------------------------

        if technologies:
            summary = ", ".join(
                f"{technology['name']}"
                + (
                    f" {technology['version']}"
                    if technology["version"]
                    else ""
                )
                for technology in technologies
            )

            findings.append(
                NormalizedFinding(
                    title="Technology stack fingerprinted",
                    description=f"WhatWeb identified: {summary}.",
                    severity=Severity.INFORMATIONAL,
                    target=ctx.target_value,
                    endpoint=(
                        entries[0].get("target", ctx.url)
                        if entries
                        else ctx.url
                    ),
                    source=self.name,
                    category="Reconnaissance",
                    cwe="CWE-200",
                    evidence=truncate(summary, 1500),
                    remediation="Suppress version banners where practical.",
                    confidence=0.9,
                    raw={
                        "technologies": technologies,
                    },
                )
            )

        return findings, technologies