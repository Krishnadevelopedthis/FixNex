"""OWASP ZAP adapter.

Talks to a running ZAP daemon over its REST API. Passive scanning is used for
the STANDARD profile; the COMPREHENSIVE profile additionally runs ZAP's active
scanner. No destructive attack strength is ever selected.
"""
from __future__ import annotations

import time

import httpx

from app.core.config import settings
from app.models.enums import ScannerName, ScanProfile, TargetType
from app.scanners.base import (
    NormalizedFinding,
    ScanContext,
    ScannerAdapter,
    ScannerAvailability,
    ScanResult,
    normalize_severity,
    truncate,
)

_POLL_INTERVAL = 3


class ZAPAdapter(ScannerAdapter):
    name = ScannerName.ZAP
    label = "OWASP ZAP"
    description = (
        "Primary web application scanner. Spiders the target and runs ZAP's passive "
        "rules; the Comprehensive profile also runs the active scanner."
    )
    kind = "external"
    requires = "a running OWASP ZAP daemon reachable at ZAP_API_URL"
    profiles = (ScanProfile.STANDARD, ScanProfile.COMPREHENSIVE)
    target_types = (TargetType.WEB_APP, TargetType.REST_API)
    weight = 5

    # ------------------------------------------------------------- plumbing
    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=settings.ZAP_API_URL.rstrip("/"), timeout=30)

    def _params(self, **kwargs) -> dict:
        params = {k: v for k, v in kwargs.items() if v is not None}
        if settings.ZAP_API_KEY:
            params["apikey"] = settings.ZAP_API_KEY
        return params

    def availability(self) -> ScannerAvailability:
        if not settings.ZAP_API_URL:
            return ScannerAvailability(
                False,
                "ZAP_API_URL is not configured. Start the ZAP daemon (the bundled Docker "
                "Compose profile does this) and set ZAP_API_URL to enable it.",
            )
        try:
            with self._client() as client:
                response = client.get("/JSON/core/view/version/", params=self._params(), timeout=5)
                response.raise_for_status()
                version = response.json().get("version")
            return ScannerAvailability(True, f"ZAP daemon reachable at {settings.ZAP_API_URL}", version)
        except Exception as exc:
            return ScannerAvailability(
                False,
                f"ZAP daemon at {settings.ZAP_API_URL} is not reachable "
                f"({type(exc).__name__}). Findings from ZAP will be unavailable for this scan.",
            )

    # ------------------------------------------------------------------ run
    def run(self, ctx: ScanContext) -> ScanResult:
        result = ScanResult(scanner=self.name, command_summary=f"ZAP REST API scan of {ctx.url}")
        availability = self.availability()
        if not availability.available:
            result.skipped_reason = availability.detail
            return result

        result.tool_version = availability.version
        deadline = time.monotonic() + min(ctx.timeout, settings.SCANNER_TIMEOUT_SECONDS)

        try:
            with self._client() as client:
                ctx.progress("ZAP: accessing target", 10)
                client.get("/JSON/core/action/accessUrl/", params=self._params(url=ctx.url))

                ctx.progress("ZAP: spidering the application", 20)
                spider_id = (
                    client.get("/JSON/spider/action/scan/", params=self._params(url=ctx.url))
                    .json()
                    .get("scan")
                )
                self._await_scan(client, "/JSON/spider/view/status/", spider_id, ctx, deadline, 20, 45,
                                 "ZAP: spidering the application")

                ctx.progress("ZAP: waiting for passive scan rules", 50)
                self._await_passive(client, ctx, deadline)

                if ctx.profile == ScanProfile.COMPREHENSIVE:
                    ctx.progress("ZAP: running active scan rules", 60)
                    ascan_id = (
                        client.get(
                            "/JSON/ascan/action/scan/",
                            params=self._params(url=ctx.url, recurse="true", inScopeOnly="false"),
                        )
                        .json()
                        .get("scan")
                    )
                    self._await_scan(client, "/JSON/ascan/view/status/", ascan_id, ctx, deadline, 60, 88,
                                     "ZAP: running active scan rules")

                ctx.progress("ZAP: collecting alerts", 92)
                alerts = (
                    client.get(
                        "/JSON/core/view/alerts/",
                        params=self._params(baseurl=ctx.url, start="0", count="500"),
                    )
                    .json()
                    .get("alerts", [])
                )
        except Exception as exc:
            result.error = f"ZAP scan failed: {type(exc).__name__}: {exc}"[:500]
            result.exit_code = 1
            return result

        result.exit_code = 0
        result.findings = self._parse(ctx, alerts)
        result.metrics = {"alerts": len(alerts), "findings": len(result.findings)}
        return result

    # -------------------------------------------------------------- polling
    def _await_scan(self, client, status_path, scan_id, ctx, deadline, low, high, message) -> None:
        if scan_id is None:
            return
        while time.monotonic() < deadline and not ctx.is_cancelled():
            status = client.get(status_path, params=self._params(scanId=scan_id)).json().get("status", "100")
            percent = int(status) if str(status).isdigit() else 100
            ctx.progress(f"{message} ({percent}%)", low + int((high - low) * percent / 100))
            if percent >= 100:
                return
            time.sleep(_POLL_INTERVAL)

    def _await_passive(self, client, ctx, deadline) -> None:
        while time.monotonic() < deadline and not ctx.is_cancelled():
            remaining = (
                client.get("/JSON/pscan/view/recordsToScan/", params=self._params())
                .json()
                .get("recordsToScan", "0")
            )
            if not str(remaining).isdigit() or int(remaining) == 0:
                return
            ctx.progress(f"ZAP: passive scan queue ({remaining} records remaining)", 52)
            time.sleep(_POLL_INTERVAL)

    # -------------------------------------------------------------- parsing
    def _parse(self, ctx: ScanContext, alerts: list[dict]) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        # ZAP reports one alert instance per affected URL; group by alert + param.
        for alert in alerts:
            cwe_id = alert.get("cweid")
            cwe = f"CWE-{cwe_id}" if cwe_id and str(cwe_id).isdigit() and int(cwe_id) > 0 else None
            confidence_map = {"0": 0.25, "1": 0.45, "2": 0.7, "3": 0.9}
            confidence = confidence_map.get(str(alert.get("confidence", "2")), 0.6)

            references = [
                r.strip()
                for r in (alert.get("reference") or "").replace("<p>", "\n").replace("</p>", "").split("\n")
                if r.strip().startswith("http")
            ][:8]

            findings.append(
                NormalizedFinding(
                    title=alert.get("alert") or alert.get("name") or "ZAP alert",
                    description=_strip_html(alert.get("description")),
                    severity=normalize_severity(alert.get("risk")),
                    target=ctx.target_value,
                    endpoint=alert.get("url") or ctx.url,
                    source=self.name,
                    category="Web Application",
                    parameter=alert.get("param") or None,
                    http_method=alert.get("method") or None,
                    cwe=cwe,
                    evidence=truncate(alert.get("evidence") or alert.get("attack"), 2000),
                    request_snippet=truncate(alert.get("attack"), 2000),
                    response_snippet=truncate(alert.get("otherinfo"), 2000),
                    remediation=_strip_html(alert.get("solution")),
                    references=references,
                    confidence=confidence,
                    raw={
                        "pluginId": alert.get("pluginId"),
                        "alertRef": alert.get("alertRef"),
                        "wascid": alert.get("wascid"),
                        "riskcode": alert.get("riskcode"),
                    },
                )
            )
        return findings


def _strip_html(value: str | None) -> str:
    if not value:
        return ""
    import re

    text = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", text).strip()
