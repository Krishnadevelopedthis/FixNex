"""
OWASP ZAP scanner adapter.

ZAP is started lazily:
- It is NOT started when the FastAPI application boots.
- It starts automatically when the first ZAP scan/availability check
  requires it.
- Nmap, Nuclei, WhatWeb and other scanners are completely independent.

The bundled ZAP binary is expected at:

    /opt/zap/zap.sh

ZAP listens only on:

    127.0.0.1:8080
"""

from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path

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

# ZAP configuration
_ZAP_HOST = "127.0.0.1"
_ZAP_PORT = 8080
_ZAP_URL = f"http://{_ZAP_HOST}:{_ZAP_PORT}"

# Maximum time allowed for ZAP to start.
# This ONLY applies when a ZAP scan is requested.
_ZAP_START_TIMEOUT = 90

# Prevent multiple ZAP processes from being started simultaneously.
_ZAP_START_LOCK = threading.Lock()

# Keep a reference to the lazily started ZAP process.
_ZAP_PROCESS: subprocess.Popen | None = None


class ZAPAdapter(ScannerAdapter):
    name = ScannerName.ZAP
    label = "OWASP ZAP"

    description = (
        "Primary web application scanner. Spiders the target and runs ZAP's "
        "passive rules; the Comprehensive profile also runs the active scanner."
    )

    kind = "external"

    requires = (
        "the bundled OWASP ZAP daemon, which is started automatically "
        "when a ZAP scan is requested"
    )

    profiles = (
        ScanProfile.STANDARD,
        ScanProfile.COMPREHENSIVE,
    )

    target_types = (
        TargetType.WEB_APP,
        TargetType.REST_API,
    )

    weight = 5

    # =============================================================
    # ZAP PROCESS MANAGEMENT
    # =============================================================

    def _start_zap(self) -> bool:
        """
        Start ZAP lazily if it is not already running.

        This function is called only when the ZAP adapter is actually used.
        """

        global _ZAP_PROCESS

        # Already responding?
        if self._zap_is_ready():
            return True

        with _ZAP_START_LOCK:

            # Another thread may have started ZAP while we waited
            # for the lock.
            if self._zap_is_ready():
                return True

            # If an old process exists but died, clear it.
            if _ZAP_PROCESS is not None:
                if _ZAP_PROCESS.poll() is not None:
                    _ZAP_PROCESS = None

            zap_path = Path("/opt/zap/zap.sh")

            if not zap_path.exists():
                return False

            print("Starting OWASP ZAP lazily...")

            Path("/tmp").mkdir(parents=True, exist_ok=True)

            log_file = open(
                "/tmp/zap.log",
                "a",
                encoding="utf-8",
            )

            command = [
                str(zap_path),
                "-daemon",
                "-host",
                _ZAP_HOST,
                "-port",
                str(_ZAP_PORT),
                "-config",
                "api.addrs.addr.name=127.0.0.1",
                "-config",
                "api.addrs.addr.regex=true",
            ]

            # -----------------------------------------------------
            # API KEY
            # -----------------------------------------------------

            if settings.ZAP_API_KEY:
                command.extend(
                    [
                        "-config",
                        f"api.key={settings.ZAP_API_KEY}",
                    ]
                )

                print("Starting ZAP with API key protection.")

            else:
                command.extend(
                    [
                        "-config",
                        "api.disablekey=true",
                    ]
                )

                print("Starting ZAP without API key protection.")

            try:
                _ZAP_PROCESS = subprocess.Popen(
                    command,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except Exception as exc:
                log_file.close()
                print(
                    f"WARNING: Failed to start OWASP ZAP: "
                    f"{type(exc).__name__}: {exc}"
                )
                return False

            print(
                f"OWASP ZAP process started with PID "
                f"{_ZAP_PROCESS.pid}."
            )

            # -----------------------------------------------------
            # WAIT ONLY HERE
            # -----------------------------------------------------
            #
            # This wait happens only when a ZAP scan is requested.
            # Normal FastAPI startup is completely unaffected.
            # -----------------------------------------------------

            deadline = time.monotonic() + _ZAP_START_TIMEOUT

            while time.monotonic() < deadline:

                if self._zap_is_ready():
                    print("OWASP ZAP is ready.")

                    try:
                        version = self._get_version()
                        print(f"ZAP version: {version}")
                    except Exception:
                        pass

                    return True

                # Process died
                if _ZAP_PROCESS.poll() is not None:
                    print("WARNING: OWASP ZAP process exited unexpectedly.")

                    try:
                        log_file.flush()
                        log_file.close()
                    except Exception:
                        pass

                    _ZAP_PROCESS = None
                    return False

                time.sleep(2)

            print(
                "WARNING: OWASP ZAP did not become ready within "
                f"{_ZAP_START_TIMEOUT} seconds."
            )

            try:
                log_file.flush()
                log_file.close()
            except Exception:
                pass

            return False

    def _zap_is_ready(self) -> bool:
        """
        Check whether the local ZAP REST API is responding.
        """

        try:
            with self._client() as client:

                response = client.get(
                    "/JSON/core/view/version/",
                    params=self._params(),
                    timeout=3,
                )

                response.raise_for_status()

                return True

        except Exception:
            return False

    def _get_version(self) -> str | None:
        """
        Return ZAP version.
        """

        with self._client() as client:

            response = client.get(
                "/JSON/core/view/version/",
                params=self._params(),
                timeout=5,
            )

            response.raise_for_status()

            return response.json().get("version")

    # =============================================================
    # HTTP CLIENT
    # =============================================================

    def _client(self) -> httpx.Client:
        """
        Create a ZAP HTTP client.

        ZAP_API_URL is still supported from configuration.
        If it is not configured, use the bundled local ZAP.
        """

        base_url = (
            settings.ZAP_API_URL.rstrip("/")
            if settings.ZAP_API_URL
            else _ZAP_URL
        )

        return httpx.Client(
            base_url=base_url,
            timeout=30,
        )

    def _params(self, **kwargs) -> dict:
        params = {
            k: v
            for k, v in kwargs.items()
            if v is not None
        }

        if settings.ZAP_API_KEY:
            params["apikey"] = settings.ZAP_API_KEY

        return params

    # =============================================================
    # AVAILABILITY
    # =============================================================

    def availability(self) -> ScannerAvailability:
        """
        Check whether ZAP is available.

        If bundled ZAP is not running, start it lazily.
        """

        # ---------------------------------------------------------
        # If externally configured URL exists and is not localhost,
        # don't attempt to launch a local ZAP process.
        # ---------------------------------------------------------

        configured_url = settings.ZAP_API_URL.strip()

        is_local_zap = (
            not configured_url
            or "127.0.0.1:8080" in configured_url
            or "localhost:8080" in configured_url
        )

        # ---------------------------------------------------------
        # External ZAP
        # ---------------------------------------------------------

        if configured_url and not is_local_zap:

            try:
                with self._client() as client:

                    response = client.get(
                        "/JSON/core/view/version/",
                        params=self._params(),
                        timeout=5,
                    )

                    response.raise_for_status()

                    version = response.json().get("version")

                return ScannerAvailability(
                    True,
                    f"ZAP daemon reachable at {configured_url}",
                    version,
                )

            except Exception as exc:

                return ScannerAvailability(
                    False,
                    (
                        f"ZAP daemon at {configured_url} is not reachable "
                        f"({type(exc).__name__})."
                    ),
                )

        # ---------------------------------------------------------
        # Bundled local ZAP
        # ---------------------------------------------------------

        if not self._start_zap():

            return ScannerAvailability(
                False,
                (
                    "Bundled OWASP ZAP could not be started. "
                    "Check /tmp/zap.log for details."
                ),
            )

        try:

            version = self._get_version()

            return ScannerAvailability(
                True,
                "Bundled OWASP ZAP daemon is running locally.",
                version,
            )

        except Exception as exc:

            return ScannerAvailability(
                False,
                (
                    "OWASP ZAP started but its API is not reachable "
                    f"({type(exc).__name__})."
                ),
            )

    # =============================================================
    # RUN
    # =============================================================

    def run(self, ctx: ScanContext) -> ScanResult:

        result = ScanResult(
            scanner=self.name,
            command_summary=f"ZAP REST API scan of {ctx.url}",
        )

        availability = self.availability()

        if not availability.available:

            result.skipped_reason = availability.detail

            return result

        result.tool_version = availability.version

        deadline = time.monotonic() + min(
            ctx.timeout,
            settings.SCANNER_TIMEOUT_SECONDS,
        )

        try:

            with self._client() as client:

                # -------------------------------------------------
                # Access target
                # -------------------------------------------------

                ctx.progress(
                    "ZAP: accessing target",
                    10,
                )

                client.get(
                    "/JSON/core/action/accessUrl/",
                    params=self._params(
                        url=ctx.url,
                    ),
                )

                # -------------------------------------------------
                # Spider
                # -------------------------------------------------

                ctx.progress(
                    "ZAP: spidering the application",
                    20,
                )

                spider_id = (
                    client.get(
                        "/JSON/spider/action/scan/",
                        params=self._params(
                            url=ctx.url,
                        ),
                    )
                    .json()
                    .get("scan")
                )

                self._await_scan(
                    client,
                    "/JSON/spider/view/status/",
                    spider_id,
                    ctx,
                    deadline,
                    20,
                    45,
                    "ZAP: spidering the application",
                )

                # -------------------------------------------------
                # Passive scan
                # -------------------------------------------------

                ctx.progress(
                    "ZAP: waiting for passive scan rules",
                    50,
                )

                self._await_passive(
                    client,
                    ctx,
                    deadline,
                )

                # -------------------------------------------------
                # Active scan
                # -------------------------------------------------

                if ctx.profile == ScanProfile.COMPREHENSIVE:

                    ctx.progress(
                        "ZAP: running active scan rules",
                        60,
                    )

                    ascan_id = (
                        client.get(
                            "/JSON/ascan/action/scan/",
                            params=self._params(
                                url=ctx.url,
                                recurse="true",
                                inScopeOnly="false",
                            ),
                        )
                        .json()
                        .get("scan")
                    )

                    self._await_scan(
                        client,
                        "/JSON/ascan/view/status/",
                        ascan_id,
                        ctx,
                        deadline,
                        60,
                        88,
                        "ZAP: running active scan rules",
                    )

                # -------------------------------------------------
                # Collect alerts
                # -------------------------------------------------

                ctx.progress(
                    "ZAP: collecting alerts",
                    92,
                )

                alerts = (
                    client.get(
                        "/JSON/core/view/alerts/",
                        params=self._params(
                            baseurl=ctx.url,
                            start="0",
                            count="500",
                        ),
                    )
                    .json()
                    .get("alerts", [])
                )

        except Exception as exc:

            result.error = (
                f"ZAP scan failed: "
                f"{type(exc).__name__}: {exc}"
            )[:500]

            result.exit_code = 1

            return result

        result.exit_code = 0

        result.findings = self._parse(
            ctx,
            alerts,
        )

        result.metrics = {
            "alerts": len(alerts),
            "findings": len(result.findings),
        }

        return result

    # =============================================================
    # POLLING
    # =============================================================

    def _await_scan(
        self,
        client,
        status_path,
        scan_id,
        ctx,
        deadline,
        low,
        high,
        message,
    ) -> None:

        if scan_id is None:
            return

        while (
            time.monotonic() < deadline
            and not ctx.is_cancelled()
        ):

            status = (
                client.get(
                    status_path,
                    params=self._params(
                        scanId=scan_id,
                    ),
                )
                .json()
                .get(
                    "status",
                    "100",
                )
            )

            percent = (
                int(status)
                if str(status).isdigit()
                else 100
            )

            ctx.progress(
                f"{message} ({percent}%)",
                low
                + int(
                    (high - low)
                    * percent
                    / 100
                ),
            )

            if percent >= 100:
                return

            time.sleep(_POLL_INTERVAL)

    def _await_passive(
        self,
        client,
        ctx,
        deadline,
    ) -> None:

        while (
            time.monotonic() < deadline
            and not ctx.is_cancelled()
        ):

            remaining = (
                client.get(
                    "/JSON/pscan/view/recordsToScan/",
                    params=self._params(),
                )
                .json()
                .get(
                    "recordsToScan",
                    "0",
                )
            )

            if (
                not str(remaining).isdigit()
                or int(remaining) == 0
            ):
                return

            ctx.progress(
                f"ZAP: passive scan queue "
                f"({remaining} records remaining)",
                52,
            )

            time.sleep(_POLL_INTERVAL)

    # =============================================================
    # PARSING
    # =============================================================

    def _parse(
        self,
        ctx: ScanContext,
        alerts: list[dict],
    ) -> list[NormalizedFinding]:

        findings: list[NormalizedFinding] = []

        for alert in alerts:

            cwe_id = alert.get("cweid")

            cwe = (
                f"CWE-{cwe_id}"
                if (
                    cwe_id
                    and str(cwe_id).isdigit()
                    and int(cwe_id) > 0
                )
                else None
            )

            confidence_map = {
                "0": 0.25,
                "1": 0.45,
                "2": 0.7,
                "3": 0.9,
            }

            confidence = confidence_map.get(
                str(
                    alert.get(
                        "confidence",
                        "2",
                    )
                ),
                0.6,
            )

            references = [
                r.strip()
                for r in (
                    alert.get("reference") or ""
                )
                .replace(
                    "<p>",
                    "\n",
                )
                .replace(
                    "</p>",
                    "",
                )
                .split("\n")
                if r.strip().startswith("http")
            ][:8]

            findings.append(
                NormalizedFinding(
                    title=(
                        alert.get("alert")
                        or alert.get("name")
                        or "ZAP alert"
                    ),
                    description=_strip_html(
                        alert.get("description")
                    ),
                    severity=normalize_severity(
                        alert.get("risk")
                    ),
                    target=ctx.target_value,
                    endpoint=(
                        alert.get("url")
                        or ctx.url
                    ),
                    source=self.name,
                    category="Web Application",
                    parameter=(
                        alert.get("param")
                        or None
                    ),
                    http_method=(
                        alert.get("method")
                        or None
                    ),
                    cwe=cwe,
                    evidence=truncate(
                        alert.get("evidence")
                        or alert.get("attack"),
                        2000,
                    ),
                    request_snippet=truncate(
                        alert.get("attack"),
                        2000,
                    ),
                    response_snippet=truncate(
                        alert.get("otherinfo"),
                        2000,
                    ),
                    remediation=_strip_html(
                        alert.get("solution")
                    ),
                    references=references,
                    confidence=confidence,
                    raw={
                        "pluginId": alert.get(
                            "pluginId"
                        ),
                        "alertRef": alert.get(
                            "alertRef"
                        ),
                        "wascid": alert.get(
                            "wascid"
                        ),
                        "riskcode": alert.get(
                            "riskcode"
                        ),
                    },
                )
            )

        return findings


def _strip_html(
    value: str | None,
) -> str:

    if not value:
        return ""

    import re

    text = re.sub(
        r"<[^>]+>",
        " ",
        value,
    )

    return re.sub(
        r"\s+",
        " ",
        text,
    ).strip()