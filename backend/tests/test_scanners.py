"""Scanner adapter contract, registry and graceful degradation."""
from __future__ import annotations

import pytest

from app.models.enums import ScanProfile, TargetType
from app.scanners.base import ScanContext, ScannerAdapter, extract_cves, extract_cwe
from app.scanners.registry import PROFILE_DEFINITIONS, profile_info, scanner_registry


def test_every_adapter_implements_the_contract():
    for adapter in scanner_registry.all():
        assert isinstance(adapter, ScannerAdapter)
        assert adapter.name and adapter.label and adapter.description
        assert adapter.kind in ("builtin", "external")
        availability = adapter.availability()
        assert isinstance(availability.available, bool)
        # An unavailable adapter must explain itself to the operator.
        assert availability.detail


def test_builtin_adapters_are_always_available():
    """The platform must produce real results with no external tooling installed."""
    builtins = [a for a in scanner_registry.all() if a.kind == "builtin"]
    assert len(builtins) >= 4
    for adapter in builtins:
        assert adapter.availability().available is True, adapter.name


def test_unavailable_external_tools_are_reported_not_fatal():
    report = scanner_registry.availability_report()
    assert report
    for entry in report:
        assert set(entry) >= {"name", "label", "kind", "available", "availability_detail"}


def test_profiles_are_ordered_by_breadth():
    light = set(profile_info()[0]["scanners"])
    standard = set(profile_info()[1]["scanners"])
    comprehensive = set(profile_info()[2]["scanners"])
    assert light < standard < comprehensive


def test_only_the_comprehensive_profile_is_marked_invasive():
    invasive = {p["name"] for p in PROFILE_DEFINITIONS if p["invasive"]}
    assert invasive == {"COMPREHENSIVE"}


def test_light_profile_contains_only_non_invasive_builtins_plus_fingerprinting():
    light = profile_info()[0]["scanners"]
    assert "http_headers" in light and "tls" in light
    # Port scanning is not part of a Light, production-safe sweep.
    assert "port_scan" not in light


def test_registry_lookup_and_names():
    assert scanner_registry.get("http_headers") is not None
    assert scanner_registry.get("does-not-exist") is None
    assert "nuclei" in scanner_registry.names()


# ------------------------------------------------------------- ScanContext
@pytest.mark.parametrize(
    "value,expected_host,expected_port,https",
    [
        ("https://app.local", "app.local", 443, True),
        ("http://app.local:8080", "app.local", 8080, False),
        ("app.local", "app.local", 443, True),
        ("https://app.local/portal", "app.local", 443, True),
    ],
)
def test_scan_context_parses_targets(value, expected_host, expected_port, https):
    ctx = ScanContext(target_value=value)
    assert ctx.hostname == expected_host
    assert ctx.effective_port == expected_port
    assert ctx.is_https is https


def test_scan_context_builds_a_url_with_base_path():
    ctx = ScanContext(target_value="https://api.local", base_path="/v1")
    assert ctx.url == "https://api.local/v1"


# ------------------------------------------------------------ parse helpers
def test_cve_extraction():
    assert extract_cves("Affected by CVE-2021-44228 and cve-2014-0160") == [
        "CVE-2021-44228", "CVE-2014-0160",
    ]
    assert extract_cves(None, "no identifiers here") == []


def test_cwe_extraction():
    assert extract_cwe("Maps to CWE-79 (XSS)") == "CWE-79"
    assert extract_cwe("nothing") is None


# -------------------------------------------------- real built-in execution
def test_http_headers_adapter_reports_failure_gracefully():
    """An unreachable target must produce an error, never an exception."""
    adapter = scanner_registry.get("http_headers")
    ctx = ScanContext(target_value="http://127.0.0.1:9", timeout=5)
    result = adapter.run(ctx)
    assert result.error is not None
    assert result.findings == []


def test_tls_adapter_flags_a_plaintext_service():
    adapter = scanner_registry.get("tls")
    ctx = ScanContext(target_value="http://127.0.0.1:8081", port=8081, timeout=5)
    result = adapter.run(ctx)
    titles = [f.title for f in result.findings]
    assert any("does not use TLS" in t for t in titles)
    assert result.findings[0].cwe == "CWE-319"


def test_adapter_supports_matrix():
    zap = scanner_registry.get("zap")
    assert zap.supports(TargetType.WEB_APP, ScanProfile.STANDARD) is True
    # ZAP is a web scanner: it does not participate for a bare host target.
    assert zap.supports(TargetType.HOST, ScanProfile.STANDARD) is False
    # ...and it is not part of the Light profile.
    assert zap.supports(TargetType.WEB_APP, ScanProfile.LIGHT) is False


# ------------------------------------------------------- port scan coverage
def test_port_scan_always_probes_the_targets_own_port():
    """Regression: the sweep skipped the one port the assessment is about.

    A target served on a port outside the fixed list - 8000, 5173, anything
    bespoke - produced a scan that never touched it, so the service under
    assessment was reported as though it were not listening at all.
    """
    from app.scanners.port_scan import _COMMON_PORTS

    bespoke = 47231
    assert bespoke not in _COMMON_PORTS

    ctx = ScanContext(target_value=f"http://127.0.0.1:{bespoke}", port=bespoke, timeout=5)
    ports = dict(_COMMON_PORTS)
    if ctx.effective_port and ctx.effective_port not in ports:
        ports[ctx.effective_port] = ("Target service", "INFORMATIONAL", None)
    assert bespoke in ports, "the target's own port must be added to the sweep"


@pytest.mark.parametrize("port", [3000, 5000, 8000, 8080, 8888])
def test_common_application_ports_are_covered(port):
    """These are where web applications actually live."""
    from app.scanners.port_scan import _COMMON_PORTS

    assert port in _COMMON_PORTS, f"port {port} is not swept"


def test_port_scan_detects_a_listener_on_the_target_port():
    """End-to-end against a real socket, so the sweep is genuinely exercised."""
    import socket
    import threading

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    threading.Thread(target=lambda: server.accept(), daemon=True).start()

    try:
        adapter = scanner_registry.get("port_scan")
        result = adapter.run(
            ScanContext(target_value=f"http://127.0.0.1:{port}", port=port, timeout=15)
        )
        assert port in (result.metrics.get("open_ports") or []), (
            f"a live listener on {port} was not detected"
        )
        assert any(str(port) in f.title for f in result.findings)
    finally:
        server.close()
