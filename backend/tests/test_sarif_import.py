"""SARIF 2.1.0 import — parsing and the import route."""
from __future__ import annotations

import io
import json

import pytest

from app.core.exceptions import ValidationError
from app.core.permissions import Role
from app.models.enums import DataOrigin, ScanProfile, Severity
from app.scanners.sarif_import import (
    SARIF_LEVEL_SEVERITY,
    parse_sarif,
    parse_sarif_bytes,
    tool_name_from,
)


def sarif(results, rules=None, tool="Semgrep"):
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool, "rules": rules or []}},
            "results": results,
        }],
    }


def rule(rule_id, **kw):
    base = {"id": rule_id, "name": kw.pop("name", rule_id)}
    base.update(kw)
    return base


# --------------------------------------------------------------------- parsing
def test_parses_a_minimal_result():
    doc = sarif([{
        "ruleId": "py.sqli",
        "level": "error",
        "message": {"text": "SQL injection detected."},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "app/db.py"},
            "region": {"startLine": 42},
        }}],
    }])
    findings, metrics = parse_sarif(doc, "semgrep", "https://app.local")
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "imported:semgrep"
    assert f.target == "https://app.local"
    assert f.endpoint == "app/db.py:42"
    assert "SQL injection" in f.description
    assert metrics["results_imported"] == 1


@pytest.mark.parametrize(
    "level,expected",
    [("error", Severity.HIGH), ("warning", Severity.MEDIUM),
     ("note", Severity.LOW), ("none", Severity.INFORMATIONAL)],
)
def test_sarif_levels_map_to_canonical_severity(level, expected):
    doc = sarif([{"ruleId": "r", "level": level, "message": {"text": "m"}}])
    findings, _ = parse_sarif(doc, "tool")
    assert findings[0].severity == expected
    assert SARIF_LEVEL_SEVERITY[level] == expected


def test_security_severity_beats_level():
    """The numeric score is more precise than SARIF's four levels, so it wins."""
    doc = sarif(
        [{"ruleId": "r", "level": "warning", "message": {"text": "m"}}],
        rules=[rule("r", properties={"security-severity": "9.4"})],
    )
    findings, _ = parse_sarif(doc, "tool")
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].cvss == 9.4


def test_unknown_level_falls_back_to_the_shared_alias_table():
    doc = sarif([{"ruleId": "r", "level": "critical", "message": {"text": "m"}}])
    findings, _ = parse_sarif(doc, "tool")
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.parametrize(
    "tag,expected",
    [("external/cwe/cwe-089", "CWE-89"), ("CWE-79", "CWE-79"),
     ("cwe:352", "CWE-352"), ("cwe-798", "CWE-798")],
)
def test_cwe_extracted_from_assorted_tag_shapes(tag, expected):
    doc = sarif(
        [{"ruleId": "r", "level": "error", "message": {"text": "m"}}],
        rules=[rule("r", properties={"tags": ["security", tag]})],
    )
    findings, _ = parse_sarif(doc, "tool")
    assert findings[0].cwe == expected


def test_cve_extracted_from_rule_id():
    doc = sarif([{"ruleId": "CVE-2021-44228", "level": "error",
                  "message": {"text": "log4j is vulnerable"}}])
    findings, _ = parse_sarif(doc, "trivy")
    assert findings[0].cve == ["CVE-2021-44228"]


def test_rule_metadata_enriches_the_finding():
    doc = sarif(
        [{"ruleId": "r", "level": "error", "message": {"text": "Found it."}}],
        rules=[rule(
            "r", name="Raw SQL query",
            shortDescription={"text": "short"},
            fullDescription={"text": "Long explanation."},
            help={"text": "Use parameterised queries."},
            helpUri="https://example.com/rule",
        )],
    )
    f = parse_sarif(doc, "semgrep")[0][0]
    assert f.title == "Raw SQL query"
    assert "Long explanation." in f.description
    assert f.remediation == "Use parameterised queries."
    assert "https://example.com/rule" in f.references


def test_rule_resolved_by_index_when_ruleid_is_absent():
    doc = sarif(
        [{"ruleIndex": 0, "level": "error", "message": {"text": "m"}}],
        rules=[rule("indexed.rule", name="Indexed rule")],
    )
    assert parse_sarif(doc, "tool")[0][0].title == "Indexed rule"


def test_suppressed_results_are_skipped_and_counted():
    doc = sarif([
        {"ruleId": "a", "level": "error", "message": {"text": "kept"}},
        {"ruleId": "b", "level": "error", "message": {"text": "dismissed"},
         "suppressions": [{"status": "accepted"}]},
    ])
    findings, metrics = parse_sarif(doc, "tool")
    assert len(findings) == 1
    assert metrics["results_suppressed"] == 1


def test_logical_location_used_when_no_physical_location():
    doc = sarif([{"ruleId": "r", "level": "error", "message": {"text": "m"},
                  "locations": [{"logicalLocations": [{"fullyQualifiedName": "com.app.Service.run"}]}]}])
    assert parse_sarif(doc, "tool")[0][0].endpoint == "com.app.Service.run"


def test_multiple_runs_are_all_parsed():
    doc = {"version": "2.1.0", "runs": [
        {"tool": {"driver": {"name": "A"}}, "results": [{"ruleId": "a", "message": {"text": "1"}}]},
        {"tool": {"driver": {"name": "B"}}, "results": [{"ruleId": "b", "message": {"text": "2"}}]},
    ]}
    findings, metrics = parse_sarif(doc, "tool")
    assert len(findings) == 2
    assert metrics["runs"] == 2


def test_tool_name_read_from_document():
    assert tool_name_from(sarif([], tool="Gitleaks")) == "Gitleaks"


# ------------------------------------------------------------------ rejection
def test_non_json_is_rejected():
    with pytest.raises(ValidationError):
        parse_sarif_bytes(b"<xml>not sarif</xml>", "tool")


def test_json_without_runs_is_rejected():
    with pytest.raises(ValidationError):
        parse_sarif({"version": "2.1.0"}, "tool")


def test_oversized_file_is_rejected():
    from app.scanners import sarif_import

    with pytest.raises(ValidationError):
        sarif_import.parse_sarif_bytes(b"x" * (sarif_import.MAX_SARIF_BYTES + 1), "tool")


def test_result_cap_is_enforced():
    from app.scanners import sarif_import

    doc = sarif([{"ruleId": f"r{i}", "message": {"text": "m"}}
                 for i in range(sarif_import.MAX_RESULTS + 50)])
    findings, metrics = parse_sarif(doc, "tool")
    assert len(findings) == sarif_import.MAX_RESULTS
    assert metrics["truncated"] is True


# ---------------------------------------------------------------------- route
def upload(client, headers, assessment_id, target_id, doc, tool="semgrep"):
    return client.post(
        "/api/scans/import",
        headers=headers,
        data={"assessment_id": str(assessment_id), "target_id": str(target_id), "tool_name": tool},
        files={"file": ("report.sarif", json.dumps(doc).encode(), "application/json")},
    )


def test_import_creates_a_scan_job_and_findings(client, auth, assessment, target):
    doc = sarif(
        [{"ruleId": "py.sqli", "level": "error",
          "message": {"text": "SQL injection in the results lookup."},
          "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/db.py"},
                                              "region": {"startLine": 42}}}]}],
        rules=[rule("py.sqli", name="SQL injection",
                    properties={"tags": ["external/cwe/cwe-089"], "security-severity": "9.1"})],
    )
    response = upload(client, auth(Role.SECURITY_ENGINEER), assessment.id, target.id, doc)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["profile"] == ScanProfile.IMPORTED
    assert body["status"] == "COMPLETED"
    assert body["findings_count"] == 1
    assert body["scanner_runs"][0]["scanner"] == "imported:semgrep"


def test_imported_findings_are_labelled_imported_not_real_scan(client, auth, assessment, target):
    doc = sarif([{"ruleId": "r", "level": "error", "message": {"text": "issue"}}])
    upload(client, auth(Role.SECURITY_ENGINEER), assessment.id, target.id, doc, tool="gitleaks")

    listing = client.get(
        "/api/findings",
        headers=auth(Role.SECURITY_ENGINEER),
        params={"assessment_id": assessment.id, "page_size": 100},
    ).json()
    imported = [f for f in listing["items"] if f["primary_source"] == "imported:gitleaks"]
    assert imported, "the imported finding should be listed"
    for finding in imported:
        # Never claim PR-CAMPUS ran the scan itself.
        assert finding["data_origin"] == DataOrigin.IMPORTED
        assert finding["data_origin"] != DataOrigin.REAL_SCAN


def test_import_goes_through_the_shared_correlation_pipeline(client, auth, assessment, target):
    """A second tool reporting the same issue merges rather than duplicating."""
    headers = auth(Role.SECURITY_ENGINEER)
    location = [{"physicalLocation": {"artifactLocation": {"uri": "app/db.py"},
                                      "region": {"startLine": 42}}}]

    first = sarif([{"ruleId": "a.sqli", "level": "error",
                    "message": {"text": "SQL injection"}, "locations": location}],
                  rules=[rule("a.sqli", properties={"tags": ["cwe-89"]})])
    second = sarif([{"ruleId": "b.taint", "level": "error",
                     "message": {"text": "Tainted input reaches a SQL sink"}, "locations": location}],
                   rules=[rule("b.taint", properties={"tags": ["cwe-89"]})])

    r1 = upload(client, headers, assessment.id, target.id, first, tool="semgrep")
    r2 = upload(client, headers, assessment.id, target.id, second, tool="trivy")
    assert r1.json()["findings_count"] == 1
    # The second tool correlates into the existing finding instead of adding one.
    assert r2.json()["findings_count"] == 0
    assert r2.json()["duplicates_merged"] == 1


def test_import_requires_scan_create_permission(client, auth, assessment, target):
    doc = sarif([{"ruleId": "r", "message": {"text": "m"}}])
    assert upload(client, auth(Role.VIEWER), assessment.id, target.id, doc).status_code == 403
    assert upload(client, auth(Role.DEVELOPER), assessment.id, target.id, doc).status_code == 403


def test_import_is_blocked_for_an_out_of_scope_target(client, auth, db, assessment, target):
    """The scope gate applies to imports exactly as it does to live scans."""
    from app.models.target import ScopeRule

    db.query(ScopeRule).filter(ScopeRule.assessment_id == assessment.id).delete()
    db.commit()

    doc = sarif([{"ruleId": "r", "message": {"text": "m"}}])
    response = upload(client, auth(Role.SECURITY_ENGINEER), assessment.id, target.id, doc)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "scope_violation"


def test_import_rejects_a_target_from_another_assessment(client, auth, assessment, target):
    doc = sarif([{"ruleId": "r", "message": {"text": "m"}}])
    response = upload(client, auth(Role.SECURITY_ENGINEER), assessment.id, 999999, doc)
    assert response.status_code == 404


def test_import_rejects_a_non_sarif_upload(client, auth, assessment, target):
    response = client.post(
        "/api/scans/import",
        headers=auth(Role.SECURITY_ENGINEER),
        data={"assessment_id": str(assessment.id), "target_id": str(target.id), "tool_name": "semgrep"},
        files={"file": ("notes.txt", b"just some text", "text/plain")},
    )
    assert response.status_code == 422


def test_import_is_audited(client, auth, assessment, target):
    doc = sarif([{"ruleId": "r", "level": "error", "message": {"text": "m"}}])
    upload(client, auth(Role.SECURITY_ENGINEER), assessment.id, target.id, doc)
    logs = client.get("/api/audit-logs", headers=auth(Role.ADMIN), params={"page_size": 100}).json()
    assert any(
        e["action"] == "scan.completed" and "Imported" in (e["description"] or "")
        for e in logs["items"]
    )


def test_known_tools_endpoint(client, auth):
    response = client.get("/api/scans/import/tools", headers=auth(Role.SECURITY_ENGINEER))
    assert response.status_code == 200
    assert "semgrep" in response.json()
