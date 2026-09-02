"""Attack-path analysis.

Individually a missing security header and a stale library are moderate
findings. Together they are often a chain: the first tells an attacker what to
aim at, the second gives them the way in. This service looks for those pairs
within an assessment and surfaces them as explicit paths.

The chain rules are a small, deliberately hand-written table rather than
anything inferred — every edge in the graph can be explained in a sentence, and
the outcome is presented as a *potential* consequence that an analyst still has
to confirm. Endpoint grouping reuses `correlation.normalize_endpoint()` so a
path is only drawn between findings that genuinely sit on the same surface.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.models.enums import SEVERITY_ORDER, FindingStatus, Severity, VerificationStatus
from app.models.finding import Finding
from app.services import correlation

# Statuses that mean a finding no longer represents a live foothold.
_INACTIVE = (FindingStatus.CLOSED, FindingStatus.FALSE_POSITIVE)


@dataclass(frozen=True)
class Match:
    """Matches a finding by category, CWE or keyword.

    By default the three signals are alternatives. Some rules turn on a
    specific idea rather than a broad class — "an *admin* surface is exposed"
    is not the same claim as "something is disclosed" — so those set
    `require_keyword`, which makes a keyword hit mandatory. Without it the
    keyword list would be decorative and the rule would fire far too often.
    """

    categories: frozenset[str] = field(default_factory=frozenset)
    cwes: frozenset[str] = field(default_factory=frozenset)
    keywords: tuple[str, ...] = ()
    require_keyword: bool = False

    def _keyword_hit(self, finding: Finding) -> bool:
        """Keywords are matched against the title only.

        Descriptions are prose and routinely mention adjacent concepts — the
        text explaining a missing Content-Security-Policy says the header
        defends against cross-site scripting, which would otherwise make that
        finding match as though it *were* an XSS. The title states what the
        finding is; the description merely discusses it.
        """
        if not self.keywords:
            return False
        title = (finding.title or "").lower()
        return any(keyword in title for keyword in self.keywords)

    def _class_hit(self, finding: Finding) -> bool:
        if finding.cwe_id and finding.cwe_id in self.cwes:
            return True
        return bool(finding.category and finding.category in self.categories)

    def matches(self, finding: Finding) -> bool:
        constrained = bool(self.cwes or self.categories)
        if self.require_keyword:
            # The keyword carries the rule's specific idea, and any class
            # constraint still has to hold alongside it.
            return self._keyword_hit(finding) and (self._class_hit(finding) if constrained else True)
        return self._class_hit(finding) or self._keyword_hit(finding)


@dataclass(frozen=True)
class ChainRule:
    """A prerequisite finding plus an enabler finding implying an outcome."""

    id: str
    name: str
    prerequisite: Match
    enabler: Match
    outcome: str
    outcome_severity: str
    rationale: str


CHAIN_RULES: tuple[ChainRule, ...] = (
    ChainRule(
        id="admin-surface-weak-auth",
        name="Exposed admin surface + weak authentication",
        prerequisite=Match(
            categories=frozenset({"Information Disclosure", "Security Misconfiguration", "Reconnaissance"}),
            keywords=("admin", "dashboard", "console", "panel", "phpmyadmin", "directory listing"),
            require_keyword=True,
        ),
        enabler=Match(
            categories=frozenset({"Authentication", "Session Management", "Access Control"}),
            cwes=frozenset({"CWE-287", "CWE-306", "CWE-521", "CWE-798", "CWE-862", "CWE-863"}),
        ),
        outcome="Administrative account takeover and bulk data exposure",
        outcome_severity=Severity.CRITICAL,
        rationale=(
            "A discoverable administrative surface tells an attacker exactly where to aim. "
            "Combined with weak or missing authentication on that surface, it becomes a "
            "direct route to an administrative session and everything it can reach."
        ),
    ),
    ChainRule(
        id="disclosure-outdated-component",
        name="Version disclosure + outdated component",
        prerequisite=Match(
            categories=frozenset({"Information Disclosure", "Reconnaissance"}),
            cwes=frozenset({"CWE-200"}),
            keywords=("version", "disclosure", "banner", "fingerprint", "x-powered-by", "technology stack"),
            require_keyword=True,
        ),
        enabler=Match(
            categories=frozenset({"Supply Chain", "Memory Safety"}),
            cwes=frozenset({"CWE-502", "CWE-829", "CWE-94", "CWE-119"}),
            keywords=("cve-", "outdated", "known vulnerability", "deserializ", "log4j"),
        ),
        outcome="Remote code execution via a publicly known exploit",
        outcome_severity=Severity.CRITICAL,
        rationale=(
            "Disclosed version numbers let an attacker match the stack against public "
            "vulnerability databases without touching the application. When a component "
            "with a known exploit is present, selecting a working payload is trivial."
        ),
    ),
    ChainRule(
        id="xss-weak-cookie",
        name="Cross-site scripting + cookie without HttpOnly",
        prerequisite=Match(
            cwes=frozenset({"CWE-79"}),
            keywords=("cross-site scripting", "xss", "innerhtml"),
        ),
        enabler=Match(
            cwes=frozenset({"CWE-1004", "CWE-614", "CWE-1275", "CWE-384"}),
            keywords=("httponly", "samesite", "secure attribute", "session fixation"),
        ),
        outcome="Session hijacking through stolen session cookies",
        outcome_severity=Severity.HIGH,
        rationale=(
            "Script injection alone is limited by what the browser will let it read. A "
            "session cookie without HttpOnly removes that limit, turning any XSS into "
            "full session theft."
        ),
    ),
    ChainRule(
        id="injection-credential-storage",
        name="Injection + weakly protected credentials",
        prerequisite=Match(
            cwes=frozenset({"CWE-89", "CWE-78", "CWE-22", "CWE-611", "CWE-918"}),
        ),
        enabler=Match(
            categories=frozenset({"Cryptography"}),
            cwes=frozenset({"CWE-256", "CWE-311", "CWE-327", "CWE-522", "CWE-798"}),
            keywords=("plaintext", "hard-coded", "hardcoded", "weak hash", "md5", "sha1"),
        ),
        outcome="Mass credential compromise and lateral movement",
        outcome_severity=Severity.CRITICAL,
        rationale=(
            "An injection flaw that reaches the data store is far more damaging when the "
            "credentials it exposes are unencrypted or weakly hashed — they can be reused "
            "directly against this system and others."
        ),
    ),
    ChainRule(
        id="exposed-service-weak-auth",
        name="Exposed management service + weak authentication",
        prerequisite=Match(
            categories=frozenset({"Network Exposure"}),
            cwes=frozenset({"CWE-668"}),
            keywords=("open port", "redis", "mongodb", "elasticsearch", "mysql", "postgresql", "rdp", "smb"),
        ),
        enabler=Match(
            categories=frozenset({"Authentication"}),
            cwes=frozenset({"CWE-287", "CWE-306", "CWE-521"}),
            keywords=("default credential", "no authentication", "anonymous"),
        ),
        outcome="Direct data exfiltration from an exposed datastore",
        outcome_severity=Severity.CRITICAL,
        rationale=(
            "A datastore or management service reachable from an untrusted network is "
            "already high risk; without enforced authentication it is an open door that "
            "needs no exploit at all."
        ),
    ),
    ChainRule(
        id="cleartext-session-exposure",
        name="Cleartext transport + session cookie without Secure",
        prerequisite=Match(
            cwes=frozenset({"CWE-319", "CWE-326", "CWE-327", "CWE-295"}),
            keywords=("hsts", "cleartext", "tls 1.0", "tls 1.1", "does not use tls", "weak cipher"),
        ),
        enabler=Match(
            cwes=frozenset({"CWE-614", "CWE-384"}),
            keywords=("secure attribute", "secure flag"),
        ),
        outcome="Session token interception on the network path",
        outcome_severity=Severity.HIGH,
        rationale=(
            "Without enforced HTTPS a session cookie that lacks the Secure attribute will "
            "eventually be transmitted in the clear, where anyone on the network path can "
            "read and replay it."
        ),
    ),
    ChainRule(
        id="ssrf-internal-exposure",
        name="Server-side request forgery + reachable internal service",
        prerequisite=Match(
            cwes=frozenset({"CWE-918"}),
            keywords=("ssrf", "server-side request forgery"),
        ),
        enabler=Match(
            categories=frozenset({"Network Exposure"}),
            cwes=frozenset({"CWE-668", "CWE-306"}),
            keywords=("open port", "internal", "metadata"),
        ),
        outcome="Pivot into internal services from the application server",
        outcome_severity=Severity.HIGH,
        rationale=(
            "SSRF turns the application into a proxy for the internal network. Any "
            "unauthenticated internal service then becomes reachable from the internet "
            "through it."
        ),
    ),
)


def _active_findings(db: Session, assessment_id: int) -> list[Finding]:
    return (
        db.query(Finding)
        .filter(
            Finding.assessment_id == assessment_id,
            Finding.status.notin_(_INACTIVE),
            Finding.verification_status != VerificationStatus.FALSE_POSITIVE,
            Finding.is_suppressed.is_(False),
        )
        .all()
    )


def _surface_key(finding: Finding) -> tuple:
    """The surface a finding sits on: its target, then its host+path.

    Endpoint normalisation is reused from the correlation engine so query
    strings and trailing slashes do not split one surface into several.
    """
    return (finding.target_id, correlation.normalize_endpoint(finding.endpoint))


def _node(finding: Finding) -> dict:
    return {
        "id": f"finding-{finding.id}",
        "kind": "finding",
        "finding_id": finding.id,
        "reference": finding.reference,
        "title": finding.title,
        "severity": finding.severity,
        "category": finding.category,
        "cwe_id": finding.cwe_id,
        "status": finding.status,
        "endpoint": finding.endpoint,
        "target_id": finding.target_id,
        "target_name": finding.target.name if finding.target else None,
    }


def build_attack_paths(db: Session, assessment_id: int) -> dict:
    """Find chains among an assessment's live findings.

    Returns a node/edge graph plus a per-path summary. Only findings that are
    still live count — a closed or false-positive finding is not a foothold.
    """
    findings = _active_findings(db, assessment_id)

    # Group by target first, so a chain never spans two unrelated systems.
    by_target: dict[int | None, list[Finding]] = {}
    for finding in findings:
        by_target.setdefault(finding.target_id, []).append(finding)

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    paths: list[dict] = []

    for target_id, group in by_target.items():
        for rule in CHAIN_RULES:
            prerequisites = [f for f in group if rule.prerequisite.matches(f)]
            enablers = [f for f in group if rule.enabler.matches(f)]
            if not prerequisites or not enablers:
                continue

            for prerequisite in prerequisites:
                for enabler in enablers:
                    if prerequisite.id == enabler.id:
                        continue
                    # Grouping by target already keeps a chain inside one system.
                    # Sharing an exact surface makes the chain stronger, but it
                    # is not a precondition: XSS on /search is perfectly capable
                    # of stealing a cookie issued at /login.
                    same_surface = _surface_key(prerequisite) == _surface_key(enabler)

                    outcome_id = f"outcome-{target_id}-{rule.id}"
                    if outcome_id not in nodes:
                        nodes[outcome_id] = {
                            "id": outcome_id,
                            "kind": "outcome",
                            "title": rule.outcome,
                            "severity": rule.outcome_severity,
                            "rule_id": rule.id,
                            "rule_name": rule.name,
                            "rationale": rule.rationale,
                            "target_id": target_id,
                            "target_name": prerequisite.target.name if prerequisite.target else None,
                        }

                    for source, role in ((prerequisite, "prerequisite"), (enabler, "enabler")):
                        node = _node(source)
                        nodes.setdefault(node["id"], node)
                        edge_id = f"{node['id']}->{outcome_id}"
                        if not any(e["id"] == edge_id for e in edges):
                            edges.append({
                                "id": edge_id,
                                "source": node["id"],
                                "target": outcome_id,
                                "role": role,
                                "rule_id": rule.id,
                                "label": "enables" if role == "enabler" else "exposes",
                            })

                    paths.append({
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "outcome": rule.outcome,
                        "outcome_severity": rule.outcome_severity,
                        "rationale": rule.rationale,
                        "target_id": target_id,
                        "target_name": prerequisite.target.name if prerequisite.target else None,
                        "prerequisite": {
                            "finding_id": prerequisite.id,
                            "reference": prerequisite.reference,
                            "title": prerequisite.title,
                            "severity": prerequisite.severity,
                        },
                        "enabler": {
                            "finding_id": enabler.id,
                            "reference": enabler.reference,
                            "title": enabler.title,
                            "severity": enabler.severity,
                        },
                        # The whole point: the chain outranks either finding alone.
                        "same_surface": same_surface,
                        "escalates": SEVERITY_ORDER.get(rule.outcome_severity, 0) > max(
                            SEVERITY_ORDER.get(prerequisite.severity, 0),
                            SEVERITY_ORDER.get(enabler.severity, 0),
                        ),
                    })

    paths.sort(key=lambda p: -SEVERITY_ORDER.get(p["outcome_severity"], 0))
    highest = paths[0]["outcome_severity"] if paths else None

    return {
        "assessment_id": assessment_id,
        "nodes": list(nodes.values()),
        "edges": edges,
        "paths": paths,
        "summary": {
            "paths": len(paths),
            "escalating_paths": sum(1 for p in paths if p["escalates"]),
            "findings_considered": len(findings),
            "findings_in_paths": sum(1 for n in nodes.values() if n["kind"] == "finding"),
            "highest_outcome_severity": highest,
            "rules_evaluated": len(CHAIN_RULES),
        },
    }
