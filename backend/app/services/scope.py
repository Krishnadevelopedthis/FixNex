"""Authorised scope enforcement.

No scan may run against anything that is not explicitly inside its
assessment's authorised scope. Every scan request is checked here, and a
rejection is written to the audit log.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.core.exceptions import ValidationError
from app.models.assessment import Assessment
from app.models.enums import ScopeRuleType
from app.models.target import ScopeRule

_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-_.]{0,251}[a-zA-Z0-9])?$")


@dataclass
class ScopeDecision:
    in_scope: bool
    reason: str
    matched_rule: ScopeRule | None = None


def parse_host(value: str) -> str:
    """Extract a bare hostname or IP from a URL, host:port pair or hostname."""
    value = (value or "").strip()
    if not value:
        return ""
    candidate = value if "://" in value else f"//{value}"
    parsed = urlparse(candidate)
    host = parsed.hostname or value.split("/")[0].split(":")[0]
    return (host or "").lower().rstrip(".")


def normalize_url(value: str) -> str:
    value = (value or "").strip().lower()
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlparse(value)
    path = (parsed.path or "").rstrip("/")
    return f"{parsed.hostname or ''}{path}"


def validate_target_value(value: str, rule_type: str | None = None) -> str:
    """Reject values that could not be a legitimate target before storing them."""
    value = (value or "").strip()
    if not value:
        raise ValidationError("A target value is required.")
    if any(ch in value for ch in ("\n", "\r", "\x00", " ", ";", "|", "&", "`", "$")):
        raise ValidationError("The target value contains characters that are not permitted.")
    if rule_type == ScopeRuleType.CIDR:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValidationError(f"'{value}' is not a valid CIDR range.") from exc
        return value
    if rule_type == ScopeRuleType.IP:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValidationError(f"'{value}' is not a valid IP address.") from exc
        return value
    host = parse_host(value)
    if not host:
        raise ValidationError(f"Could not determine a hostname from '{value}'.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME_RE.match(host):
            raise ValidationError(f"'{host}' is not a valid hostname.") from None
    return value


def _matches(rule: ScopeRule, value: str) -> bool:
    host = parse_host(value)
    rule_value = (rule.value or "").strip().lower()

    if rule.rule_type == ScopeRuleType.DOMAIN:
        return host == rule_value.lstrip("*.")

    if rule.rule_type == ScopeRuleType.WILDCARD_DOMAIN:
        base = rule_value.lstrip("*").lstrip(".")
        return host == base or host.endswith(f".{base}")

    if rule.rule_type in (ScopeRuleType.URL, ScopeRuleType.API_ENDPOINT):
        return normalize_url(value).startswith(normalize_url(rule_value))

    if rule.rule_type == ScopeRuleType.IP:
        return host == rule_value

    if rule.rule_type == ScopeRuleType.CIDR:
        try:
            network = ipaddress.ip_network(rule_value, strict=False)
        except ValueError:
            return False
        try:
            return ipaddress.ip_address(host) in network
        except ValueError:
            # Hostnames are not resolved here: DNS could change between the
            # check and the scan, so only literal addresses match a CIDR rule.
            return False

    return False


def check(db: Session, assessment: Assessment, value: str) -> ScopeDecision:
    """Decide whether `value` is inside the assessment's authorised scope."""
    rules = (
        db.query(ScopeRule)
        .filter(ScopeRule.assessment_id == assessment.id)
        .order_by(ScopeRule.is_exclusion.desc())
        .all()
    )
    if not rules:
        return ScopeDecision(
            False,
            "No authorised scope has been defined for this assessment. Add at least one "
            "scope rule before scanning.",
        )

    # Exclusions always win, so an excluded host inside an allowed domain stays out.
    for rule in rules:
        if rule.is_exclusion and _matches(rule, value):
            return ScopeDecision(
                False,
                f"'{value}' matches the explicit exclusion rule "
                f"{rule.rule_type} = {rule.value}.",
                rule,
            )

    for rule in rules:
        if not rule.is_exclusion and _matches(rule, value):
            return ScopeDecision(
                True,
                f"Authorised by scope rule {rule.rule_type} = {rule.value}.",
                rule,
            )

    return ScopeDecision(
        False,
        f"'{value}' does not match any authorised scope rule for assessment "
        f"{assessment.reference}.",
    )
