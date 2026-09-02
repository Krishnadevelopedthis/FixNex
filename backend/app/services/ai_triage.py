"""AI-assisted triage suggestions.

Given a finding, this asks Claude two questions an analyst would otherwise
answer from scratch: how likely is this a false positive, and what would the
fix look like. The answer is a **suggestion**, never a verdict — nothing here
writes `verification_status`, `severity`, `status` or risk. The analyst still
clicks confirm or reject exactly as before.

Like Redis, MinIO and the external scanners, this degrades rather than fails:
with no API key configured the service reports itself unavailable and the rest
of the platform is unaffected.
"""
from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import AppError
from app.db.base import utcnow
from app.models.finding import Finding

logger = logging.getLogger("prcampus.ai_triage")

# The model is asked for exactly these fields, and the schema is enforced
# server-side so the response cannot drift into prose.
RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "false_positive_confidence": {
            "type": "number",
            "description": (
                "0.0 means almost certainly a real issue; 1.0 means almost certainly "
                "a false positive. Use the middle of the range when genuinely unsure."
            ),
        },
        "reasoning": {
            "type": "string",
            "description": (
                "Two to four sentences explaining the confidence, citing the specific "
                "evidence in the finding. Say plainly when the evidence is insufficient."
            ),
        },
        "suggested_fix": {
            "type": "string",
            "description": (
                "A concrete remediation, with a short code or configuration snippet "
                "where one applies. Empty string if the finding is likely a false positive."
            ),
        },
        "verification_steps": {
            "type": "string",
            "description": "How a human could confirm or refute this finding themselves.",
        },
    },
    "required": ["false_positive_confidence", "reasoning", "suggested_fix", "verification_steps"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = (
    "You are assisting a security analyst triaging findings in an authorised security "
    "assessment. Judge only from the evidence given.\n\n"
    "Be candid about uncertainty: scanners report things that are real, things that are "
    "artefacts of how they probe, and things that are real but unreachable in this "
    "deployment. If the evidence does not let you distinguish those, say so and use a "
    "confidence near the middle rather than committing to a number you cannot support.\n\n"
    "Your output is a suggestion shown alongside the analyst's own verification controls. "
    "It never changes the finding's status by itself, so do not write as though it will."
)


class AITriageUnavailable(AppError):
    status_code = 503
    code = "ai_triage_unavailable"
    message = "AI triage is not configured."


def availability() -> tuple[bool, str]:
    """Whether triage can run, and why not if it cannot.

    Mirrors the scanner availability contract so the System Health page can
    present it the same way as everything else that is optional.
    """
    if not settings.AI_TRIAGE_ENABLED:
        return False, "AI triage is disabled by configuration (AI_TRIAGE_ENABLED=false)."
    if settings.OFFLINE_MODE:
        return False, "OFFLINE_MODE is enabled; no external API is called."
    if not settings.ANTHROPIC_API_KEY:
        return False, (
            "No ANTHROPIC_API_KEY is configured. Set one to enable AI triage suggestions; "
            "every other part of the platform works without it."
        )
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False, (
            "The `anthropic` package is not installed. Run `pip install anthropic` to "
            "enable AI triage suggestions."
        )
    return True, f"Configured with model {settings.AI_TRIAGE_MODEL}."


def _finding_brief(finding: Finding) -> str:
    """The evidence the model is allowed to reason from."""

    def section(label: str, value: Any) -> str:
        return f"{label}: {value}\n" if value else ""

    parts = [
        f"Title: {finding.title}\n",
        section("Severity reported by the tool", finding.severity),
        section("Detected by", finding.primary_source),
        section("Reported by this many independent tools", finding.source_count),
        section("Scanner confidence", f"{finding.confidence:.0%}"),
        section("CWE", f"{finding.cwe_id} {finding.cwe_name or ''}".strip()),
        section("CVE", ", ".join(finding.cve_ids or [])),
        section("CVSS", f"{finding.cvss_score} ({finding.cvss_vector})" if finding.cvss_score else None),
        section("Category", finding.category),
        section("Affected endpoint", finding.endpoint),
        section("Parameter", finding.parameter),
        section("HTTP method", finding.http_method),
        section("Description", finding.description),
        section("Evidence captured by the tool", (finding.technical_details or "")[:2000]),
        section("Request", (finding.request_snippet or "")[:1500]),
        section("Response", (finding.response_snippet or "")[:1500]),
    ]
    return "".join(p for p in parts if p)


def _build_prompt(finding: Finding) -> str:
    return (
        "Assess the finding below.\n\n"
        "1. How likely is it a false positive?\n"
        "2. If it is real, what is the concrete fix?\n"
        "3. How could an analyst verify it themselves?\n\n"
        f"----- FINDING {finding.reference} -----\n{_finding_brief(finding)}"
    )


def _call_model(finding: Finding) -> dict:
    """One structured request to Claude. Raises AITriageUnavailable on failure."""
    import anthropic

    client = anthropic.Anthropic(
        api_key=settings.ANTHROPIC_API_KEY,
        timeout=float(settings.AI_TRIAGE_TIMEOUT_SECONDS),
        max_retries=1,
    )

    try:
        response = client.beta.messages.create(
            model=settings.AI_TRIAGE_MODEL,
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": _build_prompt(finding)}],
            output_config={
                "format": {"type": "json_schema", "schema": RESPONSE_SCHEMA},
                "effort": settings.AI_TRIAGE_EFFORT,
            },
            # Route around a safety refusal rather than surfacing a dead end;
            # security findings legitimately contain attack-shaped text.
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
    except anthropic.AuthenticationError as exc:
        raise AITriageUnavailable("The configured ANTHROPIC_API_KEY was rejected.") from exc
    except anthropic.PermissionDeniedError as exc:
        raise AITriageUnavailable("The API key lacks permission for this model.") from exc
    except anthropic.RateLimitError as exc:
        raise AITriageUnavailable("Rate limited by the API. Try again shortly.") from exc
    except anthropic.APIConnectionError as exc:
        raise AITriageUnavailable("Could not reach the API. Check network connectivity.") from exc
    except anthropic.APIStatusError as exc:
        raise AITriageUnavailable(f"The API returned an error ({exc.status_code}).") from exc
    except Exception as exc:  # pragma: no cover - unexpected client failure
        logger.exception("Unexpected AI triage failure")
        raise AITriageUnavailable(f"AI triage failed: {type(exc).__name__}") from exc

    if getattr(response, "stop_reason", None) == "refusal":
        raise AITriageUnavailable(
            "The model declined to assess this finding. Verify it manually."
        )

    text = next((b.text for b in response.content if getattr(b, "type", None) == "text"), None)
    if not text:
        raise AITriageUnavailable("The model returned no assessable content.")

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AITriageUnavailable("The model's response was not valid JSON.") from exc

    confidence = parsed.get("false_positive_confidence")
    try:
        confidence = round(min(1.0, max(0.0, float(confidence))), 2)
    except (TypeError, ValueError):
        confidence = 0.5

    usage = getattr(response, "usage", None)
    return {
        "false_positive_confidence": confidence,
        "reasoning": str(parsed.get("reasoning") or "").strip(),
        "suggested_fix": str(parsed.get("suggested_fix") or "").strip(),
        "verification_steps": str(parsed.get("verification_steps") or "").strip(),
        "model": settings.AI_TRIAGE_MODEL,
        "effort": settings.AI_TRIAGE_EFFORT,
        "generated_at": utcnow().isoformat(),
        "input_tokens": getattr(usage, "input_tokens", None) if usage else None,
        "output_tokens": getattr(usage, "output_tokens", None) if usage else None,
    }


def _is_fresh(finding: Finding) -> bool:
    if not finding.ai_triage or not finding.ai_triage_at:
        return False
    age_limit = timedelta(hours=settings.AI_TRIAGE_CACHE_HOURS)
    stamp = finding.ai_triage_at
    if stamp.tzinfo is None:
        from datetime import timezone

        stamp = stamp.replace(tzinfo=timezone.utc)
    return utcnow() - stamp < age_limit


def suggest(db: Session, finding: Finding, refresh: bool = False) -> dict:
    """Return a cached or freshly generated triage suggestion.

    This function deliberately mutates only the two cache columns. It never
    touches verification_status, severity, status or risk — the suggestion is
    surfaced next to the analyst's controls, and they decide.
    """
    if not refresh and _is_fresh(finding):
        return {**finding.ai_triage, "cached": True}

    available, detail = availability()
    if not available:
        raise AITriageUnavailable(detail)

    result = _call_model(finding)

    finding.ai_triage = result
    finding.ai_triage_at = utcnow()
    db.commit()
    db.refresh(finding)
    return {**result, "cached": False}


def cached_suggestion(finding: Finding) -> dict | None:
    """The stored suggestion, if any — used when rendering a finding."""
    if not finding.ai_triage:
        return None
    return {**finding.ai_triage, "cached": True}
