"""AI triage suggestions: availability, caching, and the never-a-verdict rule."""
from __future__ import annotations

import json
from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.core.permissions import Role
from app.db.base import utcnow
from app.models.enums import FindingStatus, Severity, VerificationStatus
from app.services import ai_triage
from app.services.ai_triage import AITriageUnavailable, availability, suggest


# --------------------------------------------------------------- fake client
def fake_response(payload: dict, stop_reason: str = "end_turn"):
    return SimpleNamespace(
        stop_reason=stop_reason,
        content=[SimpleNamespace(type="text", text=json.dumps(payload))],
        usage=SimpleNamespace(input_tokens=1200, output_tokens=300),
    )


@pytest.fixture
def stub_model(monkeypatch):
    """Stub the network call and capture the request the service builds."""
    calls: list[dict] = []
    payload = {
        "false_positive_confidence": 0.15,
        "reasoning": "The evidence shows a boolean-based payload changing the response.",
        "suggested_fix": "Use parameterised queries via the ORM.",
        "verification_steps": "Re-send the payload and compare response lengths.",
    }

    def _fake_call(finding):
        calls.append({"finding": finding})
        result = dict(payload)
        result.update({
            "model": "claude-opus-5", "effort": "medium",
            "generated_at": utcnow().isoformat(),
            "input_tokens": 1200, "output_tokens": 300,
        })
        return result

    monkeypatch.setattr(ai_triage, "_call_model", _fake_call)
    monkeypatch.setattr(ai_triage, "availability", lambda: (True, "stubbed"))
    return calls


# ------------------------------------------------------------- availability
def test_unavailable_without_an_api_key(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "")
    monkeypatch.setattr(settings, "AI_TRIAGE_ENABLED", True)
    monkeypatch.setattr(settings, "OFFLINE_MODE", False)
    available, detail = availability()
    assert available is False
    assert "ANTHROPIC_API_KEY" in detail
    # The message must tell the operator the rest of the platform still works.
    assert "works without it" in detail


def test_unavailable_when_disabled(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "AI_TRIAGE_ENABLED", False)
    assert availability()[0] is False


def test_unavailable_in_offline_mode(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "AI_TRIAGE_ENABLED", True)
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(settings, "OFFLINE_MODE", True)
    available, detail = availability()
    assert available is False and "OFFLINE_MODE" in detail


def test_available_with_a_key(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "AI_TRIAGE_ENABLED", True)
    monkeypatch.setattr(settings, "OFFLINE_MODE", False)
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-ant-test")
    assert availability()[0] is True


# ----------------------------------------------------------------- the rule
def test_suggestion_never_changes_finding_state(db, finding, stub_model):
    """The whole safety property of this feature, asserted directly."""
    before = {
        "status": finding.status,
        "verification_status": finding.verification_status,
        "severity": finding.severity,
        "cvss_score": finding.cvss_score,
        "risk_score": finding.risk_score,
        "risk_level": finding.risk_level,
        "assigned_to_id": finding.assigned_to_id,
        "is_suppressed": finding.is_suppressed,
    }
    result = suggest(db, finding)
    assert result["false_positive_confidence"] == 0.15

    db.refresh(finding)
    for field, value in before.items():
        assert getattr(finding, field) == value, f"{field} was mutated by AI triage"


def test_high_false_positive_confidence_still_changes_nothing(db, finding, monkeypatch):
    """Even a near-certain false positive is only ever a suggestion."""
    monkeypatch.setattr(ai_triage, "availability", lambda: (True, "stubbed"))
    monkeypatch.setattr(ai_triage, "_call_model", lambda f: {
        "false_positive_confidence": 0.99,
        "reasoning": "Input is HTML-encoded.", "suggested_fix": "",
        "verification_steps": "Try the payload.", "model": "m", "effort": "medium",
        "generated_at": utcnow().isoformat(), "input_tokens": 1, "output_tokens": 1,
    })
    suggest(db, finding)
    db.refresh(finding)
    assert finding.verification_status != VerificationStatus.FALSE_POSITIVE
    assert finding.status != FindingStatus.FALSE_POSITIVE


# ------------------------------------------------------------------ caching
def test_result_is_cached_on_the_finding(db, finding, stub_model):
    suggest(db, finding)
    db.refresh(finding)
    assert finding.ai_triage is not None
    assert finding.ai_triage_at is not None
    assert finding.ai_triage["false_positive_confidence"] == 0.15


def test_second_call_uses_the_cache(db, finding, stub_model):
    first = suggest(db, finding)
    second = suggest(db, finding)
    assert first["cached"] is False
    assert second["cached"] is True
    assert len(stub_model) == 1, "the model should only have been called once"


def test_refresh_bypasses_the_cache(db, finding, stub_model):
    suggest(db, finding)
    result = suggest(db, finding, refresh=True)
    assert result["cached"] is False
    assert len(stub_model) == 2


def test_stale_cache_is_regenerated(db, finding, stub_model, monkeypatch):
    from app.core.config import settings

    suggest(db, finding)
    finding.ai_triage_at = utcnow() - timedelta(hours=settings.AI_TRIAGE_CACHE_HOURS + 1)
    db.commit()
    result = suggest(db, finding)
    assert result["cached"] is False
    assert len(stub_model) == 2


def test_unavailable_service_raises_rather_than_guessing(db, finding, monkeypatch):
    monkeypatch.setattr(ai_triage, "availability", lambda: (False, "no key"))
    with pytest.raises(AITriageUnavailable):
        suggest(db, finding)


def test_a_cached_result_is_served_even_when_the_service_is_now_unavailable(
    db, finding, stub_model, monkeypatch
):
    suggest(db, finding)
    monkeypatch.setattr(ai_triage, "availability", lambda: (False, "key removed"))
    assert suggest(db, finding)["cached"] is True


# ------------------------------------------------------- response handling
def test_confidence_is_clamped_into_range(db, finding, monkeypatch):
    import anthropic

    class FakeMessages:
        def create(self, **kwargs):
            return fake_response({
                "false_positive_confidence": 7.4,  # nonsense from the model
                "reasoning": "r", "suggested_fix": "f", "verification_steps": "v",
            })

    monkeypatch.setattr(
        anthropic, "Anthropic",
        lambda **kw: SimpleNamespace(beta=SimpleNamespace(messages=FakeMessages())),
    )
    from app.core.config import settings

    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(settings, "AI_TRIAGE_ENABLED", True)
    monkeypatch.setattr(settings, "OFFLINE_MODE", False)

    assert ai_triage._call_model(finding)["false_positive_confidence"] == 1.0


def test_a_refusal_is_surfaced_not_swallowed(db, finding, monkeypatch):
    import anthropic

    class FakeMessages:
        def create(self, **kwargs):
            return fake_response({}, stop_reason="refusal")

    monkeypatch.setattr(
        anthropic, "Anthropic",
        lambda **kw: SimpleNamespace(beta=SimpleNamespace(messages=FakeMessages())),
    )
    with pytest.raises(AITriageUnavailable, match="declined"):
        ai_triage._call_model(finding)


def test_malformed_json_is_reported_not_guessed(db, finding, monkeypatch):
    import anthropic

    class FakeMessages:
        def create(self, **kwargs):
            return SimpleNamespace(
                stop_reason="end_turn",
                content=[SimpleNamespace(type="text", text="not json at all")],
                usage=None,
            )

    monkeypatch.setattr(
        anthropic, "Anthropic",
        lambda **kw: SimpleNamespace(beta=SimpleNamespace(messages=FakeMessages())),
    )
    with pytest.raises(AITriageUnavailable, match="valid JSON"):
        ai_triage._call_model(finding)


def test_request_uses_the_configured_model_and_schema(db, finding, monkeypatch):
    import anthropic
    from app.core.config import settings

    captured = {}

    class FakeMessages:
        def create(self, **kwargs):
            captured.update(kwargs)
            return fake_response({
                "false_positive_confidence": 0.2, "reasoning": "r",
                "suggested_fix": "f", "verification_steps": "v",
            })

    monkeypatch.setattr(
        anthropic, "Anthropic",
        lambda **kw: SimpleNamespace(beta=SimpleNamespace(messages=FakeMessages())),
    )
    ai_triage._call_model(finding)

    assert captured["model"] == settings.AI_TRIAGE_MODEL
    assert captured["output_config"]["format"]["type"] == "json_schema"
    assert captured["output_config"]["effort"] == settings.AI_TRIAGE_EFFORT
    # The finding's own evidence must reach the prompt.
    assert finding.title in captured["messages"][0]["content"]
    # And the model must be told its output is not a verdict.
    assert "suggestion" in captured["system"].lower()


# -------------------------------------------------------------------- route
def test_route_returns_503_when_unconfigured(client, auth, finding, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "")
    response = client.get(f"/api/findings/{finding.id}/ai-triage", headers=auth(Role.SECURITY_ENGINEER))
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "ai_triage_unavailable"


def test_route_returns_the_suggestion_with_its_disclaimer(client, auth, finding, stub_model):
    response = client.get(f"/api/findings/{finding.id}/ai-triage", headers=auth(Role.SECURITY_ENGINEER))
    assert response.status_code == 200
    body = response.json()
    assert body["false_positive_confidence"] == 0.15
    assert "not a verdict" in body["disclaimer"]


def test_route_requires_finding_view(client, auth, finding, stub_model):
    # A developer holds finding:view but only for findings assigned to them.
    assert client.get(
        f"/api/findings/{finding.id}/ai-triage", headers=auth(Role.DEVELOPER)
    ).status_code in (403, 404)


def test_route_404s_for_a_missing_finding(client, auth, stub_model):
    assert client.get("/api/findings/999999/ai-triage", headers=auth(Role.ADMIN)).status_code == 404
