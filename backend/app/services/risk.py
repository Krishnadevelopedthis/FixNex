"""FixNex contextual risk engine.

This produces a *platform-specific* risk score. It is deliberately kept
separate from the CVSS base score, which is always preserved unchanged: CVSS
describes the vulnerability, contextual risk describes what that vulnerability
means for this particular asset.
"""
from __future__ import annotations

from app.models.enums import (
    Criticality,
    DataSensitivity,
    Exposure,
    Severity,
    VerificationStatus,
)

DISCLAIMER = (
    "Contextual risk is a FixNex platform score that combines the CVSS base score "
    "with asset criticality, data sensitivity, exposure and exploitability. "
    "It is not an official CVSS rating."
)

# Context contributes *points*, which are then applied against the remaining
# headroom to 10 (or down towards 0). A multiplicative model was tried first and
# saturated: every finding on a high-criticality internet-facing asset collapsed
# to 10.0/CRITICAL, which erases the ranking the score exists to provide.
_CRITICALITY_POINTS = {
    Criticality.CRITICAL: 0.9,
    Criticality.HIGH: 0.5,
    Criticality.MEDIUM: 0.0,
    Criticality.LOW: -0.6,
}
_SENSITIVITY_POINTS = {
    DataSensitivity.HIGH: 0.5,
    DataSensitivity.MEDIUM: 0.15,
    DataSensitivity.LOW: 0.0,
    DataSensitivity.NONE: -0.4,
}
_EXPOSURE_POINTS = {
    Exposure.INTERNET_FACING: 0.7,
    Exposure.INTERNAL: 0.0,
    Exposure.ISOLATED: -1.2,
}

_LABELS = {
    Criticality.CRITICAL: "Critical", Criticality.HIGH: "High",
    Criticality.MEDIUM: "Medium", Criticality.LOW: "Low",
    DataSensitivity.NONE: "None",
    Exposure.INTERNET_FACING: "Internet-facing", Exposure.INTERNAL: "Internal",
    Exposure.ISOLATED: "Isolated",
}


def _label(value: str) -> str:
    return _LABELS.get(value, str(value).replace("_", " ").title())


def risk_level_from_score(score: float) -> str:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFORMATIONAL


def _band(score: float) -> str:
    """Coarse band used for the impact / likelihood heat map axes."""
    if score >= 7.5:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def calculate(
    *,
    cvss_score: float | None,
    severity: str = Severity.MEDIUM,
    asset_criticality: str = Criticality.MEDIUM,
    data_sensitivity: str = DataSensitivity.MEDIUM,
    exposure: str = Exposure.INTERNAL,
    exploit_available: bool = False,
    verification_status: str = VerificationStatus.UNVERIFIED,
    confidence: float = 0.5,
    cvss_metrics: dict | None = None,
) -> dict:
    """Return the contextual risk breakdown for one finding."""
    base = cvss_score if cvss_score is not None else {
        Severity.CRITICAL: 9.5, Severity.HIGH: 7.5, Severity.MEDIUM: 5.0,
        Severity.LOW: 2.5, Severity.INFORMATIONAL: 0.5,
    }.get(severity, 5.0)

    explanation: list[str] = [f"CVSS base score of {base:.1f} taken as the starting point."]
    points = 0.0

    criticality_points = _CRITICALITY_POINTS.get(asset_criticality, 0.0)
    points += criticality_points
    explanation.append(
        f"Asset criticality is {_label(asset_criticality)} ({criticality_points:+.2f} points)."
    )

    sensitivity_points = _SENSITIVITY_POINTS.get(data_sensitivity, 0.0)
    points += sensitivity_points
    explanation.append(
        f"Data sensitivity is {_label(data_sensitivity)} ({sensitivity_points:+.2f} points)."
    )

    exposure_points = _EXPOSURE_POINTS.get(exposure, 0.0)
    points += exposure_points
    explanation.append(f"Exposure is {_label(exposure)} ({exposure_points:+.2f} points).")

    if exploit_available:
        points += 0.9
        explanation.append("A public exploit is known to exist (+0.90 points).")

    if verification_status == VerificationStatus.CONFIRMED:
        points += 0.3
        explanation.append("The finding has been manually confirmed by an analyst (+0.30 points).")
    elif verification_status == VerificationStatus.FALSE_POSITIVE:
        explanation.append("The finding was verified as a false positive; contextual risk is zero.")
        return {
            "base_cvss": cvss_score,
            "risk_score": 0.0,
            "risk_level": Severity.INFORMATIONAL,
            "impact": "LOW",
            "likelihood": "LOW",
            "factors": {
                "asset_criticality": asset_criticality,
                "data_sensitivity": data_sensitivity,
                "exposure": exposure,
                "exploit_available": exploit_available,
                "verification_status": verification_status,
                "adjustment": 0.0,
            },
            "explanation": explanation,
            "disclaimer": DISCLAIMER,
        }
    elif confidence < 0.5:
        points -= 0.6
        explanation.append(
            f"Scanner confidence is low ({confidence:.0%}); risk is discounted by 0.60 points "
            "until an analyst verifies the finding."
        )

    # Apply the adjustment against the distance still available to 10 (upwards)
    # or to 0 (downwards), so context shifts the score without ever pinning it
    # to the ceiling and flattening the ranking.
    headroom = (10.0 - base) / 10.0 if points >= 0 else base / 10.0
    adjustment = points * headroom

    risk_score = round(min(max(base + adjustment, 0.0), 10.0), 1)
    risk_level = risk_level_from_score(risk_score)
    explanation.append(
        f"Context contributes {points:+.2f} points, scaled by the available headroom to "
        f"{adjustment:+.2f}, giving a contextual risk of {risk_score:.1f} ({risk_level})."
    )

    # Impact is driven by what the vulnerability does plus what the asset holds.
    impact_base = base
    if asset_criticality in (Criticality.CRITICAL, Criticality.HIGH):
        impact_base += 1.0
    if data_sensitivity == DataSensitivity.HIGH:
        impact_base += 0.5

    # Likelihood is driven by reachability and ease of exploitation.
    likelihood_base = base
    metrics = cvss_metrics or {}
    if metrics.get("Attack Vector") == "Network":
        likelihood_base += 0.5
    if metrics.get("Attack Complexity") == "Low":
        likelihood_base += 0.5
    if metrics.get("Privileges Required") == "None":
        likelihood_base += 0.5
    if metrics.get("User Interaction") == "Required":
        likelihood_base -= 0.5
    if exposure == Exposure.INTERNET_FACING:
        likelihood_base += 1.0
    elif exposure == Exposure.ISOLATED:
        likelihood_base -= 1.5
    if exploit_available:
        likelihood_base += 1.0

    return {
        "base_cvss": cvss_score,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "impact": _band(min(impact_base, 10.0)),
        "likelihood": _band(min(max(likelihood_base, 0.0), 10.0)),
        "factors": {
            "asset_criticality": asset_criticality,
            "data_sensitivity": data_sensitivity,
            "exposure": exposure,
            "exploit_available": exploit_available,
            "verification_status": verification_status,
            "confidence": confidence,
            "adjustment": round(adjustment, 2),
            "context_points": round(points, 2),
        },
        "explanation": explanation,
        "disclaimer": DISCLAIMER,
    }


def context_from_target(target) -> dict:
    """Derive risk context from the target's asset, with sensible defaults."""
    asset = getattr(target, "asset", None) if target else None
    if asset is None:
        return {
            "asset_criticality": Criticality.MEDIUM,
            "data_sensitivity": DataSensitivity.MEDIUM,
            "exposure": Exposure.INTERNET_FACING,
        }
    return {
        "asset_criticality": asset.criticality,
        "data_sensitivity": asset.data_sensitivity,
        "exposure": asset.exposure,
    }
