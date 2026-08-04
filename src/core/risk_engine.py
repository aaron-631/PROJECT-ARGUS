"""Argus contextual risk formula: ``R = (S_base * C_env) * P_conf``."""

from __future__ import annotations

import math
from typing import Any, cast


def _clamp(value: float, lower: float, upper: float) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return lower
    if not math.isfinite(numeric):
        return lower
    return max(lower, min(upper, numeric))


def _base_from(canonical_signals: Any) -> tuple[float, float, float]:
    if hasattr(canonical_signals, "base_score"):
        return (
            _clamp(cast(float, getattr(canonical_signals, "base_score")), 1.0, 10.0),
            _clamp(cast(float, getattr(canonical_signals, "context_multiplier", 0.5)), 0.1, 1.0),
            _clamp(cast(float, getattr(canonical_signals, "confidence_penalty", 0.92)), 0.5, 1.0),
        )
    if isinstance(canonical_signals, dict):
        return (
            _clamp(
                cast(
                    float,
                    canonical_signals.get("base_score", canonical_signals.get("base_risk", 1.0)),
                ),  # noqa: E501
                1.0,
                10.0,
            ),
            _clamp(
                cast(
                    float,
                    canonical_signals.get(
                        "context_multiplier", canonical_signals.get("c_env", 0.5)
                    ),
                ),  # noqa: E501
                0.1,
                1.0,
            ),
            _clamp(
                cast(
                    float,
                    canonical_signals.get(
                        "confidence_penalty", canonical_signals.get("confidence", 0.92)
                    ),
                ),
                0.5,
                1.0,
            ),
        )
    if hasattr(canonical_signals, "get_base_risk"):
        return _clamp(cast(float, canonical_signals.get_base_risk()), 1.0, 10.0), 1.0, 1.0
    return 1.0, 0.5, 0.92


def _apply_semantic_weight(base: float, judge_score: float) -> float:
    """Apply semantic confidence as a bounded confidence penalty.

    A judge score of 0.0 represents a safe response and retains the minimum
    penalty (0.5); 1.0 retains the full canonical risk.  This keeps semantic
    judging advisory and prevents a judge from creating an out-of-range score.
    """

    penalty = 0.5 + 0.5 * _clamp(judge_score, 0.0, 1.0)
    return _clamp(base * penalty, 0.0, 10.0)


def calculate_risk(
    canonical_signals: Any, judge_score: float | None, judge_type: str
) -> dict[str, Any]:
    base_score, context_multiplier, confidence_penalty = _base_from(canonical_signals)
    canonical_risk = _clamp(base_score * context_multiplier * confidence_penalty, 0.0, 10.0)
    if judge_type != "NullJudgeBackend" and judge_score is not None:
        final_risk = _apply_semantic_weight(canonical_risk, judge_score)
        methodology = f"canonical+semantic (via {judge_type})"
    else:
        final_risk = canonical_risk
        methodology = "canonical_only"
    return {
        "final_risk": round(final_risk, 3),
        "evaluation_methodology": methodology,
        "base_score": round(base_score, 3),
        "context_multiplier": round(context_multiplier, 3),
        "confidence_penalty": round(confidence_penalty, 3),
        "formula": "R = (S_base * C_env) * P_conf",
    }


__all__ = ["calculate_risk"]
