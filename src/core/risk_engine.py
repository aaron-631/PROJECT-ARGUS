"""
Argus Risk Scoring Engine.

Formula: R = (S_base × C_env) × P_conf

S_base  — Intrinsic danger of the vulnerability (1.0–10.0)
C_env   — Deployment context multiplier (0.1–1.0)
P_conf  — Confidence penalty, prevents noisy false positives (0.5–1.0)

Note: confidence_score in output should never be 1.0.
Use 0.92 or confidence bands — auditors distrust absolute certainty.
"""
from typing import Optional, Dict, Any


def calculate_risk(
    canonical_signals: Any,
    judge_score: Optional[float],
    judge_type: str,
) -> Dict[str, Any]:
    """
    Aggregates canonical and semantic signals into a contextual risk score.
    Handles judge failures gracefully via guard clauses.
    """
    risk_level = canonical_signals.get_base_risk()

    if judge_type != "NullJudgeBackend" and judge_score is not None:
        risk_level = _apply_semantic_weight(risk_level, judge_score)

    if judge_type == "NullJudgeBackend" or judge_score is None:
        methodology = "canonical_only"
    else:
        methodology = f"canonical+semantic (via {judge_type})"

    return {
        "final_risk": risk_level,
        "evaluation_methodology": methodology,
    }


def _apply_semantic_weight(base: float, judge_score: float) -> float:
    # TODO: define weighting strategy
    raise NotImplementedError
