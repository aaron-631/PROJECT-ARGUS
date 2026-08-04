"""Unit tests for the Argus risk formula."""

from src.core.risk_engine import calculate_risk


class Signals:
    base_score = 10.0
    context_multiplier = 0.1
    confidence_penalty = 0.92


def test_risk_formula_applies_context_and_confidence() -> None:
    result = calculate_risk(Signals(), None, "NullJudgeBackend")
    assert result["final_risk"] == 0.92
    assert result["evaluation_methodology"] == "canonical_only"


def test_semantic_judge_is_advisory_and_bounded() -> None:
    result = calculate_risk(Signals(), 1.0, "MockJudgeBackend")
    assert result["final_risk"] == 0.92
    assert "canonical+semantic" in result["evaluation_methodology"]


def test_invalid_judge_score_is_clamped() -> None:
    result = calculate_risk(
        {"base_score": 99, "c_env": -1, "confidence": 9}, 99, "MockJudgeBackend"
    )
    assert 0.0 <= result["final_risk"] <= 10.0


def test_formula_boundaries_and_monotonic_context() -> None:
    low = calculate_risk(
        {"base_score": 1, "c_env": 0.1, "confidence": 0.5}, None, "NullJudgeBackend"
    )
    high = calculate_risk(
        {"base_score": 10, "c_env": 1.0, "confidence": 1.0}, None, "NullJudgeBackend"
    )
    assert low["final_risk"] == 0.05
    assert high["final_risk"] == 10.0
    assert low["formula"] == "R = (S_base * C_env) * P_conf"
    assert (
        calculate_risk(
            {"base_score": 7, "c_env": 1.0, "confidence": 0.92}, None, "NullJudgeBackend"
        )["final_risk"]
        > calculate_risk(
            {"base_score": 7, "c_env": 0.1, "confidence": 0.92}, None, "NullJudgeBackend"
        )["final_risk"]
    )


def test_judge_failure_preserves_canonical_result() -> None:
    canonical = calculate_risk(
        {"base_score": 7, "c_env": 0.5, "confidence": 0.92}, None, "MockJudgeBackend"
    )
    failed = calculate_risk(
        {"base_score": 7, "c_env": 0.5, "confidence": 0.92}, None, "NullJudgeBackend"
    )
    assert canonical["final_risk"] == failed["final_risk"]
    assert failed["evaluation_methodology"] == "canonical_only"
