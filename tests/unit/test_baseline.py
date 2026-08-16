import json
from pathlib import Path

import pytest

from argus import EXIT_FINDINGS, EXIT_OK, _exit_for_results
from src.core.baseline import BaselineError, apply_baseline


def _report(findings: list[dict], attacks: list[dict] | None = None) -> dict:
    return {
        "metadata": {"source_type": "local", "source": "fixture", "scan_id": "scan"},
        "configuration": {},
        "findings": findings,
        "attack_results": attacks or [],
        "summary": {"decision": "BLOCK" if findings else "PASS", "fail_on": "HIGH"},
        "evaluation_methodology": "canonical_only",
    }


def _finding(rule_id: str, severity: str = "HIGH") -> dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": "Fixture finding",
        "description": "Fixture description",
        "confidence_score": 0.9,
        "evidence": {"tool": rule_id},
        "source_file": "config/mcp.json",
        "line": 2,
        "risk_score": 4.0,
        "remediation": "Fix the fixture.",
    }


def test_baseline_passes_when_only_existing_findings_remain(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(_report([_finding("ARGUS_ST_017")])), encoding="utf-8")
    current = _report([_finding("ARGUS_ST_017")])

    apply_baseline(current, baseline_path)

    comparison = current["summary"]["baseline"]
    assert comparison["gate"] == "PASS"
    assert current["summary"]["overall_decision"] == "BLOCK"
    assert current["summary"]["gate_decision"] == "PASS"
    assert comparison["new_finding_count"] == 0
    assert comparison["unchanged_finding_count"] == 1
    assert _exit_for_results(current, "HIGH") == EXIT_OK


def test_baseline_blocks_new_and_escalated_findings(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(_report([_finding("ARGUS_ST_017", "MEDIUM")])), encoding="utf-8"
    )
    current = _report([_finding("ARGUS_ST_017", "HIGH"), _finding("ARGUS_ST_010", "CRITICAL")])

    apply_baseline(current, baseline_path)

    comparison = current["summary"]["baseline"]
    assert comparison["gate"] == "BLOCK"
    assert comparison["new_finding_count"] == 1
    assert comparison["changed_finding_count"] == 1
    assert _exit_for_results(current, "HIGH") == EXIT_FINDINGS


def test_baseline_rejects_non_argus_json(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text("{}", encoding="utf-8")

    with pytest.raises(BaselineError):
        apply_baseline(_report([]), path)


def test_baseline_does_not_collapse_duplicate_rule_occurrences(tmp_path: Path) -> None:
    baseline_finding = _finding("ARGUS_ST_003")
    baseline_finding["line"] = 10
    current_first = {**baseline_finding, "line": 10}
    current_second = {**baseline_finding, "line": 20}
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(_report([baseline_finding])), encoding="utf-8")
    current = _report([current_first, current_second])

    apply_baseline(current, baseline_path)

    comparison = current["summary"]["baseline"]
    assert comparison["gate"] == "BLOCK"
    assert comparison["new_finding_count"] == 1
    assert comparison["unchanged_finding_count"] == 1
