"""Compare a scan with a previously accepted report.

Baseline mode is intentionally deterministic.  It does not hide current
findings from the report; it changes the CI gate so teams can fail on new or
more-severe findings while they remediate an existing backlog.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.models import ScanReport, SEVERITY_ORDER


class BaselineError(ValueError):
    """Raised when a baseline file is missing or is not an Argus report."""


def _load_report(path: str | Path) -> ScanReport:
    baseline_path = Path(path)
    try:
        payload = json.loads(baseline_path.read_text(encoding="utf-8"))
        return ScanReport.model_validate(payload)
    except FileNotFoundError as exc:
        raise BaselineError(f"baseline report does not exist: {baseline_path}") from exc
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise BaselineError(f"baseline report is invalid: {baseline_path.name}") from exc


def _finding_key(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence", {})
    return json.dumps(
        {
            "rule_id": finding.get("rule_id"),
            "source_file": finding.get("source_file"),
            "title": finding.get("title"),
            "evidence": evidence,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _attack_key(attack: dict[str, Any]) -> str:
    return json.dumps(
        {
            "module_id": attack.get("module_id"),
            "attack_type": attack.get("attack_type"),
            "payload_id": attack.get("payload_id"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _finding_snapshot(finding: dict[str, Any], key: str) -> dict[str, Any]:
    return {
        "key": key,
        "rule_id": finding.get("rule_id"),
        "severity": finding.get("severity"),
        "title": finding.get("title"),
        "source_file": finding.get("source_file"),
        "line": finding.get("line"),
    }


def _attack_snapshot(attack: dict[str, Any], key: str) -> dict[str, Any]:
    return {
        "key": key,
        "module_id": attack.get("module_id"),
        "attack_type": attack.get("attack_type"),
        "payload_id": attack.get("payload_id"),
        "error": bool(attack.get("error")),
    }


def compare_results(current: dict[str, Any], baseline: ScanReport) -> dict[str, Any]:
    """Return a sanitized baseline comparison for a current report."""

    current_findings = {
        _finding_key(item): item for item in current.get("findings", []) if isinstance(item, dict)
    }
    baseline_findings = {
        _finding_key(item.model_dump(mode="json")): item.model_dump(mode="json")
        for item in baseline.findings
    }
    new_findings: list[dict[str, Any]] = []
    changed_findings: list[dict[str, Any]] = []
    unchanged_findings: list[dict[str, Any]] = []
    for key, finding in current_findings.items():
        previous = baseline_findings.get(key)
        if previous is None:
            new_findings.append(_finding_snapshot(finding, key))
            continue
        previous_rank = SEVERITY_ORDER.get(str(previous.get("severity")), 0)
        current_rank = SEVERITY_ORDER.get(str(finding.get("severity")), 0)
        if current_rank > previous_rank:
            changed_findings.append(
                {
                    "before": _finding_snapshot(previous, key),
                    "after": _finding_snapshot(finding, key),
                }
            )
        else:
            unchanged_findings.append(_finding_snapshot(finding, key))

    resolved_findings = [
        _finding_snapshot(finding, key)
        for key, finding in baseline_findings.items()
        if key not in current_findings
    ]

    current_attacks = {
        _attack_key(item): item
        for item in current.get("attack_results", [])
        if isinstance(item, dict)
    }
    baseline_attacks = {
        _attack_key(item.model_dump(mode="json")): item.model_dump(mode="json")
        for item in baseline.attack_results
    }
    new_attack_failures: list[dict[str, Any]] = []
    for key, attack in current_attacks.items():
        is_failure = bool(attack.get("error")) or bool(
            attack.get("canonical_result", {}).get("attack_succeeded")
        )
        previous = baseline_attacks.get(key, {})
        previous_failure = bool(previous.get("error")) or bool(
            previous.get("canonical_result", {}).get("attack_succeeded")
        )
        if is_failure and not previous_failure:
            new_attack_failures.append(_attack_snapshot(attack, key))

    gate = "BLOCK" if new_findings or changed_findings or new_attack_failures else "PASS"
    return {
        "baseline_file": Path(str(current.get("_baseline_path", "baseline.json"))).name,
        "baseline_scan_id": baseline.metadata.scan_id,
        "new_finding_count": len(new_findings),
        "changed_finding_count": len(changed_findings),
        "unchanged_finding_count": len(unchanged_findings),
        "resolved_finding_count": len(resolved_findings),
        "new_attack_failure_count": len(new_attack_failures),
        "new_findings": new_findings,
        "changed_findings": changed_findings,
        "resolved_findings": resolved_findings,
        "new_attack_failures": new_attack_failures,
        "gate": gate,
    }


def apply_baseline(results: dict[str, Any], path: str | Path) -> dict[str, Any]:
    """Attach a baseline comparison to a result without changing findings."""

    baseline = _load_report(path)
    current = {**results, "_baseline_path": str(path)}
    comparison = compare_results(current, baseline)
    results.setdefault("summary", {})["baseline"] = comparison
    results["summary"]["gate_decision"] = comparison["gate"]
    results["summary"].setdefault("overall_decision", results["summary"].get("decision", "UNKNOWN"))
    return results


__all__ = ["BaselineError", "apply_baseline", "compare_results"]
