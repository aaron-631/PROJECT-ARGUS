"""Deterministic JSON and Markdown report exporters."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.models import ScanReport
from src.core.sanitization import sanitize_value
from src.interfaces.exporter import BaseExporter


def build_report(results: dict[str, Any] | ScanReport) -> ScanReport:
    if isinstance(results, ScanReport):
        return results
    clean = sanitize_value(results)
    return ScanReport.model_validate(clean)


def validate_contracts(report: ScanReport) -> None:
    """Validate generated Pydantic JSON Schema artifacts at the export boundary."""

    from jsonschema import validate

    root = Path(__file__).resolve().parents[2] / "src" / "models"
    finding_schema = json.loads((root / "finding.json").read_text(encoding="utf-8"))
    attack_schema = json.loads((root / "attack_result.json").read_text(encoding="utf-8"))
    report_schema = json.loads((root / "report.json").read_text(encoding="utf-8"))
    for finding in report.findings:
        validate(finding.model_dump(mode="json", exclude_none=True), finding_schema)
    for attack in report.attack_results:
        validate(attack.model_dump(mode="json", exclude_none=True), attack_schema)
    validate(report.model_dump(mode="json", exclude_none=True), report_schema)


class JSONExporter(BaseExporter):
    exporter_id = "json"
    version = "1.0.0"

    def export(self, results: dict[str, Any] | ScanReport, output_path: str | Path) -> Path:
        report = build_report(results)
        validate_contracts(report)
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(
                report.model_dump(mode="json", exclude_none=True),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        return destination


class MarkdownExporter(BaseExporter):
    exporter_id = "markdown"
    version = "1.0.0"

    def export(self, results: dict[str, Any] | ScanReport, output_path: str | Path) -> Path:
        report = build_report(results)
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# Argus Security Evaluation Report",
            "",
            f"- Source: `{report.metadata.source}`",
            f"- Profile: `{report.metadata.profile}`",
            f"- Scan ID: `{report.metadata.scan_id}`",
            f"- Evaluation methodology: `{report.evaluation_methodology}`",
            "",
            "## Summary",
            "",
            f"Findings: **{len(report.findings)}**  ",
            f"Dynamic attack results: **{len(report.attack_results)}**  ",
            f"Maximum risk: **{report.summary.get('max_risk', 0)} / 10**",
            "",
            "## Static findings",
            "",
        ]
        if not report.findings:
            lines.append("No static findings were produced.")
        for finding in report.findings:
            lines.extend(
                [
                    f"### {finding.severity.value}: {finding.title} (`{finding.rule_id}`)",
                    "",
                    finding.description,
                    "",
                    f"- Evidence: `{finding.source_file or 'n/a'}` line `{finding.line or 'n/a'}`",
                    f"- Risk: **{finding.risk_score} / 10**; confidence: **{finding.confidence_score}**",  # noqa: E501
                    f"- Methodology: `{finding.evaluation_methodology}`",
                    "",
                    f"**Remediation:** {finding.remediation or 'Review the evidence and apply a least-privilege control.'}",  # noqa: E501
                    "",
                ]
            )
        lines.extend(["## Dynamic evaluation", ""])
        if not report.attack_results:
            lines.append(
                "Dynamic attacks were not run; provide an explicit target endpoint to enable them."
            )
        for result in report.attack_results:
            outcome = "succeeded" if result.canonical_result.get("attack_succeeded") else "blocked"
            lines.extend(
                [
                    f"### {result.attack_type}: {result.payload_id}",
                    "",
                    f"- Canonical outcome: **{outcome}**",
                    f"- Risk: **{result.risk_score} / 10**",
                    f"- Methodology: `{result.evaluation_methodology}`",
                    "",
                ]
            )
        if report.summary.get("errors"):
            lines.extend(
                [
                    "## Execution notes",
                    "",
                    *[f"- {error}" for error in report.summary["errors"]],
                    "",
                ]
            )
        destination.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        return destination


__all__ = ["JSONExporter", "MarkdownExporter", "build_report", "validate_contracts"]
