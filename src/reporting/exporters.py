"""Deterministic JSON and Markdown report exporters."""

from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path
from typing import Any

from src.models import ScanReport
from src.core.sanitization import sanitize_value
from src.core.taxonomy import taxonomy_for_attack, taxonomy_for_rule
from src.interfaces.exporter import BaseExporter


def build_report(results: dict[str, Any] | ScanReport) -> ScanReport:
    report = (
        results
        if isinstance(results, ScanReport)
        else ScanReport.model_validate(sanitize_value(results))
    )
    findings = [
        item.model_copy(
            update={
                "owasp_ids": item.owasp_ids or list(taxonomy_for_rule(item.rule_id).owasp_ids),
                "atlas_ids": item.atlas_ids or list(taxonomy_for_rule(item.rule_id).atlas_ids),
                "cwe_ids": item.cwe_ids or list(taxonomy_for_rule(item.rule_id).cwe_ids),
            }
        )
        for item in report.findings
    ]
    attacks = [
        item.model_copy(
            update={
                "owasp_ids": item.owasp_ids or list(taxonomy_for_attack(item.module_id).owasp_ids),
                "atlas_ids": item.atlas_ids or list(taxonomy_for_attack(item.module_id).atlas_ids),
                "cwe_ids": item.cwe_ids or list(taxonomy_for_attack(item.module_id).cwe_ids),
            }
        )
        for item in report.attack_results
    ]
    return report.model_copy(update={"findings": findings, "attack_results": attacks})


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
            f"- Decision: **{report.summary.get('decision', 'UNKNOWN')}** "
            f"(fail on `{report.summary.get('fail_on', 'HIGH')}`)",
            "",
            "## Summary",
            "",
            f"Findings: **{len(report.findings)}**  ",
            f"Dynamic attack results: **{len(report.attack_results)}**  ",
            f"Dynamic transport errors: **{report.summary.get('dynamic_error_count', 0)}**  ",
            f"Maximum risk: **{report.summary.get('max_risk', 0)} / 10**",
            "",
        ]
        compliance = report.summary.get("compliance_coverage")
        if isinstance(compliance, dict):
            lines.extend(["## Standards coverage", ""])
            owasp_llm = compliance.get("owasp_llm", {})
            owasp_agentic = compliance.get("owasp_agentic", {})
            atlas = compliance.get("mitre_atlas", {})
            if isinstance(owasp_llm, dict):
                lines.append(
                    f"- OWASP LLM Top 10 ({owasp_llm.get('edition', 'unknown')}): tested "
                    f"`{', '.join(owasp_llm.get('tested', [])) or 'none'}`; not covered "
                    f"`{', '.join(owasp_llm.get('not_covered', [])) or 'none'}`"
                )
            if isinstance(owasp_agentic, dict):
                lines.append(
                    f"- OWASP Agentic ({owasp_agentic.get('edition', 'unknown')}): tested "
                    f"`{', '.join(owasp_agentic.get('tested', [])) or 'none'}`; not covered "
                    f"`{', '.join(owasp_agentic.get('not_covered', [])) or 'none'}`"
                )
            if isinstance(atlas, dict):
                lines.append(
                    f"- MITRE ATLAS mappings: `{', '.join(atlas.get('mapped', [])) or 'none'}`"
                )
            lines.append("")
        performance = report.summary.get("performance")
        if isinstance(performance, dict):
            lines.extend(["## Performance", ""])
            if performance.get("files_scanned") is not None:
                lines.append(f"- Files scanned: **{performance['files_scanned']}**")
            if performance.get("tool_count") is not None:
                lines.append(f"- MCP tools discovered: **{performance['tool_count']}**")
            if performance.get("elapsed_seconds") is not None:
                lines.append(f"- Elapsed: **{performance['elapsed_seconds']} seconds**")
            if performance.get("ingest_seconds") is not None:
                lines.append(f"- Ingest: **{performance['ingest_seconds']} seconds**")
            if performance.get("evaluation_seconds") is not None:
                lines.append(f"- Evaluation: **{performance['evaluation_seconds']} seconds**")
            lines.append("")
        baseline = report.summary.get("baseline")
        if isinstance(baseline, dict):
            lines.extend(["## Baseline comparison", ""])
            lines.append(f"- Baseline gate: **{baseline.get('gate', 'UNKNOWN')}**")
            lines.append(f"- New findings: **{baseline.get('new_finding_count', 0)}**")
            lines.append(f"- Severity increases: **{baseline.get('changed_finding_count', 0)}**")
            lines.append(
                f"- New dynamic attack failures: **{baseline.get('new_attack_failure_count', 0)}**"
            )
            lines.append(f"- Resolved findings: **{baseline.get('resolved_finding_count', 0)}**")
            lines.append("")
        lines.extend(["## Static findings", ""])
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
                    f"- OWASP: `{', '.join(finding.owasp_ids) or 'unmapped'}`; ATLAS: "
                    f"`{', '.join(finding.atlas_ids) or 'unmapped'}`; CWE: "
                    f"`{', '.join(finding.cwe_ids) or 'not assigned'}`",
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
                    f"- OWASP: `{', '.join(result.owasp_ids) or 'unmapped'}`; ATLAS: "
                    f"`{', '.join(result.atlas_ids) or 'unmapped'}`; CWE: "
                    f"`{', '.join(result.cwe_ids) or 'not assigned'}`",
                    (
                        f"- Source channel: `{result.metadata.get('source_channel')}`; "
                        f"retrieved documents: "
                        f"`{result.metadata.get('retrieved_document_count', 0)}`"
                        if result.metadata.get("source_channel")
                        else ""
                    ),
                    "",
                ]
            )
        servers = report.summary.get("mcp_servers", [])
        tools = report.summary.get("mcp_tools", [])
        skills = report.summary.get("skills", [])
        lines.extend(["## MCP inventory", ""])
        lines.append(f"Declared MCP servers: **{len(servers)}**  ")
        lines.append(f"Declared MCP tools: **{len(tools)}**")
        if servers:
            lines.extend(["", "### Servers", ""])
            for server in servers:
                transport = server.get("transport", "unknown")
                identity = server.get("command") or server.get("host") or "unknown"
                verified = "verified" if server.get("verified") else "unverified"
                lines.append(
                    f"- `{server.get('name', 'unknown')}` ({transport}, {identity}, {verified}) "
                    f"from `{server.get('file', 'unknown')}`"
                )
        if tools:
            lines.extend(["", "### Tools", ""])
        for tool in tools:
            approval = (
                "approval configured" if tool.get("approval_required") else "no approval metadata"
            )
            lines.append(
                f"- `{tool.get('name', 'unknown')}` ({approval}) "
                f"from `{tool.get('file', 'unknown')}`"
            )
        probe = report.summary.get("mcp_probe")
        if isinstance(probe, dict):
            lines.extend(["", "## MCP live probe", ""])
            lines.append(f"- Transport: `{probe.get('transport', 'unknown')}`")
            lines.append(f"- Target: `{probe.get('target', 'unknown')}`")
            lines.append(f"- Protocol: `{probe.get('protocol_version', 'unknown')}`")
            lines.append(f"- Pages read: **{probe.get('pages', 0)}**")
            lines.append(f"- Tools discovered: **{probe.get('tool_count', 0)}**")
            lines.append("- Tool calls made: **0** (read-only discovery)")
            if probe.get("server_info"):
                lines.append(f"- Server info: `{probe['server_info']}`")
        lines.extend(["", "## Skill inventory", ""])
        lines.append(f"Discovered skills: **{len(skills)}**")
        for skill in skills:
            lines.append(
                f"- `{skill.get('name', 'unknown')}` "
                f"({skill.get('provenance', 'review_required')}) "
                f"from `{skill.get('file', 'unknown')}`"
            )
        lines.append("")
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


class SARIFExporter(BaseExporter):
    """Export findings in SARIF 2.1.0 for GitHub Code Scanning and CI tools."""

    exporter_id = "sarif"
    version = "1.0.0"
    _schema_uri = "https://json.schemastore.org/sarif-2.1.0.json"
    _project_uri = "https://github.com/aaron-631/PROJECT-ARGUS"

    @staticmethod
    def _level(severity: str) -> str:
        return {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
        }.get(severity.upper(), "warning")

    @staticmethod
    def _dynamic_rule_id(attack_type: str) -> str:
        normalized = re.sub(r"[^A-Z0-9]+", "_", attack_type.upper()).strip("_")
        return f"ARGUS_DYN_{normalized or 'UNKNOWN'}"

    @staticmethod
    def _fingerprint(*parts: object) -> str:
        value = "|".join(str(part) for part in parts)
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _location(source_file: str | None, line: int | None) -> list[dict[str, Any]]:
        if not source_file:
            return []
        physical: dict[str, Any] = {"artifactLocation": {"uri": source_file.replace("\\", "/")}}
        if line is not None:
            physical["region"] = {"startLine": line}
        return [{"physicalLocation": physical}]

    def export(self, results: dict[str, Any] | ScanReport, output_path: str | Path) -> Path:
        report = build_report(results)
        validate_contracts(report)
        rules: dict[str, dict[str, Any]] = {}
        sarif_results: list[dict[str, Any]] = []

        for finding in report.findings:
            rule_id = finding.rule_id
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {
                        "text": finding.remediation
                        or "Review the evidence and apply a least-privilege control."
                    },
                    "properties": {
                        "security-severity": f"{finding.risk_score:.2f}",
                        "severity": finding.severity.value,
                        "evaluation_methodology": finding.evaluation_methodology,
                        "owasp_ids": finding.owasp_ids,
                        "atlas_ids": finding.atlas_ids,
                        "cwe_ids": finding.cwe_ids,
                        "tags": [*finding.owasp_ids, *finding.atlas_ids, *finding.cwe_ids],
                    },
                },
            )
            evidence = json.dumps(finding.evidence, sort_keys=True, ensure_ascii=False)
            result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": self._level(finding.severity.value),
                "message": {"text": f"{finding.description} Evidence: {evidence}"},
                "locations": self._location(finding.source_file, finding.line),
                "partialFingerprints": {
                    "primaryLocationLineHash": self._fingerprint(
                        rule_id, finding.source_file, finding.line, evidence
                    )
                },
                "properties": {
                    "risk_score": finding.risk_score,
                    "confidence_score": finding.confidence_score,
                    "deployment_context": finding.deployment_context,
                    "evaluation_methodology": finding.evaluation_methodology,
                    "owasp_ids": finding.owasp_ids,
                    "atlas_ids": finding.atlas_ids,
                    "cwe_ids": finding.cwe_ids,
                },
            }
            sarif_results.append(result)

        for attack in report.attack_results:
            succeeded = bool(attack.canonical_result.get("attack_succeeded"))
            if not succeeded and not attack.error:
                continue
            rule_id = self._dynamic_rule_id(attack.attack_type)
            title = f"Dynamic {attack.attack_type} check"
            message = (
                f"The {attack.attack_type} probe produced an unsafe response."
                if succeeded
                else f"The {attack.attack_type} probe could not complete: {attack.error}."
            )
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": title,
                    "shortDescription": {"text": title},
                    "fullDescription": {"text": message},
                    "help": {
                        "text": "Review the model behavior and provider configuration "
                        "before approving deployment."
                    },
                    "properties": {
                        "security-severity": f"{attack.risk_score:.2f}",
                        "category": "dynamic-security-test",
                        "owasp_ids": attack.owasp_ids,
                        "atlas_ids": attack.atlas_ids,
                        "cwe_ids": attack.cwe_ids,
                        "tags": [*attack.owasp_ids, *attack.atlas_ids, *attack.cwe_ids],
                    },
                },
            )
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": "error" if succeeded else "warning",
                    "message": {"text": f"{message} Payload: {attack.payload_id}."},
                    "partialFingerprints": {
                        "primaryLocationLineHash": self._fingerprint(
                            rule_id, attack.payload_id, attack.error
                        )
                    },
                    "properties": {
                        "risk_score": attack.risk_score,
                        "evaluation_methodology": attack.evaluation_methodology,
                        "owasp_ids": attack.owasp_ids,
                        "atlas_ids": attack.atlas_ids,
                        "cwe_ids": attack.cwe_ids,
                    },
                }
            )

        sarif = {
            "$schema": self._schema_uri,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Argus",
                            "version": report.metadata.argus_version,
                            "informationUri": self._project_uri,
                            "rules": list(rules.values()),
                        }
                    },
                    "automationDetails": {"id": f"argus/{report.metadata.scan_id}"},
                    "results": sarif_results,
                    "properties": {
                        "decision": report.summary.get("decision", "UNKNOWN"),
                        "fail_on": report.summary.get("fail_on", "HIGH"),
                        "scan_id": report.metadata.scan_id,
                        "compliance_coverage": report.summary.get("compliance_coverage", {}),
                    },
                }
            ],
        }
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(sarif, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return destination


__all__ = [
    "JSONExporter",
    "MarkdownExporter",
    "SARIFExporter",
    "build_report",
    "validate_contracts",
]
