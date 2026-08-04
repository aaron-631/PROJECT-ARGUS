import json
from pathlib import Path

from argus import EXIT_ERROR, _exit_for_results
from src.core import doctor
from src.reporting import SARIFExporter


def test_doctor_report_is_secret_free_and_checks_optional_provider(tmp_path: Path) -> None:
    report = doctor.build_report(
        tmp_path / "reports",
        environ={"OPENAI_API_KEY": "do-not-print-this-value"},
    )

    assert report["summary"]["status"] == "PASS"
    assert any(item["name"] == "Provider credentials" for item in report["checks"])
    serialized = json.dumps(report)
    assert "do-not-print-this-value" not in serialized


def test_doctor_json_mode_returns_success_for_required_checks(tmp_path: Path, capsys) -> None:
    exit_code = doctor.run_doctor(tmp_path / "reports", as_json=True, environ={})

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["summary"]["status"] == "PASS"
    assert {item["status"] for item in output["checks"]} >= {"PASS", "INFO"}


def test_sarif_export_contains_github_finding_location(tmp_path: Path) -> None:
    results = {
        "metadata": {
            "source_type": "local",
            "source": "fixture",
            "scan_id": "stable",
        },
        "configuration": {},
        "findings": [
            {
                "rule_id": "ARGUS_ST_017",
                "severity": "HIGH",
                "title": "High-impact MCP tool without approval",
                "description": "The tool can perform a high-impact action without approval.",
                "confidence_score": 0.92,
                "evidence": {"tool": "write_file"},
                "source_file": "config/mcp.json",
                "line": 4,
                "risk_score": 3.91,
                "remediation": "Require approval before the side effect.",
            }
        ],
        "attack_results": [],
        "summary": {"decision": "BLOCK", "fail_on": "HIGH"},
        "evaluation_methodology": "canonical_only",
    }

    destination = SARIFExporter().export(results, tmp_path / "report.sarif")
    sarif = json.loads(destination.read_text(encoding="utf-8"))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "Argus"
    assert run["tool"]["driver"]["rules"][0]["id"] == "ARGUS_ST_017"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "config/mcp.json"
    )
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 4


def test_cli_exit_code_preserves_error_decision() -> None:
    assert _exit_for_results({"summary": {"decision": "ERROR"}}, "HIGH") == EXIT_ERROR
