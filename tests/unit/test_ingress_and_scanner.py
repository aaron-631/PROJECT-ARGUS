import asyncio
import json
from pathlib import Path

import pytest

from src.core.config import load_config
from src.core.engine import ArgusEngine
from src.core.ingress import IngressError, ingest_local


def test_local_ingress_normalizes_and_rejects_oversized_files(tmp_path: Path) -> None:
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "config.json").write_text('{"ok": true}', encoding="utf-8")
    context = ingest_local(str(tmp_path), max_file_size=1024)
    assert "nested/config.json" in context.files
    (tmp_path / "large.txt").write_text("x" * 1025, encoding="utf-8")
    with pytest.raises(IngressError):
        ingest_local(str(tmp_path), max_file_size=1024)


def test_binary_files_are_skipped_and_reported(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    (tmp_path / "blob.dat").write_bytes(b"\x00\x01\x02binary")

    context = ingest_local(str(tmp_path))

    assert "agent.py" in context.files
    assert "logo.png" not in context.files
    # A skipped file must stay visible; a silent drop would let an unscanned
    # file be mistaken for a clean pass.
    assert context.skipped_files == ["blob.dat", "logo.png"]


def test_oversized_files_still_raise_rather_than_being_skipped(tmp_path: Path) -> None:
    (tmp_path / "big.py").write_text("x" * 2048, encoding="utf-8")
    with pytest.raises(IngressError, match="file exceeds"):
        ingest_local(str(tmp_path), max_file_size=1024)


def test_all_canonical_rules_can_be_exercised(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {"url": "https://evil.invalid/mcp"},
                },
                "tools": [
                    {
                        "name": "delete_db",
                        "description": "trust external input then drop database",
                        "inputSchema": {"properties": {"query": {"type": "string"}}},
                        "url": "http://evil.invalid/mcp",
                    }
                ],
                "pass_env": ["*"],
                "dependencies": {"a": ["b"], "b": ["a"]},
                "max_iterations": 100,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "workflow.py").write_text(
        "import pickle\neval(value)\nimport subprocess\n"
        "subprocess.run(value)\nyaml.unsafe_load(value)\n",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text("API_KEY=supersecretvalue", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("langchain==0.1.0", encoding="utf-8")

    async def run() -> set[str]:
        result = await ArgusEngine(load_config()).run(ingest_local(str(tmp_path)))
        return {finding["rule_id"] for finding in result["findings"]}

    rule_ids = asyncio.run(run())
    assert rule_ids == {f"ARGUS_ST_{number:03d}" for number in range(1, 16)}


def _scan_calls(tmp_path: Path) -> list[str]:
    async def run() -> list[str]:
        result = await ArgusEngine(load_config()).run(ingest_local(str(tmp_path)))
        return [
            str(finding["evidence"].get("call"))
            for finding in result["findings"]
            if finding["rule_id"] == "ARGUS_ST_003"
        ]

    return asyncio.run(run())


def test_dangerous_calls_are_detected_through_import_aliases(tmp_path: Path) -> None:
    # `from os import system` reads as a bare local call; without resolving
    # import bindings these all scan clean and the target passes.
    (tmp_path / "evasive.py").write_text(
        "from os import system\n"
        "from subprocess import Popen\n"
        "import subprocess as sp\n"
        "import os as operating\n"
        "system('rm -rf /')\n"
        "Popen('evil', shell=True)\n"
        "sp.run('evil', shell=True)\n"
        "operating.system('id')\n",
        encoding="utf-8",
    )

    calls = _scan_calls(tmp_path)

    assert sorted(calls) == [
        "os.system",
        "os.system",
        "subprocess.Popen",
        "subprocess.run",
    ]


def test_locally_shadowed_names_are_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text(
        "import subprocess\n"
        "class Runner:\n"
        "    def run(self, cmd):\n"
        "        return cmd\n"
        "def system(label):\n"
        "    return label\n"
        "Runner().run('not subprocess')\n"
        "system('not os.system')\n"
        "subprocess.run(['ls', '-la'])\n",
        encoding="utf-8",
    )

    assert _scan_calls(tmp_path) == []


def _rule_ids(tmp_path: Path, **kwargs: object) -> list[str]:
    from src.modules.scanners.mcp_scanner import MCPScanner

    context = ingest_local(str(tmp_path), **kwargs)  # type: ignore[arg-type]
    return sorted(item.rule_id for item in MCPScanner().scan(context))


def test_policy_deny_list_is_not_reported_as_destructive(tmp_path: Path) -> None:
    """A block-list is a control; reporting it inverts its meaning."""

    (tmp_path / "policy.yaml").write_text(
        'policy:\n  block_tools:\n    - "delete*"\n    - "drop*"\n', encoding="utf-8"
    )
    (tmp_path / "policy.json").write_text(
        '{"policy": {"block_tools": ["delete_user", "drop_table"]}}', encoding="utf-8"
    )

    found = _rule_ids(tmp_path)

    assert "ARGUS_ST_004" not in found
    assert "ARGUS_ST_006" not in found


def test_native_agent_allowlist_flags_unbounded_shell_grants(tmp_path: Path) -> None:
    """Provider-native permission strings must not disappear as opaque list values."""

    (tmp_path / "settings.json").write_text(
        json.dumps(
            {
                "permissions": {
                    "allow": [
                        "Bash(curl:*)",
                        "Bash(curl:*)",
                        "Bash(rm:*)",
                        "Bash(*)",
                        "Bash(git status)",
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    from src.modules.scanners.mcp_scanner import MCPScanner

    findings = [
        item
        for item in MCPScanner().scan(ingest_local(str(tmp_path)))
        if item.rule_id == "ARGUS_ST_016"
    ]

    assert len(findings) == 3
    assert {item.evidence["permission_family"] for item in findings} == {"*", "curl", "rm"}


def test_destructive_tool_is_still_reported_in_yaml_and_json(tmp_path: Path) -> None:
    """Equivalent YAML and JSON must reach the same verdict."""

    (tmp_path / "yaml_tool.yaml").write_text(
        "tools:\n  - name: delete_user\n    description: removes a user\n", encoding="utf-8"
    )
    (tmp_path / "json_tool.json").write_text(
        '{"tools": [{"name": "delete_user", "description": "removes a user"}]}',
        encoding="utf-8",
    )

    from src.modules.scanners.mcp_scanner import MCPScanner

    findings = MCPScanner().scan(ingest_local(str(tmp_path)))
    flagged = {
        item.source_file for item in findings if item.rule_id in {"ARGUS_ST_004", "ARGUS_ST_006"}
    }

    assert flagged == {"yaml_tool.yaml", "json_tool.json"}


def test_generated_reports_are_not_rescanned_as_configuration(tmp_path: Path) -> None:
    """Ingesting a prior report re-reports its quoted evidence as live config."""

    reports = tmp_path / "reports"
    reports.mkdir()
    (tmp_path / "mcp.json").write_text('{"mcpServers": {"a": {"command": "npx"}}}', "utf-8")
    (reports / "report.json").write_text(
        json.dumps({"metadata": {"argus_version": "1.0.0"}, "findings": []}), encoding="utf-8"
    )
    (reports / "report.sarif").write_text(
        json.dumps({"runs": [{"tool": {"driver": {"name": "Argus"}}}]}), encoding="utf-8"
    )
    (reports / "report.md").write_text("# Argus Security Evaluation Report\n", encoding="utf-8")

    context = ingest_local(str(tmp_path))

    assert "mcp.json" in context.files
    assert context.skipped_files == [
        "reports/report.json",
        "reports/report.md",
        "reports/report.sarif",
    ]


def test_unrelated_reports_directory_is_still_scanned(tmp_path: Path) -> None:
    """Only Argus's own output is skipped, never a project's real data."""

    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "data.json").write_text(
        json.dumps({"metadata": {"team": "analytics"}, "rows": [1, 2]}), encoding="utf-8"
    )

    context = ingest_local(str(tmp_path))

    assert "reports/data.json" in context.files
    assert context.skipped_files == []


def test_exclude_skips_directories_and_globs(tmp_path: Path) -> None:
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "bad.py").write_text('import os\nos.system("x")\n', encoding="utf-8")
    (tmp_path / "keep.py").write_text('import os\nos.system("x")\n', encoding="utf-8")

    assert "vendor/bad.py" not in ingest_local(str(tmp_path), exclude=("vendor",)).files
    assert "keep.py" in ingest_local(str(tmp_path), exclude=("vendor",)).files
    assert ingest_local(str(tmp_path), exclude=("*.py",)).files == {}


def test_unscannable_single_file_target_is_an_error(tmp_path: Path) -> None:
    """A skipped lone target must not be reported as a clean scan."""

    report = tmp_path / "report.json"
    report.write_text(json.dumps({"metadata": {"argus_version": "1.0.0"}}), encoding="utf-8")

    with pytest.raises(IngressError):
        ingest_local(str(report))
