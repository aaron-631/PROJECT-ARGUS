"""Structured parser and rule-routing regressions."""

import json
import asyncio
from pathlib import Path

from src.core.documents import parse_file
from src.core.engine import ArgusEngine
from src.core.config import load_config
from src.core.ingress import ingest_local
from src.models import FileRecord
from src.modules.scanners.mcp_scanner import MCPScanner
from src.modules.scanners.rules import RULE_CAPABILITIES


def test_structured_documents_parse_toml_and_record_malformed_input() -> None:
    toml = parse_file(FileRecord(path="agent.toml", content="[agent]\nmax_iterations = 100\n"))
    assert toml.value["agent"]["max_iterations"] == 100
    malformed = parse_file(FileRecord(path="agent.json", content="{not-json"))
    assert malformed.parse_error
    assert malformed.value is None


def test_capabilities_declare_ast_and_structured_routing(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text(
        "import subprocess\nsubprocess.run(['echo', 'fixed'])\n", encoding="utf-8"
    )
    (tmp_path / "unsafe.py").write_text(
        "import subprocess\nsubprocess.run(user_value)\n", encoding="utf-8"
    )
    (tmp_path / "agent.toml").write_text(
        "[tool]\nname = 'delete'\ndescription = 'drop database'\n", encoding="utf-8"
    )
    (tmp_path / "secrets.json").write_text(
        '{"value": "sk_live_1234567890abcdef"}', encoding="utf-8"
    )
    context = ingest_local(str(tmp_path))
    findings = MCPScanner().scan(context)
    assert any(
        item.source_file == "unsafe.py" and item.rule_id == "ARGUS_ST_003" for item in findings
    )
    assert not any(
        item.source_file == "safe.py" and item.rule_id == "ARGUS_ST_003" for item in findings
    )
    assert any(
        item.source_file == "agent.toml" and item.rule_id == "ARGUS_ST_004" for item in findings
    )
    assert any(
        item.source_file == "secrets.json" and item.rule_id == "ARGUS_ST_010" for item in findings
    )
    assert RULE_CAPABILITIES["ARGUS_ST_003"].mode == "python_ast"
    assert RULE_CAPABILITIES["ARGUS_ST_004"].mode == "structured"


def test_ingress_keeps_equivalent_structured_values(tmp_path: Path) -> None:
    payload = {"tool": {"name": "read", "inputSchema": {"properties": {"q": {}}}}}
    (tmp_path / "agent.json").write_text(json.dumps(payload), encoding="utf-8")
    context = ingest_local(str(tmp_path))
    document = context.documents["agent.json"]
    assert document.value == payload
    assert context.document_errors == []


def test_document_parse_errors_are_not_reported_as_pass(tmp_path: Path) -> None:
    empty = tmp_path / "mcp_config.json"
    empty.write_text("", encoding="utf-8")
    context = ingest_local(str(empty))
    config = load_config().model_copy(update={"attacks": []})

    result = asyncio.run(ArgusEngine(config).run(context))

    assert result["summary"]["decision"] == "ERROR"
    assert result["summary"]["error_count"] >= 1
    assert result["summary"]["errors"]
