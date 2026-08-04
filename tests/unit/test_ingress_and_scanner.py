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
