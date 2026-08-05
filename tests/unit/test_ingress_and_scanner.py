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
