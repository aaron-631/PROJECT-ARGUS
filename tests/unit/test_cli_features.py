import asyncio
import json
from pathlib import Path

import pytest

import argus
from src.core.config import load_config
from src.core.engine import ArgusEngine
from src.core.ingress import ingest_local


def _write_unsafe_agent(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text("import os\nos.system('id')\n", encoding="utf-8")


def test_version_flag_matches_package_metadata(capsys: pytest.CaptureFixture[str]) -> None:
    from importlib.metadata import version

    with pytest.raises(SystemExit) as exc:
        argus.main(["--version"])
    assert exc.value.code == 0
    assert version("argus-framework") in capsys.readouterr().out


def test_rules_command_lists_rule_ids(capsys: pytest.CaptureFixture[str]) -> None:
    assert argus.main(["rules"]) == 0
    assert "ARGUS_ST_001" in capsys.readouterr().out


def test_json_flag_emits_parseable_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_unsafe_agent(tmp_path)
    argus.main(["scan", "--target", str(tmp_path), "--json", "--output", str(tmp_path / "out")])
    summary = json.loads(capsys.readouterr().out)
    assert summary["decision"] == "BLOCK"
    assert summary["finding_count"] > 0


def test_format_flag_limits_generated_reports(tmp_path: Path) -> None:
    _write_unsafe_agent(tmp_path)
    output = tmp_path / "out"
    argus.main(["scan", "--target", str(tmp_path), "--format", "json", "--output", str(output)])
    assert [path.name for path in sorted(output.iterdir())] == ["report.json"]


def test_disabled_rule_is_suppressed_and_recorded(tmp_path: Path) -> None:
    _write_unsafe_agent(tmp_path)
    config = load_config()

    baseline = asyncio.run(ArgusEngine(config).run(ingest_local(str(tmp_path))))
    assert any(item["rule_id"] == "ARGUS_ST_003" for item in baseline["findings"])

    suppressed_config = config.model_copy(update={"disabled_rules": ["ARGUS_ST_003"]})
    suppressed = asyncio.run(ArgusEngine(suppressed_config).run(ingest_local(str(tmp_path))))

    assert not any(item["rule_id"] == "ARGUS_ST_003" for item in suppressed["findings"])
    # Suppression must leave an audit trail, otherwise a scan with critical
    # rules disabled is indistinguishable from a genuinely clean one.
    assert suppressed["summary"]["suppressed_rules"] == ["ARGUS_ST_003"]
