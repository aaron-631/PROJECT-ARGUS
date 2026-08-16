"""Reproducible proof that retrieved content cannot cross the tool boundary."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_isolated_indirect_injection_demo_blocks_without_side_effect() -> None:
    root = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        [sys.executable, str(root / "examples" / "indirect-injection" / "run_demo.py")],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    evidence = json.loads(completed.stdout)
    assert evidence["injection_source"] == "retrieved_document"
    assert evidence["tool_attempted"] == "execute_command"
    assert evidence["decision"] == "BLOCK"
    assert evidence["side_effects"] == 0
    assert evidence["canary_modified"] is False
    assert evidence["execution_attempted"] is False
