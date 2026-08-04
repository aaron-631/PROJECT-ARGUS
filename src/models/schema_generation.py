"""Generate and verify the versioned JSON Schema contract artifacts.

Pydantic models are canonical.  The JSON files in this directory are generated
artifacts for consumers that cannot import Python models.
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from .domain import AttackResult, Finding, ScanReport

ROOT = Path(__file__).resolve().parent
SCHEMA_MODELS: dict[str, type[Any]] = {
    "finding.json": Finding,
    "attack_result.json": AttackResult,
    "report.json": ScanReport,
}


def generated_schemas() -> dict[str, dict[str, Any]]:
    return {filename: model.model_json_schema() for filename, model in SCHEMA_MODELS.items()}


def write_schemas(output_dir: str | Path = ROOT) -> None:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    for filename, schema in generated_schemas().items():
        (destination / filename).write_text(
            json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def schemas_are_current(schema_dir: str | Path = ROOT) -> bool:
    directory = Path(schema_dir)
    with tempfile.TemporaryDirectory(prefix="argus-schema-") as temporary:
        write_schemas(temporary)
        return all(
            (directory / filename).is_file()
            and (directory / filename).read_text(encoding="utf-8")
            == (Path(temporary) / filename).read_text(encoding="utf-8")
            for filename in SCHEMA_MODELS
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate or verify Argus JSON Schema contracts")
    parser.add_argument(
        "--check", action="store_true", help="fail when committed schemas are stale"
    )
    args = parser.parse_args()
    if args.check:
        if not schemas_are_current():
            print("Argus JSON schemas are stale; run python -m src.models.schema_generation")
            return 1
        return 0
    write_schemas()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
