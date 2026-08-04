"""Argus CLI entrypoint.

Public interface:
    python argus.py scan --target ./agent-config --profile banking_agent
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from src.core.config import ConfigurationError, load_config
from src.core.engine import ArgusEngine
from src.core.ingress import IngressError, ingest
from src.reporting import JSONExporter, MarkdownExporter
from src.utils.logger import configure_logging

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FINDINGS = 10
EXIT_ERROR = 1
_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus", description="Argus — local-first AI security evaluation framework"
    )
    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser("scan", help="Run a security evaluation")
    scan_parser.add_argument("--target", required=True, help="Local path or Git URL")
    scan_parser.add_argument("--profile", default="default", help="Configuration profile name")
    scan_parser.add_argument("--output", default=None, help="Report output directory")
    scan_parser.add_argument(
        "--endpoint", default=None, help="Explicitly enable dynamic testing at this endpoint"
    )
    scan_parser.add_argument("--config", default=None, help="Path to default YAML configuration")
    scan_parser.add_argument(
        "--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=None
    )
    scan_parser.add_argument("--verbose", action="store_true", help="Enable diagnostic logging")
    return parser


def _write_reports(results: dict, config, output: str | None) -> list[Path]:
    output_dir = Path(output or config.reporting.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    formats = set(config.reporting.formats)
    if "json" in formats:
        written.append(JSONExporter().export(results, output_dir / "report.json"))
    if "markdown" in formats:
        written.append(MarkdownExporter().export(results, output_dir / "report.md"))
    return written


def _exit_for_results(results: dict, fail_on: str) -> int:
    threshold = _SEVERITY_ORDER[fail_on]
    for finding in results.get("findings", []):
        if _SEVERITY_ORDER.get(str(finding.get("severity", "LOW")), 0) >= threshold:
            return EXIT_FINDINGS
    for attack in results.get("attack_results", []):
        if (
            attack.get("canonical_result", {}).get("attack_succeeded")
            and threshold <= _SEVERITY_ORDER["HIGH"]
        ):
            return EXIT_FINDINGS
    return EXIT_OK


def run_scan(args: argparse.Namespace) -> int:
    configure_logging(bool(getattr(args, "verbose", False)))
    config = load_config(profile=args.profile, config_path=args.config)
    if args.endpoint:
        config = config.model_copy(update={"target_endpoint": args.endpoint})
    context = ingest(args.target, max_file_size=config.engine.max_file_size_bytes)
    context = context.model_copy(
        update={"profile": config.profile, "target_endpoint": args.endpoint}
    )
    results = asyncio.run(ArgusEngine(config).run(context))
    written = _write_reports(results, config, args.output)
    for path in written:
        print(f"[Argus] Report written: {path}")
    fail_on = args.fail_on or config.reporting.fail_on
    return _exit_for_results(results, fail_on)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.print_help()
        return EXIT_USAGE
    try:
        return run_scan(args)
    except (ConfigurationError, IngressError, ValueError, OSError) as exc:
        print(f"[Argus] Error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
