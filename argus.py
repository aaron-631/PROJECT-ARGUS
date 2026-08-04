"""Argus CLI entrypoint.

Public interface:
    python argus.py audit --target ./agent-repository
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from src.core.config import ConfigurationError, load_config
from src.core.engine import ArgusEngine
from src.core.ingress import IngressError, ingest
from src.models.config import TargetConfig
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
    scan_parser = subparsers.add_parser(
        "scan",
        aliases=["audit"],
        help="Audit an agent repository and optionally probe an authorized endpoint",
    )
    scan_parser.add_argument("--target", required=True, help="Local path or Git URL")
    scan_parser.add_argument("--profile", default="default", help="Configuration profile name")
    scan_parser.add_argument("--output", default=None, help="Report output directory")
    scan_parser.add_argument(
        "--endpoint", default=None, help="Explicitly enable dynamic testing at this endpoint"
    )
    scan_parser.add_argument(
        "--provider",
        choices=["generic", "openai", "anthropic", "ollama"],
        default=None,
        help="Live endpoint format (OpenAI also supports OpenAI-compatible gateways)",
    )
    scan_parser.add_argument(
        "--model", default=None, help="Model name required by openai, anthropic, or ollama"
    )
    scan_parser.add_argument(
        "--api-key-env",
        default=None,
        help="Environment variable containing the live target API key",
    )
    scan_parser.add_argument(
        "--auth-header",
        default=None,
        help="Custom live-target auth header, e.g. X-API-Key",
    )
    scan_parser.add_argument(
        "--header-env",
        action="append",
        default=[],
        metavar="HEADER=ENV_VAR",
        help="Read an additional live-target header from an environment variable (repeatable)",
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
        if attack.get("error"):
            return EXIT_ERROR
        if (
            attack.get("canonical_result", {}).get("attack_succeeded")
            and threshold <= _SEVERITY_ORDER["HIGH"]
        ):
            return EXIT_FINDINGS
    return EXIT_OK


def _header_env_values(values: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values:
        name, separator, environment_name = value.partition("=")
        if not separator or not name.strip() or not environment_name.strip():
            raise ConfigurationError(f"--header-env must use HEADER=ENV_VAR: {value}")
        parsed[name.strip()] = environment_name.strip()
    return parsed


def _apply_target_options(config, args: argparse.Namespace):
    updates: dict[str, object] = {}
    for argument, field in (
        ("provider", "provider"),
        ("model", "model"),
        ("api_key_env", "api_key_env"),
        ("auth_header", "auth_header"),
    ):
        value = getattr(args, argument, None)
        if value is not None:
            updates[field] = value
    header_env = _header_env_values(getattr(args, "header_env", []))
    if header_env:
        updates["header_env"] = {**config.target.header_env, **header_env}
    if not updates:
        return config
    target = config.target.model_copy(update=updates)
    return config.model_copy(update={"target": TargetConfig.model_validate(target)})


def _print_summary(
    results: dict, written: list[Path], exit_code: int, endpoint: str | None
) -> None:
    summary = results.get("summary", {})
    findings = results.get("findings", [])
    attacks = results.get("attack_results", [])
    succeeded = sum(
        bool(item.get("canonical_result", {}).get("attack_succeeded")) for item in attacks
    )
    errors = summary.get("errors", [])
    decision = (
        "BLOCK"
        if exit_code == EXIT_FINDINGS
        else "ERROR"
        if exit_code == EXIT_ERROR
        else "PASS"
    )
    print(f"[Argus] Decision: {decision}")
    print(
        "[Argus] Static findings: "
        f"{len(findings)} (critical={summary.get('critical_count', 0)}, "
        f"high={summary.get('high_count', 0)})"
    )
    if endpoint:
        print(
            f"[Argus] Live probes: {len(attacks)}; "
            f"resistant: {len(attacks) - succeeded}; failed: {succeeded}"
        )
    else:
        print("[Argus] Live probes: not run (no --endpoint or ARGUS_TARGET_ENDPOINT)")
    if errors:
        print(f"[Argus] Execution notes: {len(errors)}")
    for path in written:
        print(f"[Argus] Report written: {path}")


def run_scan(args: argparse.Namespace) -> int:
    configure_logging(bool(getattr(args, "verbose", False)))
    config = load_config(profile=args.profile, config_path=args.config)
    config = _apply_target_options(config, args)
    if args.fail_on:
        reporting = config.reporting.model_copy(update={"fail_on": args.fail_on})
        config = config.model_copy(update={"reporting": reporting})
    if args.endpoint:
        config = config.model_copy(update={"target_endpoint": args.endpoint})
    effective_endpoint = args.endpoint or config.target_endpoint
    context = ingest(args.target, max_file_size=config.engine.max_file_size_bytes)
    context = context.model_copy(
        update={"profile": config.profile, "target_endpoint": effective_endpoint}
    )
    results = asyncio.run(ArgusEngine(config).run(context))
    written = _write_reports(results, config, args.output)
    fail_on = args.fail_on or config.reporting.fail_on
    exit_code = _exit_for_results(results, fail_on)
    _print_summary(results, written, exit_code, effective_endpoint)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command not in {"scan", "audit"}:
        parser.print_help()
        return EXIT_USAGE
    try:
        return run_scan(args)
    except (ConfigurationError, IngressError, ValueError, OSError) as exc:
        print(f"[Argus] Error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
