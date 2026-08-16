"""Argus CLI entrypoint.

Public interface:
    python argus.py audit --target ./agent-repository
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from time import perf_counter
from pathlib import Path

from src.core.config import ConfigurationError, load_config
from src.core.baseline import apply_baseline
from src.core.doctor import run_doctor
from src.core.engine import ArgusEngine
from src.core.ingress import IngressError, ingest
from src.core.sanitization import sanitize
from src.core.taxonomy import taxonomy_for_rule
from src.core.mcp_probe import (
    MCPProbeError,
    MCPProbeLimits,
    MCPProbeResult,
    build_probe_context,
    probe_stdio,
    probe_streamable_http,
    probe_summary,
)
from src.models import SEVERITY_ORDER
from src.models.config import TargetConfig
from src.reporting import JSONExporter, MarkdownExporter, SARIFExporter
from src.utils.logger import configure_logging

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FINDINGS = 10
EXIT_ERROR = 1


def _package_version() -> str:
    """Read the installed version so the CLI can never drift from pyproject."""

    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("argus-framework")
    except PackageNotFoundError:
        return "0.0.0+unknown"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus", description="Argus — local-first AI security evaluation framework"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_package_version()}")
    subparsers = parser.add_subparsers(dest="command")
    doctor_parser = subparsers.add_parser(
        "doctor", help="Check the local environment before scanning or probing"
    )
    doctor_parser.add_argument(
        "--report-dir", default="./reports", help="Directory where reports will be written"
    )
    doctor_parser.add_argument(
        "--strict", action="store_true", help="Treat optional dependency warnings as failures"
    )
    doctor_parser.add_argument(
        "--json", action="store_true", dest="as_json", help="Print machine-readable JSON"
    )
    scan_parser = subparsers.add_parser(
        "scan",
        aliases=["audit"],
        help="Audit an agent repository and optionally probe an authorized endpoint",
    )
    scan_parser.add_argument("--target", required=True, help="Local path or Git URL")
    scan_parser.add_argument("--profile", default="default", help="Configuration profile name")
    scan_parser.add_argument("--output", default=None, help="Report output directory")
    scan_parser.add_argument(
        "--format",
        dest="formats",
        action="append",
        default=None,
        choices=["json", "markdown", "sarif"],
        help="Report format to generate (repeatable; default: all configured formats)",
    )
    scan_parser.add_argument(
        "--disable-rule",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="Suppress a specific rule (repeatable, e.g. --disable-rule ARGUS_ST_003)",
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help=(
            "Skip paths matching a glob or directory name, relative to the target "
            "(repeatable, e.g. --exclude vendor --exclude '*.min.js')"
        ),
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Print machine-readable JSON summary to stdout",
    )
    scan_parser.add_argument(
        "--baseline",
        default=None,
        help="Compare with a previous report.json and fail only on new regressions",
    )
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
    probe_parser = subparsers.add_parser(
        "mcp-probe",
        help="Explicitly connect to an MCP server and read-only discover its tools",
    )
    probe_parser.add_argument("--transport", required=True, choices=["stdio", "streamable-http"])
    probe_parser.add_argument(
        "--command",
        dest="mcp_command",
        default=None,
        help="stdio executable, for example npx or python",
    )
    probe_parser.add_argument(
        "--arg",
        action="append",
        default=[],
        help="One stdio argument; repeat for each argument (use --arg=value for values starting with -)",  # noqa: E501
    )
    probe_parser.add_argument("--endpoint", default=None, help="Streamable HTTP MCP endpoint")
    probe_parser.add_argument("--server-name", default="live-mcp-server")
    probe_parser.add_argument(
        "--header-env",
        action="append",
        default=[],
        metavar="HEADER=ENV_VAR",
        help="Read an HTTP header from an environment variable (repeatable)",
    )
    probe_parser.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="NAME=ENV_VAR",
        help="Expose an environment variable to a stdio server (repeatable)",
    )
    probe_parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Per-operation timeout in seconds; use 120 for a cold npx/uvx install",
    )
    probe_parser.add_argument("--max-tools", type=int, default=1000)
    probe_parser.add_argument("--max-pages", type=int, default=100)
    probe_parser.add_argument("--max-response-bytes", type=int, default=2_000_000)
    probe_parser.add_argument("--max-tool-bytes", type=int, default=100_000)
    probe_parser.add_argument("--profile", default="default", help="Configuration profile name")
    probe_parser.add_argument("--output", default=None, help="Report output directory")
    probe_parser.add_argument(
        "--format",
        dest="formats",
        action="append",
        default=None,
        choices=["json", "markdown", "sarif"],
        help="Report format to generate (repeatable; default: all configured formats)",
    )
    probe_parser.add_argument(
        "--disable-rule",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="Suppress a specific rule (repeatable, e.g. --disable-rule ARGUS_ST_003)",
    )
    probe_parser.add_argument(
        "--baseline",
        default=None,
        help="Compare with a previous report.json and fail only on new regressions",
    )
    probe_parser.add_argument("--config", default=None, help="Path to default YAML configuration")
    probe_parser.add_argument(
        "--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=None
    )
    probe_parser.add_argument(
        "--confirm-live",
        action="store_true",
        help="Confirm that launching/contacting this MCP server is authorized",
    )
    probe_parser.add_argument("--verbose", action="store_true", help="Enable diagnostic logging")

    rules_parser = subparsers.add_parser("rules", help="List all available security rules")
    rules_parser.add_argument(
        "--verbose", action="store_true", help="Show full descriptions and remediation"
    )
    rules_parser.add_argument(
        "--compliance", action="store_true", help="Show OWASP, MITRE ATLAS, and CWE mappings"
    )
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
    if "sarif" in formats:
        written.append(SARIFExporter().export(results, output_dir / "report.sarif"))
    return written


def _exit_for_results(results: dict, fail_on: str) -> int:
    if results.get("summary", {}).get("decision") == "ERROR":
        return EXIT_ERROR
    baseline = results.get("summary", {}).get("baseline")
    if isinstance(baseline, dict):
        if baseline.get("gate") == "BLOCK":
            return EXIT_FINDINGS
        if baseline.get("gate") == "ERROR":
            return EXIT_ERROR
        if baseline.get("gate") == "PASS":
            return EXIT_OK
    threshold = SEVERITY_ORDER[fail_on]
    for finding in results.get("findings", []):
        if SEVERITY_ORDER.get(str(finding.get("severity", "LOW")), 0) >= threshold:
            return EXIT_FINDINGS
    for attack in results.get("attack_results", []):
        if attack.get("error"):
            return EXIT_ERROR
        if (
            attack.get("canonical_result", {}).get("attack_succeeded")
            and threshold <= SEVERITY_ORDER["HIGH"]
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


def _read_selected_environment(values: list[str], option: str) -> dict[str, str]:
    mapping = _header_env_values(values)
    selected: dict[str, str] = {}
    for child_name, environment_name in mapping.items():
        if environment_name not in os.environ:
            raise ConfigurationError(
                f"{option} references an unset environment variable: {environment_name}"
            )
        selected[child_name] = os.environ[environment_name]
    return selected


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
        "BLOCK" if exit_code == EXIT_FINDINGS else "ERROR" if exit_code == EXIT_ERROR else "PASS"
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
    baseline = summary.get("baseline")
    if isinstance(baseline, dict):
        print(
            "[Argus] Baseline: "
            f"{baseline.get('gate', 'UNKNOWN')} "
            f"(new findings={baseline.get('new_finding_count', 0)}, "
            f"severity increases={baseline.get('changed_finding_count', 0)}, "
            f"new attack failures={baseline.get('new_attack_failure_count', 0)})"
        )
    performance = summary.get("performance")
    if isinstance(performance, dict):
        elapsed = performance.get("elapsed_seconds")
        details = f"{elapsed:.3f}s" if isinstance(elapsed, (int, float)) else "unknown"
        if performance.get("files_scanned") is not None:
            details += f"; files: {performance['files_scanned']}"
        if performance.get("tool_count") is not None:
            details += f"; tools: {performance['tool_count']}"
        print(f"[Argus] Performance: {details}")
    for path in written:
        print(f"[Argus] Report written: {path}")


def run_scan(args: argparse.Namespace) -> int:
    configure_logging(bool(getattr(args, "verbose", False)))
    operation_started = perf_counter()
    config = load_config(profile=args.profile, config_path=args.config)
    config = _apply_target_options(config, args)
    if args.formats:
        reporting = config.reporting.model_copy(update={"formats": args.formats})
        config = config.model_copy(update={"reporting": reporting})
    if args.disable_rule:
        existing = list(getattr(config, "disabled_rules", []))
        existing.extend(args.disable_rule)
        config = config.model_copy(update={"disabled_rules": existing})
    if args.fail_on:
        reporting = config.reporting.model_copy(update={"fail_on": args.fail_on})
        config = config.model_copy(update={"reporting": reporting})
    if args.endpoint:
        config = config.model_copy(update={"target_endpoint": args.endpoint})
    effective_endpoint = args.endpoint or config.target_endpoint
    ingest_started = perf_counter()
    context = ingest(
        args.target,
        max_file_size=config.engine.max_file_size_bytes,
        exclude=tuple(getattr(args, "exclude", []) or ()),
    )
    ingest_seconds = perf_counter() - ingest_started
    context = context.model_copy(
        update={"profile": config.profile, "target_endpoint": effective_endpoint}
    )
    evaluation_started = perf_counter()
    results = asyncio.run(ArgusEngine(config).run(context))
    evaluation_seconds = perf_counter() - evaluation_started
    results["summary"]["performance"] = {
        "operation": "scan",
        "files_scanned": len(context.files),
        "ingest_seconds": round(ingest_seconds, 3),
        "evaluation_seconds": round(evaluation_seconds, 3),
        "elapsed_seconds": round(perf_counter() - operation_started, 3),
    }
    if args.baseline:
        apply_baseline(results, args.baseline)
    written = _write_reports(results, config, args.output)
    fail_on = args.fail_on or config.reporting.fail_on
    exit_code = _exit_for_results(results, fail_on)
    if getattr(args, "as_json", False):
        import json

        print(json.dumps(results.get("summary", {}), indent=2))
    else:
        _print_summary(results, written, exit_code, effective_endpoint)
    return exit_code


def _mcp_probe_server_metadata(args: argparse.Namespace) -> dict[str, object]:
    if args.transport == "stdio":
        return {
            "name": args.server_name,
            "file": "mcp-probe.json",
            "transport": "stdio",
            "command": Path(args.mcp_command or "unknown").name,
            "host": None,
            "verified": False,
        }
    from urllib.parse import urlsplit

    parsed = urlsplit(args.endpoint or "")
    return {
        "name": args.server_name,
        "file": "mcp-probe.json",
        "transport": "streamable-http",
        "command": None,
        "host": parsed.hostname,
        "verified": False,
    }


def _run_mcp_probe_report(
    args: argparse.Namespace,
    config,
    result=None,
    error: str | None = None,
    elapsed_seconds: float | None = None,
) -> tuple[list[Path], dict]:
    if result is None:
        context = build_probe_context(
            MCPProbeResult(
                transport=args.transport,
                target=(args.endpoint or f"stdio:{Path(args.mcp_command or 'unknown').name}"),
                protocol_version="unknown",
                server_info={},
                tools=[],
                pages=0,
                session_id_present=False,
            )
        )
    else:
        context = build_probe_context(result)
    results = asyncio.run(ArgusEngine(config).run(context))
    results["summary"]["mcp_servers"] = [
        _mcp_probe_server_metadata(args),
        *results["summary"].get("mcp_servers", []),
    ]
    if result is not None:
        results["summary"]["mcp_probe"] = probe_summary(result, args.server_name)
        if elapsed_seconds is not None:
            results["summary"]["mcp_probe"]["elapsed_seconds"] = round(elapsed_seconds, 3)
    if elapsed_seconds is not None:
        results["summary"]["performance"] = {
            "operation": "mcp-probe",
            "elapsed_seconds": round(elapsed_seconds, 3),
            "tool_count": len(result.tools) if result is not None else 0,
        }
    if error:
        results["summary"].setdefault("errors", []).append(error)
        results["summary"]["decision"] = "ERROR"
    if args.baseline and not error:
        apply_baseline(results, args.baseline)
    written = _write_reports(results, config, args.output)
    return written, results


def run_mcp_probe(args: argparse.Namespace) -> int:
    configure_logging(bool(getattr(args, "verbose", False)))
    if not args.confirm_live:
        raise ConfigurationError(
            "mcp-probe requires --confirm-live because it starts or contacts a live MCP server"
        )
    config = load_config(profile=args.profile, config_path=args.config)
    if args.formats:
        reporting = config.reporting.model_copy(update={"formats": args.formats})
        config = config.model_copy(update={"reporting": reporting})
    if args.disable_rule:
        existing = list(getattr(config, "disabled_rules", []))
        existing.extend(args.disable_rule)
        config = config.model_copy(update={"disabled_rules": existing})
    if args.fail_on:
        reporting = config.reporting.model_copy(update={"fail_on": args.fail_on})
        config = config.model_copy(update={"reporting": reporting})
    headers = _read_selected_environment(args.header_env, "--header-env")
    process_environment = _read_selected_environment(args.env, "--env")
    limits = MCPProbeLimits(
        timeout_seconds=args.timeout,
        max_tools=args.max_tools,
        max_pages=args.max_pages,
        max_response_bytes=args.max_response_bytes,
        max_tool_bytes=args.max_tool_bytes,
    )
    operation_started = perf_counter()
    try:
        if args.transport == "stdio":
            if not args.mcp_command:
                raise ConfigurationError("--command is required for stdio MCP probing")
            result = asyncio.run(
                probe_stdio(
                    [args.mcp_command, *args.arg],
                    server_name=args.server_name,
                    environment=process_environment,
                    limits=limits,
                )
            )
        else:
            if not args.endpoint:
                raise ConfigurationError("--endpoint is required for Streamable HTTP probing")
            result = asyncio.run(
                probe_streamable_http(
                    args.endpoint,
                    headers=headers,
                    server_name=args.server_name,
                    limits=limits,
                )
            )
        written, results = _run_mcp_probe_report(
            args, config, result=result, elapsed_seconds=perf_counter() - operation_started
        )
    except MCPProbeError as exc:
        detail = sanitize(str(exc))
        written, results = _run_mcp_probe_report(
            args,
            config,
            error=f"mcp probe failed: {type(exc).__name__}: {detail}",
            elapsed_seconds=perf_counter() - operation_started,
        )
        print(f"[Argus] MCP probe failed: {type(exc).__name__}: {detail}", file=sys.stderr)
        for path in written:
            print(f"[Argus] Report written: {path}")
        return EXIT_ERROR
    decision = results["summary"].get("decision", "UNKNOWN")
    exit_code = _exit_for_results(results, args.fail_on or config.reporting.fail_on)
    print(f"[Argus] Decision: {'BLOCK' if exit_code == EXIT_FINDINGS else 'PASS'}")
    print(
        f"[Argus] MCP transport: {args.transport}; tools discovered: "
        f"{results['summary'].get('mcp_probe', {}).get('tool_count', 0)}"
    )
    print("[Argus] Tool calls: 0 (read-only discovery)")
    performance = results["summary"].get("performance")
    if isinstance(performance, dict) and isinstance(
        performance.get("elapsed_seconds"), (int, float)
    ):
        print(f"[Argus] Performance: {performance['elapsed_seconds']:.3f}s")
    if decision == "ERROR":
        return EXIT_ERROR
    for path in written:
        print(f"[Argus] Report written: {path}")
    return exit_code


def run_rules(args: argparse.Namespace) -> int:
    from src.modules.scanners.mcp_scanner import _RULES

    for rule_id, (severity, title, description, _score, remediation) in sorted(_RULES.items()):
        sev = severity.value if hasattr(severity, "value") else str(severity)
        print(f"{rule_id} [{sev}] {title}")
        if args.compliance:
            mapping = taxonomy_for_rule(rule_id)
            print(f"  OWASP: {', '.join(mapping.owasp_ids) or 'not mapped'}")
            print(f"  ATLAS: {', '.join(mapping.atlas_ids) or 'not mapped'}")
            print(f"  CWE: {', '.join(mapping.cwe_ids) or 'not assigned'}")
            print(f"  Status: {mapping.status}")
        if args.verbose:
            print(f"  {description}")
            print(f"  Fix: {remediation}")
            print()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in {"scan", "audit"}:
        runner = run_scan
    elif args.command == "rules":
        return run_rules(args)
    elif args.command == "mcp-probe":
        runner = run_mcp_probe
    elif args.command == "doctor":
        return run_doctor(args.report_dir, strict=args.strict, as_json=args.as_json)
    else:
        parser.print_help()
        return EXIT_USAGE
    try:
        return runner(args)
    except (ConfigurationError, IngressError, ValueError, OSError) as exc:
        print(f"[Argus] Error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
