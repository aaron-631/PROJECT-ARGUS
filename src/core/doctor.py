"""Environment diagnostics for first-time Argus users."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


def _check(name: str, status: str, detail: str, *, required: bool = False) -> dict[str, Any]:
    return {"name": name, "status": status, "detail": detail, "required": required}


def _version(command: str, arguments: Sequence[str] = ("--version",)) -> tuple[bool, str]:
    executable = shutil.which(command)
    if executable is None:
        return False, f"{command} is not on PATH"
    try:
        completed = subprocess.run(
            [executable, *arguments],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{command} could not be checked ({type(exc).__name__})"
    output = (completed.stdout or completed.stderr).strip().splitlines()
    version = output[0][:160] if output else "version unavailable"
    if completed.returncode != 0:
        return False, f"{version} (exit {completed.returncode})"
    return True, version


def _report_directory_check(report_dir: str | Path) -> dict[str, Any]:
    target = Path(report_dir).expanduser()
    if target.exists():
        if not target.is_dir():
            return _check(
                "report directory", "FAIL", f"{target} exists but is not a directory", required=True
            )
        if not os.access(target, os.W_OK):
            return _check("report directory", "FAIL", f"{target} is not writable", required=True)
        return _check("report directory", "PASS", f"{target} is writable", required=True)

    parent = target.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    if parent.is_dir() and os.access(parent, os.W_OK):
        return _check(
            "report directory",
            "PASS",
            f"{target} will be created under writable {parent}",
            required=True,
        )
    return _check(
        "report directory", "FAIL", f"no writable parent found for {target}", required=True
    )


def collect_checks(
    report_dir: str | Path = "./reports", environ: Mapping[str, str] | None = None
) -> list[dict[str, Any]]:
    """Return stable, secret-free environment checks for humans or automation."""

    env = environ if environ is not None else os.environ
    python_ok = sys.version_info >= (3, 11)
    checks = [
        _check(
            "Python",
            "PASS" if python_ok else "FAIL",
            f"{platform.python_version()} (requires Python 3.11+)",
            required=True,
        )
    ]

    node_ok, node_detail = _version("node")
    npm_ok, npm_detail = _version("npm")
    checks.append(
        _check(
            "Node.js/npm",
            "PASS" if node_ok and npm_ok else "WARN",
            f"node: {node_detail}; npm: {npm_detail}; required for npx/stdio MCP demos",
        )
    )

    docker_ok, docker_detail = _version("docker")
    compose_ok = False
    compose_detail = "Docker Compose is not available"
    if docker_ok:
        compose_ok, compose_detail = _version("docker", ("compose", "version"))
    checks.append(
        _check(
            "Docker/Compose",
            "PASS" if docker_ok and compose_ok else "WARN",
            f"docker: {docker_detail}; compose: {compose_detail}; optional for the gateway POC",
        )
    )

    provider_names = {
        "OpenAI": ("OPENAI_API_KEY",),
        "Anthropic": ("ANTHROPIC_API_KEY",),
        "Gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        "Ollama": ("OLLAMA_HOST",),
    }
    configured = [
        provider
        for provider, names in provider_names.items()
        if any(env.get(name) for name in names)
    ]
    provider_detail = (
        f"configured providers: {', '.join(configured)}"
        if configured
        else "no optional provider variables detected; local/static use is still ready"
    )
    checks.append(_check("Provider credentials", "INFO", provider_detail))

    try:
        from src.core.mcp_probe import MCPProbeLimits

        MCPProbeLimits().validate()
        mcp_detail = "stdio and Streamable HTTP discovery are available; tool calls are not used"
        mcp_status = "PASS"
    except (ImportError, ValueError) as exc:
        mcp_detail = f"MCP probe support unavailable ({type(exc).__name__})"
        mcp_status = "FAIL"
    checks.append(_check("MCP transports", mcp_status, mcp_detail, required=True))
    checks.append(_report_directory_check(report_dir))
    return checks


def build_report(
    report_dir: str | Path = "./reports", environ: Mapping[str, str] | None = None
) -> dict[str, Any]:
    checks = collect_checks(report_dir=report_dir, environ=environ)
    required_failures = [item for item in checks if item["required"] and item["status"] == "FAIL"]
    warnings = [item for item in checks if item["status"] == "WARN"]
    return {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "python": platform.python_version(),
        },
        "checks": checks,
        "summary": {
            "status": "FAIL" if required_failures else "PASS",
            "required_failures": len(required_failures),
            "warnings": len(warnings),
        },
    }


def print_report(report: dict[str, Any], *, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return
    for item in report["checks"]:
        print(f"[Argus Doctor] {item['name']}: {item['status']} — {item['detail']}")
    summary = report["summary"]
    suffix = f"; warnings: {summary['warnings']}" if summary["warnings"] else ""
    print(f"[Argus Doctor] Overall: {summary['status']}{suffix}")


def run_doctor(
    report_dir: str | Path = "./reports",
    *,
    strict: bool = False,
    as_json: bool = False,
    environ: Mapping[str, str] | None = None,
) -> int:
    """Run diagnostics; warnings fail only when ``strict`` is requested."""

    report = build_report(report_dir=report_dir, environ=environ)
    print_report(report, as_json=as_json)
    if report["summary"]["status"] == "FAIL":
        return 1
    if strict and report["summary"]["warnings"]:
        return 1
    return 0


__all__ = ["build_report", "collect_checks", "print_report", "run_doctor"]
