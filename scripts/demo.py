#!/usr/bin/env python3
"""Run the safe, reproducible Argus portfolio demonstration.

The default demo never launches an external package or contacts a provider.
Pass ``--live-mcp`` only when Node/npm and authorization for the pinned demo
server are available.
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

EXPECTED_FINDINGS_EXIT = 10


def _run(root: Path, command: list[str], expected: set[int]) -> subprocess.CompletedProcess[str]:
    print(f"\n$ {' '.join(command)}")
    result = subprocess.run(command, cwd=root, text=True, capture_output=True)
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)
    if result.returncode not in expected:
        raise SystemExit(
            f"Demo step failed with exit code {result.returncode}: {' '.join(command)}"
        )
    return result


def _write_doctor(root: Path, output: Path) -> None:
    result = _run(
        root,
        [sys.executable, "argus.py", "doctor", "--json", "--report-dir", str(output / "doctor")],
        {0},
    )
    doctor_path = output / "doctor.json"
    doctor_path.write_text(result.stdout, encoding="utf-8")
    json.loads(result.stdout)


def _run_mock_llm(root: Path, output: Path) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = subprocess.Popen(
        [
            sys.executable,
            "tests/mock_server.py",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if server.poll() is not None:
                raise SystemExit("The deterministic mock server exited before it became ready")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            raise SystemExit("The deterministic mock server did not become ready")
        _run(
            root,
            [
                sys.executable,
                "argus.py",
                "audit",
                "--target",
                "examples/vulnerable-agent",
                "--endpoint",
                f"http://127.0.0.1:{port}/v1/messages",
                "--fail-on",
                "CRITICAL",
                "--output",
                str(output / "mock-llm"),
            ],
            {EXPECTED_FINDINGS_EXIT},
        )
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


def _run_live_mcp(root: Path, output: Path) -> None:
    if shutil.which("npx") is None:
        print("\n[Argus demo] Skipping live MCP: npx is not available.")
        return
    mcp_root = output / "mcp-root"
    mcp_root.mkdir(parents=True, exist_ok=True)
    _run(
        root,
        [
            sys.executable,
            "argus.py",
            "mcp-probe",
            "--transport",
            "stdio",
            "--command",
            "npx",
            "--arg=-y",
            "--arg=@modelcontextprotocol/server-filesystem@2026.7.10",
            f"--arg={mcp_root}",
            "--server-name",
            "official-filesystem",
            "--timeout",
            "120",
            "--confirm-live",
            "--output",
            str(output / "real-mcp"),
        ],
        {0, EXPECTED_FINDINGS_EXIT},
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Argus portfolio demonstration")
    parser.add_argument(
        "--output",
        default="reports/demo",
        help="Directory for demo evidence (default: reports/demo)",
    )
    parser.add_argument(
        "--live-mcp",
        action="store_true",
        help="Also run the authorized pinned stdio MCP discovery (may download with npx)",
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = (root / args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)

    _write_doctor(root, output)
    static = _run(
        root,
        [
            sys.executable,
            "argus.py",
            "audit",
            "--target",
            "examples/vulnerable-agent",
            "--output",
            str(output / "static"),
        ],
        {EXPECTED_FINDINGS_EXIT},
    )
    if static.returncode != EXPECTED_FINDINGS_EXIT:
        raise SystemExit("The vulnerable fixture did not produce the expected BLOCK result")

    _run(
        root,
        [
            sys.executable,
            "argus.py",
            "audit",
            "--target",
            "examples/vulnerable-agent",
            "--baseline",
            str(output / "static" / "report.json"),
            "--output",
            str(output / "baseline-check"),
        ],
        {0},
    )
    _run_mock_llm(root, output)
    if args.live_mcp:
        _run_live_mcp(root, output)

    print(f"\n[Argus demo] Evidence written to {output}")
    print("[Argus demo] Static, baseline, and mock-LLM checks completed successfully.")
    if not args.live_mcp:
        print("[Argus demo] Use --live-mcp only for an explicitly authorized MCP demo.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
