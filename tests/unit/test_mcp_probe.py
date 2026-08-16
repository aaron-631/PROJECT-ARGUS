import asyncio
import json
import json as json_module
import sys
from pathlib import Path

import aiohttp
import pytest

from src.core.mcp_probe import (
    MCPProbeError,
    MCPProbeLimits,
    _parse_sse_json,
    probe_stdio,
    probe_streamable_http,
)


def test_stdio_probe_reads_paginated_tools_without_calling_tools(
    tmp_path: Path, monkeypatch
) -> None:
    server = tmp_path / "mcp_server.py"
    server.write_text(
        """
import json
import os
import sys

assert "ARGUS_PROBE_SECRET" not in os.environ

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        response = {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "fixture", "version": "1.0"},
            },
        }
        print(json.dumps(response), flush=True)
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        if message.get("params", {}).get("cursor"):
            tools = [{"name": "read_file", "inputSchema": {"type": "object"}}]
            result = {"tools": tools}
        else:
            tools = [{"name": "write_file", "inputSchema": {"type": "object"}}]
            result = {"tools": tools, "nextCursor": "page-2"}
        print(
            json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}),
            flush=True,
        )
    elif method == "tools/call":
        print(
            json.dumps({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -1}}),
            flush=True,
        )
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("ARGUS_PROBE_SECRET", "must-not-leak")

    result = asyncio.run(
        probe_stdio(
            [sys.executable, str(server)],
            limits=MCPProbeLimits(timeout_seconds=3.0),
        )
    )

    assert result.pages == 2
    assert [tool["name"] for tool in result.tools] == ["write_file", "read_file"]
    assert result.server_info == {"name": "fixture", "version": "1.0"}


def test_streamable_http_probe_tracks_session_and_pagination(monkeypatch) -> None:
    requests: list[dict] = []

    class FakeContent:
        def __init__(self, body: bytes):
            self.body = body

        async def read(self, limit: int) -> bytes:
            assert len(self.body) <= limit
            return self.body

        async def iter_chunked(self, size: int):
            del size
            yield self.body

    class FakeResponse:
        def __init__(
            self,
            status: int,
            body: object,
            headers: dict[str, str] | None = None,
            raw_body: bytes | None = None,
        ):
            self.status = status
            self.headers = headers or {}
            self.content = FakeContent(
                raw_body
                if raw_body is not None
                else json.dumps(body).encode("utf-8") if body else b""
            )

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

    class FakeSession:
        def __init__(self, **kwargs):
            self.closed = False

        def post(self, endpoint, *, json, headers):
            requests.append({"endpoint": endpoint, "body": json, "headers": headers})
            method = json["method"]
            if method == "initialize":
                return FakeResponse(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": json["id"],
                        "result": {
                            "protocolVersion": "2025-06-18",
                            "serverInfo": {"name": "http-fixture", "version": "1"},
                        },
                    },
                    {"Mcp-Session-Id": "session-1", "Content-Type": "application/json"},
                )
            if method == "notifications/initialized":
                return FakeResponse(202, None)
            if method == "tools/list" and json.get("params", {}).get("cursor"):
                return FakeResponse(
                    200,
                    {"jsonrpc": "2.0", "id": json["id"], "result": {"tools": []}},
                    {"Content-Type": "text/event-stream"},
                    raw_body=(
                        "data: "
                        + json_module.dumps(
                            {
                                "jsonrpc": "2.0",
                                "id": json["id"],
                                "result": {"tools": []},
                            }
                        )
                        + "\n\n: keep-alive\n\n"
                    ).encode("utf-8"),
                )
            return FakeResponse(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": json["id"],
                    "result": {
                        "tools": [{"name": "search", "inputSchema": {"type": "object"}}],
                        "nextCursor": "next",
                    },
                },
                {"Content-Type": "application/json"},
            )

        def delete(self, endpoint, *, headers):
            return FakeResponse(200, None)

        async def close(self):
            self.closed = True

    monkeypatch.setattr(aiohttp, "ClientSession", FakeSession)
    result = asyncio.run(
        probe_streamable_http(
            "https://mcp.example.test/mcp?token=removed",
            headers={"Authorization": "Bearer secret"},
            limits=MCPProbeLimits(timeout_seconds=3.0),
        )
    )

    assert result.pages == 2
    assert [tool["name"] for tool in result.tools] == ["search"]
    assert result.session_id_present is True
    assert requests[1]["headers"]["Mcp-Session-Id"] == "session-1"
    assert requests[1]["headers"]["MCP-Protocol-Version"] == "2025-06-18"
    assert requests[2]["headers"]["MCP-Protocol-Version"] == "2025-06-18"
    assert all(request["body"]["method"] != "tools/call" for request in requests)
    assert result.target == "https://mcp.example.test/mcp"


def test_sse_parser_rejects_a_result_for_another_request() -> None:
    body = b'data: {"jsonrpc":"2.0","id":99,"result":{}}\n\n'
    with pytest.raises(MCPProbeError, match="requested JSON-RPC result"):
        _parse_sse_json(body, request_id=1)
