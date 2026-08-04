"""Read-only MCP discovery for explicitly authorized live servers.

The probe performs only the MCP lifecycle needed to inspect a server:
``initialize``, ``notifications/initialized``, and paginated ``tools/list``.
It never sends ``tools/call`` and never executes a command unless the caller
explicitly starts this opt-in workflow.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import aiohttp

from src.core.documents import parse_context
from src.core.sanitization import sanitize, sanitize_value
from src.models import FileRecord, ScanContext, SourceMetadata

MCP_PROTOCOL_VERSION = "2025-06-18"
_DEFAULT_MAX_RESPONSE_BYTES = 2_000_000
_DEFAULT_MAX_TOOL_BYTES = 100_000
_SAFE_PROCESS_ENVIRONMENT = (
    "PATH",
    "HOME",
    "USERPROFILE",
    "SystemRoot",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "APPDATA",
    "LOCALAPPDATA",
)


class MCPProbeError(ValueError):
    """Raised when a read-only MCP discovery cannot complete safely."""


@dataclass(frozen=True)
class MCPProbeLimits:
    timeout_seconds: float = 15.0
    max_tools: int = 1000
    max_pages: int = 100
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES
    max_tool_bytes: int = _DEFAULT_MAX_TOOL_BYTES

    def validate(self) -> None:
        if not 0.1 <= self.timeout_seconds <= 600:
            raise MCPProbeError("timeout must be between 0.1 and 600 seconds")
        if not 1 <= self.max_tools <= 100_000:
            raise MCPProbeError("max_tools must be between 1 and 100000")
        if not 1 <= self.max_pages <= 10_000:
            raise MCPProbeError("max_pages must be between 1 and 10000")
        if not 1024 <= self.max_response_bytes <= 50_000_000:
            raise MCPProbeError("max_response_bytes must be between 1024 and 50000000")
        if not 1024 <= self.max_tool_bytes <= self.max_response_bytes:
            raise MCPProbeError("max_tool_bytes must be <= max_response_bytes")


@dataclass(frozen=True)
class MCPProbeResult:
    transport: str
    target: str
    protocol_version: str
    server_info: dict[str, Any]
    tools: list[dict[str, Any]]
    pages: int
    session_id_present: bool


def _safe_http_target(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    if not parsed.scheme or not parsed.netloc:
        raise MCPProbeError("MCP endpoint must be an absolute HTTP(S) URL")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _safe_server_info(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, Any] = {}
    for key in ("name", "version", "title", "description"):
        item = value.get(key)
        if isinstance(item, str):
            result[key] = sanitize(item)[:500]
    return result


def _safe_tool(tool: Any, max_tool_bytes: int) -> dict[str, Any]:
    if not isinstance(tool, dict):
        raise MCPProbeError("MCP tools/list returned a non-object tool")
    name = tool.get("name")
    if not isinstance(name, str) or not name.strip():
        raise MCPProbeError("MCP tools/list returned a tool without a name")
    try:
        encoded_size = len(json.dumps(tool, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise MCPProbeError("MCP tool metadata was not JSON serializable") from exc
    if encoded_size > max_tool_bytes:
        raise MCPProbeError("MCP tool metadata exceeded the configured size limit")
    safe = sanitize_value(tool)
    if not isinstance(safe, dict):
        raise MCPProbeError("MCP tool metadata could not be sanitized")
    safe["name"] = sanitize(name)[:300]
    if isinstance(safe.get("description"), str):
        safe["description"] = safe["description"][:4000]
    return safe


def _tools_from_result(
    result: Any, limits: MCPProbeLimits
) -> tuple[list[dict[str, Any]], str | None]:
    if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
        raise MCPProbeError("MCP tools/list response did not contain a tools array")
    tools = [_safe_tool(tool, limits.max_tool_bytes) for tool in result["tools"]]
    if len(tools) > limits.max_tools:
        raise MCPProbeError("MCP server returned more tools than the configured limit")
    cursor = result.get("nextCursor")
    if cursor is not None and not isinstance(cursor, str):
        raise MCPProbeError("MCP tools/list returned a non-string nextCursor")
    return tools, cursor


def _json_message(message: dict[str, Any]) -> bytes:
    return (json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _process_environment(overrides: dict[str, str] | None) -> dict[str, str]:
    """Build a minimal child environment without inheriting ambient secrets."""

    environment = {
        name: os.environ[name] for name in _SAFE_PROCESS_ENVIRONMENT if name in os.environ
    }
    environment.update(overrides or {})
    return environment


class _StdioSession:
    def __init__(
        self,
        command: list[str],
        limits: MCPProbeLimits,
        environment: dict[str, str] | None,
    ) -> None:
        if not command or any(not item for item in command):
            raise MCPProbeError("stdio MCP command must contain a command and non-empty arguments")
        self.command = command
        self.limits = limits
        self.environment = _process_environment(environment)
        self.process: asyncio.subprocess.Process | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._request_id = 0
        self._isolated_process_group = os.name == "posix"

    async def start(self) -> None:
        try:
            process_options: dict[str, Any] = {
                "stdin": asyncio.subprocess.PIPE,
                "stdout": asyncio.subprocess.PIPE,
                "stderr": asyncio.subprocess.PIPE,
                "env": self.environment,
                "limit": self.limits.max_response_bytes + 1024,
            }
            if self._isolated_process_group:
                process_options["start_new_session"] = True
            self.process = await asyncio.create_subprocess_exec(*self.command, **process_options)
        except (OSError, ValueError) as exc:
            raise MCPProbeError(f"unable to start MCP stdio server: {type(exc).__name__}") from exc
        if self.process.stderr is not None:
            self._stderr_task = asyncio.create_task(self._drain_stderr())

    async def _drain_stderr(self) -> None:
        if self.process is None or self.process.stderr is None:
            return
        while await self.process.stderr.readline():
            pass

    async def _send(self, message: dict[str, Any]) -> None:
        if self.process is None or self.process.stdin is None:
            raise MCPProbeError("MCP stdio server is not running")
        self.process.stdin.write(_json_message(message))
        try:
            await asyncio.wait_for(self.process.stdin.drain(), self.limits.timeout_seconds)
        except (asyncio.TimeoutError, ConnectionError) as exc:
            raise MCPProbeError("MCP stdio write timed out") from exc

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        await self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    async def request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        self._request_id += 1
        request_id = self._request_id
        await self._send(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
        )
        if self.process is None or self.process.stdout is None:
            raise MCPProbeError("MCP stdio server has no stdout")
        while True:
            try:
                line = await asyncio.wait_for(
                    self.process.stdout.readline(), self.limits.timeout_seconds
                )
            except asyncio.TimeoutError as exc:
                raise MCPProbeError(f"MCP stdio request timed out: {method}") from exc
            if not line:
                raise MCPProbeError("MCP stdio server exited before returning a response")
            if len(line) > self.limits.max_response_bytes:
                raise MCPProbeError("MCP stdio response exceeded the configured size limit")
            try:
                message = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise MCPProbeError("MCP stdio server emitted invalid JSON") from exc
            if not isinstance(message, dict):
                raise MCPProbeError("MCP stdio server emitted a non-object JSON message")
            if message.get("id") != request_id:
                if message.get("method") and message.get("id") is not None:
                    await self._send(
                        {
                            "jsonrpc": "2.0",
                            "id": message["id"],
                            "error": {
                                "code": -32601,
                                "message": "Argus probe does not serve requests",
                            },
                        }
                    )
                continue
            if "error" in message:
                raise MCPProbeError(f"MCP {method} request returned an error")
            return message.get("result")

    async def close(self) -> None:
        if self.process is not None and self.process.returncode is None:
            if self.process.stdin is not None:
                self.process.stdin.close()
            if self._isolated_process_group:
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            else:
                self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), 2.0)
            except asyncio.TimeoutError:
                if self._isolated_process_group:
                    try:
                        os.killpg(self.process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    self.process.kill()
                await self.process.wait()
        if self._stderr_task is not None:
            self._stderr_task.cancel()
            await asyncio.gather(self._stderr_task, return_exceptions=True)


async def _list_tools(
    session: _StdioSession | "_HTTPStreamableSession", limits: MCPProbeLimits
) -> tuple[list[dict[str, Any]], int]:
    all_tools: list[dict[str, Any]] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    pages = 0
    while True:
        pages += 1
        if pages > limits.max_pages:
            raise MCPProbeError("MCP tools/list exceeded the configured page limit")
        params = {"cursor": cursor} if cursor is not None else {}
        page, next_cursor = _tools_from_result(await session.request("tools/list", params), limits)
        all_tools.extend(page)
        if len(all_tools) > limits.max_tools:
            raise MCPProbeError("MCP server returned more tools than the configured limit")
        if next_cursor is None:
            return all_tools, pages
        if next_cursor in seen_cursors:
            raise MCPProbeError("MCP tools/list returned a repeated pagination cursor")
        seen_cursors.add(next_cursor)
        cursor = next_cursor


async def probe_stdio(
    command: list[str],
    *,
    server_name: str = "stdio-mcp-server",
    environment: dict[str, str] | None = None,
    limits: MCPProbeLimits | None = None,
) -> MCPProbeResult:
    """Launch a specified stdio server and discover tools without calling one."""

    probe_limits = limits or MCPProbeLimits()
    probe_limits.validate()
    session = _StdioSession(command, probe_limits, environment)
    await session.start()
    try:
        initialized = await session.request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "argus", "version": "1.0.0"},
            },
        )
        await session.notify("notifications/initialized")
        tools, pages = await _list_tools(session, probe_limits)
        return MCPProbeResult(
            transport="stdio",
            target=f"stdio:{Path(command[0]).name}",
            protocol_version=(
                initialized.get("protocolVersion", MCP_PROTOCOL_VERSION)
                if isinstance(initialized, dict)
                else MCP_PROTOCOL_VERSION
            ),
            server_info=(
                _safe_server_info(initialized.get("serverInfo"))
                if isinstance(initialized, dict)
                else {}
            ),
            tools=tools,
            pages=pages,
            session_id_present=False,
        )
    finally:
        await session.close()


def _parse_sse_json(body: bytes) -> dict[str, Any]:
    text = body.decode("utf-8", errors="strict")
    data_lines: list[str] = []
    messages: list[dict[str, Any]] = []
    for line in text.splitlines():
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
        elif not line.strip() and data_lines:
            candidate = "\n".join(data_lines)
            data_lines = []
            try:
                message = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict):
                messages.append(message)
    if data_lines:
        try:
            message = json.loads("\n".join(data_lines))
        except json.JSONDecodeError:
            message = None
        if isinstance(message, dict):
            messages.append(message)
    for message in messages:
        if "result" in message or "error" in message:
            return message
    raise MCPProbeError("MCP SSE response did not contain a JSON-RPC result")


async def _read_sse_result(response: aiohttp.ClientResponse, max_bytes: int) -> dict[str, Any]:
    """Read an SSE response until the requested JSON-RPC result arrives."""

    buffer = b""
    total_bytes = 0
    async for chunk in response.content.iter_chunked(8192):
        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            raise MCPProbeError("MCP HTTP response exceeded the configured size limit")
        buffer += chunk
        while True:
            separators = [
                position
                for position in (buffer.find(b"\n\n"), buffer.find(b"\r\n\r\n"))
                if position >= 0
            ]
            if not separators:
                break
            position = min(separators)
            separator_length = 4 if buffer[position : position + 4] == b"\r\n\r\n" else 2
            event = buffer[:position]
            buffer = buffer[position + separator_length :]
            try:
                return _parse_sse_json(event)
            except MCPProbeError:
                continue
    if buffer:
        return _parse_sse_json(buffer)
    raise MCPProbeError("MCP SSE response did not contain a JSON-RPC result")


class _HTTPStreamableSession:
    def __init__(self, endpoint: str, headers: dict[str, str], limits: MCPProbeLimits) -> None:
        self.endpoint = _safe_http_target(endpoint)
        self.headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            **headers,
        }
        self.limits = limits
        self.session_id: str | None = None
        self.protocol_version: str | None = None
        self.session: aiohttp.ClientSession | None = None
        self._request_id = 0

    async def start(self) -> None:
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.limits.timeout_seconds)
        )

    async def request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        if self.session is None:
            raise MCPProbeError("MCP HTTP session is not running")
        self._request_id += 1
        request_id = self._request_id
        headers = dict(self.headers)
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        body = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
        try:
            async with self.session.post(self.endpoint, json=body, headers=headers) as response:
                if response.status < 200 or response.status >= 300:
                    raise MCPProbeError(f"MCP HTTP request returned status {response.status}")
                session_id = response.headers.get("Mcp-Session-Id")
                if session_id:
                    self.session_id = session_id
                content_type = response.headers.get("Content-Type", "").lower()
                if "text/event-stream" in content_type:
                    message = await _read_sse_result(response, self.limits.max_response_bytes)
                else:
                    raw = await response.content.read(self.limits.max_response_bytes + 1)
                    if len(raw) > self.limits.max_response_bytes:
                        raise MCPProbeError("MCP HTTP response exceeded the configured size limit")
                    if not raw:
                        return {}
                    message = json.loads(raw.decode("utf-8"))
        except MCPProbeError:
            raise
        except (
            aiohttp.ClientError,
            asyncio.TimeoutError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise MCPProbeError(f"MCP HTTP request failed: {type(exc).__name__}") from exc
        if not isinstance(message, dict):
            raise MCPProbeError("MCP HTTP response was not a JSON-RPC object")
        if "error" in message:
            raise MCPProbeError(f"MCP {method} request returned an error")
        result = message.get("result")
        if method == "initialize" and isinstance(result, dict):
            negotiated = result.get("protocolVersion")
            self.protocol_version = negotiated if isinstance(negotiated, str) else None
        return result

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        if self.session is None:
            raise MCPProbeError("MCP HTTP session is not running")
        headers = dict(self.headers)
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        body = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        try:
            async with self.session.post(self.endpoint, json=body, headers=headers) as response:
                if response.status < 200 or response.status >= 300:
                    raise MCPProbeError(f"MCP HTTP notification returned status {response.status}")
        except MCPProbeError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise MCPProbeError(f"MCP HTTP notification failed: {type(exc).__name__}") from exc

    async def close(self) -> None:
        if self.session is None:
            return
        if self.session_id:
            headers = dict(self.headers)
            headers["Mcp-Session-Id"] = self.session_id
            if self.protocol_version:
                headers["MCP-Protocol-Version"] = self.protocol_version
            try:
                async with self.session.delete(self.endpoint, headers=headers):
                    pass
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
        await self.session.close()
        self.session = None


async def probe_streamable_http(
    endpoint: str,
    *,
    headers: dict[str, str] | None = None,
    server_name: str = "streamable-http-mcp-server",
    limits: MCPProbeLimits | None = None,
) -> MCPProbeResult:
    """Discover tools from an MCP Streamable HTTP endpoint without calling one."""

    del server_name  # Reserved for a future multi-server report field.
    probe_limits = limits or MCPProbeLimits()
    probe_limits.validate()
    session = _HTTPStreamableSession(endpoint, headers or {}, probe_limits)
    await session.start()
    try:
        initialized = await session.request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "argus", "version": "1.0.0"},
            },
        )
        await session.notify("notifications/initialized")
        tools, pages = await _list_tools(session, probe_limits)
        return MCPProbeResult(
            transport="streamable-http",
            target=session.endpoint,
            protocol_version=(
                initialized.get("protocolVersion", MCP_PROTOCOL_VERSION)
                if isinstance(initialized, dict)
                else MCP_PROTOCOL_VERSION
            ),
            server_info=(
                _safe_server_info(initialized.get("serverInfo"))
                if isinstance(initialized, dict)
                else {}
            ),
            tools=tools,
            pages=pages,
            session_id_present=session.session_id is not None,
        )
    finally:
        await session.close()


def build_probe_context(result: MCPProbeResult) -> ScanContext:
    """Build a normal Argus scan context from safe, in-memory tool metadata."""

    payload = json.dumps({"tools": result.tools}, ensure_ascii=False, sort_keys=True)
    record = FileRecord(
        path="mcp-probe.json",
        content=payload,
        size_bytes=len(payload.encode("utf-8")),
        sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        language="json",
    )
    context = ScanContext(
        source_path=result.target,
        source_type="local",
        files={record.path: record},
        source_metadata=SourceMetadata(source_type="local", source=result.target),
    )
    return parse_context(context)


def probe_summary(result: MCPProbeResult, server_name: str) -> dict[str, Any]:
    """Return report-safe metadata about a completed read-only probe."""

    return {
        "server_name": sanitize(server_name)[:200],
        "transport": result.transport,
        "target": result.target,
        "protocol_version": sanitize(result.protocol_version)[:100],
        "server_info": result.server_info,
        "pages": result.pages,
        "tool_count": len(result.tools),
        "tool_calls": 0,
        "read_only": True,
        "session_id_present": result.session_id_present,
    }


__all__ = [
    "MCPProbeError",
    "MCPProbeLimits",
    "MCPProbeResult",
    "build_probe_context",
    "probe_stdio",
    "probe_streamable_http",
    "probe_summary",
]
