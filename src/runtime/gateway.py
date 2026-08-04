"""Provider-neutral HTTP reverse proxy with runtime policy enforcement."""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import uuid
from time import perf_counter
from typing import Any

import aiohttp
from aiohttp import web

from .approval import ApprovalClient
from .audit import AuditWriter
from .audit_sink import AuditSink
from .config import RuntimeConfig
from .metrics import RuntimeMetrics
from .policy import RuntimePolicy


class RuntimeGateway:
    def __init__(
        self,
        config: RuntimeConfig,
        session: aiohttp.ClientSession | None = None,
        audit: AuditWriter | None = None,
        metrics: RuntimeMetrics | None = None,
    ) -> None:
        self.config = config
        self.policy = RuntimePolicy(config.policy)
        self.session = session
        self._owns_session = session is None
        audit_key = os.getenv(config.audit_hmac_key_env)
        self.audit = audit or AuditWriter(
            config.audit_path, audit_key.encode("utf-8") if audit_key else None
        )
        self.metrics = metrics or RuntimeMetrics()
        self.approval_client = (
            ApprovalClient(
                config.approval_service_url,
                config.approval_service_token_env,
                config.approval_service_timeout_seconds,
            )
            if config.approval_service_url
            else None
        )
        self.audit_sink = (
            AuditSink(
                config.audit_sink_url,
                config.audit_sink_token_env,
                config.audit_sink_timeout_seconds,
                config.audit_sink_max_retries,
            )
            if config.audit_sink_url
            else None
        )
        self._audit_ship_tasks: set[asyncio.Task[bool]] = set()

    async def start(self) -> None:
        if self.session is None:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config.request_timeout_seconds)
            )

    async def close(self) -> None:
        if self._audit_ship_tasks:
            await asyncio.gather(*self._audit_ship_tasks, return_exceptions=True)
        if self._owns_session and self.session is not None:
            await self.session.close()
            self.session = None

    def _audit_ship_done(self, task: asyncio.Task[bool]) -> None:
        self._audit_ship_tasks.discard(task)
        try:
            if not task.result():
                self.metrics.observe_audit_ship_failure()
        except asyncio.CancelledError:
            pass
        except Exception:
            self.metrics.observe_audit_ship_failure()

    @staticmethod
    def _request_id(request: web.Request) -> str:
        supplied = request.headers.get("X-Request-ID", "").strip()
        return supplied[:100] if supplied else uuid.uuid4().hex

    def _audit(
        self,
        request_id: str,
        decision: str,
        reason_codes: list[str],
        status_code: int,
        started: float,
        tool_names: list[str] | None = None,
        upstream_status: int | None = None,
        redaction_count: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.metrics.observe_request(decision)
        self.metrics.observe_redaction(redaction_count)
        if upstream_status is not None:
            self.metrics.observe_upstream(upstream_status)
        record = self.audit.write(
            {
                "event_type": "runtime_request",
                "request_id": request_id,
                "decision": decision,
                "reason_codes": reason_codes,
                "tool_names": tool_names or [],
                "status_code": status_code,
                "upstream_status": upstream_status,
                "latency_ms": round((perf_counter() - started) * 1000, 3),
                "redaction_count": redaction_count,
                "metadata": metadata or {},
            }
        )
        if self.audit_sink is not None and self.session is not None:
            task = asyncio.create_task(self.audit_sink.publish(self.session, record))
            self._audit_ship_tasks.add(task)
            task.add_done_callback(self._audit_ship_done)

    async def _policy_response(
        self,
        request_id: str,
        decision: str,
        reason_codes: list[str],
        status_code: int,
        started: float,
        tool_names: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> web.Response:
        self._audit(
            request_id,
            decision,
            reason_codes,
            status_code,
            started,
            tool_names,
            metadata=metadata,
        )
        message = "Request blocked by Argus runtime policy"
        if decision == "review":
            message = "Human approval is required by Argus runtime policy"
        return web.json_response(
            {
                "error": {
                    "type": "argus_policy_enforced",
                    "message": message,
                    "request_id": request_id,
                    "reason_codes": reason_codes,
                }
            },
            status=status_code,
            headers={"X-Argus-Decision": decision, "X-Request-ID": request_id},
        )

    def _forward_headers(self, request: web.Request) -> dict[str, str]:
        allowed = {header.lower() for header in self.config.forward_headers}
        never_forward = {
            "connection",
            "content-length",
            "host",
            "transfer-encoding",
            self.config.approval_header.lower(),
            self.config.client_auth_header.lower(),
        }
        return {
            key: value
            for key, value in request.headers.items()
            if key.lower() in allowed and key.lower() not in never_forward
        }

    def _client_auth_failure(self, request: web.Request) -> tuple[int, str] | None:
        if not self.config.require_client_auth:
            return None
        expected = os.getenv(self.config.client_auth_token_env)
        if not expected:
            return 503, "CLIENT_AUTH_NOT_CONFIGURED"
        supplied = request.headers.get(self.config.client_auth_header, "")
        if not supplied or not hmac.compare_digest(supplied, expected):
            return 401, "CLIENT_AUTH_REQUIRED"
        return None

    async def _resolve_approval(
        self,
        request_id: str,
        body: dict[str, Any],
        decision: Any,
        approval_token: str | None,
        configured_token: str | None,
        response: bool = False,
    ) -> Any:
        if decision.decision != "review" or self.approval_client is None:
            return decision
        assert self.session is not None
        result = await self.approval_client.authorize(
            self.session, request_id, body, decision.reason_codes
        )
        if not result.approved:
            return decision.model_copy(
                update={
                    "reason_codes": decision.reason_codes + [result.reason_code],
                    "metadata": {
                        **decision.metadata,
                        "approval_service": result.reason_code,
                    },
                }
            )
        if response:
            resolved, _ = self.policy.inspect_response(
                body, approval_token, configured_token, approval_granted=True
            )
        else:
            resolved = self.policy.inspect_request(
                body, approval_token, configured_token, approval_granted=True
            )
        return resolved.model_copy(
            update={
                "metadata": {
                    **resolved.metadata,
                    "approval_decision_id": result.decision_id or "approved",
                }
            }
        )

    async def handle_messages(self, request: web.Request) -> web.Response:
        started = perf_counter()
        request_id = self._request_id(request)
        if self.session is None:
            await self.start()
        auth_failure = self._client_auth_failure(request)
        if auth_failure is not None:
            status_code, reason_code = auth_failure
            return await self._policy_response(
                request_id, "block", [reason_code], status_code, started
            )
        try:
            raw_body = await request.read()
        except web.HTTPRequestEntityTooLarge:
            return await self._policy_response(
                request_id, "block", ["REQUEST_TOO_LARGE"], 413, started
            )
        if len(raw_body) > self.config.max_body_bytes:
            return await self._policy_response(
                request_id, "block", ["REQUEST_TOO_LARGE"], 413, started
            )
        try:
            body: Any = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return await self._policy_response(request_id, "block", ["INVALID_JSON"], 400, started)
        if isinstance(body, dict) and body.get("stream") is True:
            if not self.config.allow_buffered_streaming:
                return await self._policy_response(
                    request_id, "block", ["STREAMING_UNSUPPORTED"], 501, started
                )

        configured_token = os.getenv(self.config.approval_token_env)
        decision = self.policy.inspect_request(
            body,
            request.headers.get(self.config.approval_header),
            configured_token,
        )
        if decision.decision == "review" and isinstance(body, dict):
            decision = await self._resolve_approval(
                request_id,
                body,
                decision,
                request.headers.get(self.config.approval_header),
                configured_token,
            )
        if decision.decision == "block":
            return await self._policy_response(
                request_id,
                decision.decision,
                decision.reason_codes,
                403,
                started,
                decision.tool_names,
                decision.metadata,
            )
        if decision.decision == "review":
            return await self._policy_response(
                request_id,
                decision.decision,
                decision.reason_codes,
                428,
                started,
                decision.tool_names,
                decision.metadata,
            )

        assert self.session is not None
        try:
            async with self.session.post(
                self.config.upstream_url,
                data=raw_body,
                headers=self._forward_headers(request),
            ) as upstream:
                response_bytes = await upstream.read()
                if len(response_bytes) > self.config.max_body_bytes:
                    self.metrics.observe_error()
                    return await self._policy_response(
                        request_id,
                        "block",
                        ["RESPONSE_TOO_LARGE"],
                        502,
                        started,
                        decision.tool_names,
                    )
                content_type = upstream.headers.get("Content-Type", "application/json")
                try:
                    response_body: Any = json.loads(response_bytes.decode("utf-8"))
                    is_json = True
                except (UnicodeDecodeError, json.JSONDecodeError):
                    response_body = response_bytes.decode("utf-8", errors="replace")
                    is_json = False
                output_decision, safe_body = self.policy.inspect_response(
                    response_body,
                    request.headers.get(self.config.approval_header),
                    configured_token,
                )
                if output_decision.decision == "review" and isinstance(response_body, dict):
                    output_decision = await self._resolve_approval(
                        request_id,
                        response_body,
                        output_decision,
                        request.headers.get(self.config.approval_header),
                        configured_token,
                        response=True,
                    )
                    if output_decision.decision != "review":
                        output_decision, safe_body = self.policy.inspect_response(
                            response_body,
                            request.headers.get(self.config.approval_header),
                            configured_token,
                            approval_granted=True,
                        )
                output_tool_names = output_decision.tool_names or decision.tool_names
                audit_metadata = {**decision.metadata, **output_decision.metadata}
                if output_decision.decision == "review":
                    self._audit(
                        request_id,
                        "review",
                        output_decision.reason_codes,
                        428,
                        started,
                        output_tool_names,
                        upstream.status,
                        metadata=audit_metadata,
                    )
                    return web.json_response(
                        {
                            "error": {
                                "type": "argus_policy_enforced",
                                "message": (
                                    "Human approval is required before the agent can "
                                    "execute this tool"
                                ),
                                "request_id": request_id,
                                "reason_codes": output_decision.reason_codes,
                            }
                        },
                        status=428,
                        headers={
                            "X-Argus-Decision": "review",
                            "X-Request-ID": request_id,
                        },
                    )
                if output_decision.decision == "block":
                    self._audit(
                        request_id,
                        "block",
                        output_decision.reason_codes,
                        502,
                        started,
                        output_tool_names,
                        upstream.status,
                        metadata=audit_metadata,
                    )
                    return web.json_response(
                        {
                            "error": {
                                "type": "argus_output_blocked",
                                "message": "The upstream response was blocked by Argus policy",
                                "request_id": request_id,
                                "reason_codes": output_decision.reason_codes,
                            }
                        },
                        status=502,
                        headers={"X-Argus-Decision": "block", "X-Request-ID": request_id},
                    )
                if output_decision.decision == "redact":
                    self._audit(
                        request_id,
                        "redact",
                        output_decision.reason_codes,
                        upstream.status,
                        started,
                        output_tool_names,
                        upstream.status,
                        output_decision.redaction_count,
                        metadata=audit_metadata,
                    )
                    if is_json:
                        return web.json_response(
                            safe_body,
                            status=upstream.status,
                            headers={"X-Argus-Decision": "redact", "X-Request-ID": request_id},
                        )
                    return web.Response(
                        text=str(safe_body),
                        status=upstream.status,
                        content_type="text/plain",
                        headers={"X-Argus-Decision": "redact", "X-Request-ID": request_id},
                    )
                self._audit(
                    request_id,
                    "allow",
                    [],
                    upstream.status,
                    started,
                    output_tool_names,
                    upstream.status,
                    metadata=audit_metadata,
                )
                return web.Response(
                    body=response_bytes,
                    status=upstream.status,
                    headers={
                        "Content-Type": content_type,
                        "X-Argus-Decision": "allow",
                        "X-Request-ID": request_id,
                    },
                )
        except asyncio.TimeoutError:
            self.metrics.observe_error()
            self._audit(
                request_id, "block", ["UPSTREAM_TIMEOUT"], 504, started, decision.tool_names
            )
            return web.json_response(
                {"error": {"type": "argus_upstream_timeout", "request_id": request_id}},
                status=504,
                headers={"X-Argus-Decision": "block", "X-Request-ID": request_id},
            )
        except aiohttp.ClientError:
            self.metrics.observe_error()
            self._audit(
                request_id, "block", ["UPSTREAM_UNAVAILABLE"], 502, started, decision.tool_names
            )
            return web.json_response(
                {"error": {"type": "argus_upstream_unavailable", "request_id": request_id}},
                status=502,
                headers={"X-Argus-Decision": "block", "X-Request-ID": request_id},
            )

    async def handle_health(self, request: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "service": "argus-runtime-gateway"})

    async def handle_metrics(self, request: web.Request) -> web.Response:
        if self.config.protect_metrics:
            auth_failure = self._client_auth_failure(request)
            if auth_failure is not None:
                status_code, reason_code = auth_failure
                return web.json_response(
                    {"error": {"type": "argus_authentication_required", "reason": reason_code}},
                    status=status_code,
                )
        return web.Response(text=self.metrics.render(), content_type="text/plain; version=0.0.4")


def create_app(config: RuntimeConfig) -> web.Application:
    gateway = RuntimeGateway(config)
    app = web.Application(client_max_size=config.max_body_bytes)
    app["runtime_gateway"] = gateway
    app.router.add_post("/v1/messages", gateway.handle_messages)
    app.router.add_post("/v1/chat/completions", gateway.handle_messages)
    app.router.add_get("/healthz", gateway.handle_health)
    app.router.add_get("/metrics", gateway.handle_metrics)

    async def on_startup(application: web.Application) -> None:
        await application["runtime_gateway"].start()

    async def on_cleanup(application: web.Application) -> None:
        await application["runtime_gateway"].close()

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


__all__ = ["RuntimeGateway", "create_app"]
