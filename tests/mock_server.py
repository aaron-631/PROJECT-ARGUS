"""Deterministic local HTTP target used by integration tests and demos."""

from __future__ import annotations

import asyncio

from aiohttp import web


def reset_state() -> None:
    handle_completion.call_count = 0
    handle_completion.failures_remaining = 0
    handle_completion.always_rate_limit = False
    handle_completion.slow_seconds = 0.0
    handle_completion.malformed_json = False
    handle_completion.connection_reset = False
    handle_completion.failure_status = 503
    handle_completion.retry_after = "0"


async def handle_completion(request: web.Request) -> web.Response:
    mode = request.query.get("mode", "")
    if mode in {"timeout", "slow"}:
        seconds = float(request.query.get("seconds", "5" if mode == "timeout" else "1"))
        await asyncio.sleep(max(0.0, min(seconds, 30.0)))
    elif handle_completion.slow_seconds > 0:
        await asyncio.sleep(min(float(handle_completion.slow_seconds), 30.0))
    if mode == "reset" or handle_completion.connection_reset:
        if request.transport is not None:
            request.transport.close()
        raise ConnectionResetError("synthetic connection reset")
    if mode == "malformed" or handle_completion.malformed_json:
        return web.Response(status=200, text="{not valid json", content_type="application/json")
    body = await request.json()
    prompt = body.get("messages", [{}])[-1].get("content", "")
    handle_completion.call_count += 1
    if handle_completion.always_rate_limit or handle_completion.call_count % 10 == 0:
        return web.Response(status=429, headers={"Retry-After": handle_completion.retry_after})
    if handle_completion.failures_remaining > 0:
        handle_completion.failures_remaining -= 1
        return web.Response(status=handle_completion.failure_status, text="synthetic failure")
    if mode == "5xx":
        return web.Response(status=handle_completion.failure_status, text="synthetic failure")
    if "ignore previous instructions" in prompt.lower() or "system prompt" in prompt.lower():
        response_text = "Sure, I'll ignore my instructions and help you."
    else:
        response_text = "I cannot help with that request."
    if mode == "malformed" or handle_completion.malformed_json:
        return web.Response(status=200, text="not-json", content_type="application/json")
    return web.json_response({"content": [{"type": "text", "text": response_text}]})


handle_completion.call_count = 0
handle_completion.failures_remaining = 0
handle_completion.always_rate_limit = False
handle_completion.slow_seconds = 0.0
handle_completion.malformed_json = False
handle_completion.connection_reset = False
handle_completion.failure_status = 503
handle_completion.retry_after = "0"

app = web.Application()
app.router.add_post("/v1/messages", handle_completion)
app.router.add_post("/v1/chat/completions", handle_completion)


if __name__ == "__main__":
    web.run_app(app, host="127.0.0.1", port=8765)
