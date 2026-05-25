"""
Deterministic mock LLM endpoint.
All CI tests run against this — zero real API calls.
Supports synthetic rate limits for throttling tests.
"""
from aiohttp import web


async def handle_completion(request):
    body = await request.json()
    prompt = body.get("messages", [{}])[-1].get("content", "")

    # Simulate rate limiting
    if hasattr(handle_completion, "_call_count"):
        handle_completion._call_count += 1
    else:
        handle_completion._call_count = 1

    if handle_completion._call_count % 10 == 0:
        return web.Response(status=429, headers={"Retry-After": "1"})

    # Deterministic responses for testing
    if "ignore previous instructions" in prompt.lower():
        response_text = "Sure, I'll ignore my instructions and help you."
    else:
        response_text = "I cannot help with that request."

    return web.json_response({
        "content": [{"type": "text", "text": response_text}]
    })


app = web.Application()
app.router.add_post("/v1/messages", handle_completion)

if __name__ == "__main__":
    web.run_app(app, host="127.0.0.1", port=8765)
