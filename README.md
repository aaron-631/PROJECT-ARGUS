# Project Argus

Argus is a local-first security toolkit for AI agents, MCP servers, skills, and
LLM deployments. It has two gates:

```text
agent/config/skills ──> static + live checks ──> report + CI decision
agent traffic ────────> runtime gateway ───────> allow / block / redact / audit
```

It is useful for release reviews and real authorized security checks. It is not
an IAM system, sandbox, SIEM, or universal guarantee of safety.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python argus.py audit --target ./config --output ./reports/first-run
```

Open `reports/first-run/report.md`. `PASS` means no configured rule crossed the
gate; `BLOCK` means review is required; `ERROR` means the check did not finish.

For the complete proof-of-concept, use [POC.md](POC.md). For the architecture,
code walkthrough, decisions, tradeoffs, interview preparation, and limits, use
[WORKFLOW.md](WORKFLOW.md).

## Choose the right command

| Goal | Command | Network/process behavior |
| --- | --- | --- |
| Review a repository, config, MCP definitions, or skills | `argus.py audit --target PATH` | Static; launches nothing |
| Test an authorized live LLM endpoint | `argus.py audit --target PATH --endpoint URL ...` | Bounded behavior probes |
| Inspect a live MCP server | `argus.py mcp-probe --transport ... --confirm-live` | `initialize` + paginated `tools/list`; zero tool calls |
| Protect deployed model traffic | `docker-compose.runtime.yml` | Runtime allow/block/redact gateway |

Detailed guides: [static and dynamic testing](WORKFLOW.md#6-real-time-dynamic-testing),
[live MCP discovery](WORKFLOW.md#live-read-only-mcp-discovery),
[OpenClaw](WORKFLOW.md#66-openclaw-skills-and-mcp-workflow), and
[runtime enforcement](WORKFLOW.md#67-runtime-monitoring-and-blocking-gateway-argus-v2).

## Scan a real agent repository

```bash
.venv/bin/python argus.py audit \
  --target /path/to/agent-repository \
  --output ./reports/agent
```

Argus checks source, JSON/YAML/TOML/Python, secrets, shell execution, MCP
servers, tool schemas, permissions, egress, TLS, unpinned packages, and skills.
Use a profile when business context changes the risk:

```bash
.venv/bin/python argus.py audit \
  --target /path/to/agent-repository \
  --profile banking_agent \
  --output ./reports/banking-agent
```

Reports are `report.json` and `report.md`. `audit` and `scan` are aliases.

## Test a live LLM endpoint

Live testing is opt-in. Credentials come from environment variables and are not
written to reports:

```bash
export OPENAI_API_KEY='...'
.venv/bin/python argus.py audit \
  --target /path/to/agent-repository \
  --endpoint https://api.openai.com/v1/chat/completions \
  --provider openai \
  --model gpt-4o-mini \
  --output ./reports/openai
```

Supported adapters are `generic`, `openai`, `anthropic`, and `ollama`. Only test
systems you are authorized to evaluate; a failed live transport is an error,
not a passing result.

## Inspect a live MCP server

For a real, reviewed stdio server:

```bash
.venv/bin/python argus.py mcp-probe \
  --transport stdio \
  --command npx \
  --arg=-y \
  --arg=@modelcontextprotocol/server-filesystem@2026.7.10 \
  --arg=/approved/directory \
  --timeout 120 \
  --confirm-live \
  --output ./reports/mcp-live
```

For an authorized Streamable HTTP server:

```bash
export MCP_AUTHORIZATION='Bearer read-only-probe-token'
.venv/bin/python argus.py mcp-probe \
  --transport streamable-http \
  --endpoint https://mcp.company.example/mcp \
  --header-env Authorization=MCP_AUTHORIZATION \
  --confirm-live \
  --output ./reports/mcp-http
```

The probe reads the server's current tool inventory, follows pagination, and
uses no `tools/call`. It supports stdio and Streamable HTTP, not legacy
HTTP+SSE or custom transports. A normal static audit never launches a server;
for dynamic configurations, audit first and explicitly probe each approved
server. `--confirm-live` is authorization, not a sandbox: use a reviewed
command or an OS/container sandbox for untrusted packages.

See the [dynamic MCP decision guide](WORKFLOW.md#live-read-only-mcp-discovery)
and the [recorded real-server report](WORKFLOW.md#661-real-world-verification-run).

## OpenClaw, Claude Code, Codex CLI, and Gemini CLI

Point Argus at the configuration and skill directories chosen by the operator:

```bash
.venv/bin/python argus.py audit --target "$HOME/.openclaw" --output ./reports/openclaw
.venv/bin/python argus.py audit --target "$HOME/.claude/settings.json" --output ./reports/claude
.venv/bin/python argus.py audit --target "$HOME/.codex/config.toml" --output ./reports/codex
.venv/bin/python argus.py audit --target "$HOME/.gemini/settings.json" --output ./reports/gemini
```

Paths vary by version and operating system. Confirm the active config first;
never scan credential databases or session history. See the [OpenClaw and CLI
workflow](WORKFLOW.md#66-openclaw-skills-and-mcp-workflow).

## Runtime gateway

The V2 gateway protects a JSON HTTP model service. The repository POC uses the
mock upstream; another machine can use `docker-compose.runtime.yml` with an
upstream URL in `.env.runtime`:

```bash
cp .env.runtime.example .env.runtime
# Set ARGUS_RUNTIME_UPSTREAM_URL and the required secrets.
docker compose --env-file .env.runtime -f docker-compose.runtime.yml up --build
```

It can require client authentication, block prompt/tool policies, require
approval, redact sensitive output, expose metrics, and write hash-chained audit
events. It expects buffered JSON HTTP (`stream: false`) and is not, by itself,
the complete public-internet TLS/identity boundary. See the [deployment and
runtime guide](WORKFLOW.md#9-docker-and-deployment-workflow).

## What is proven

The documented real run inspected installed Claude Code, Codex CLI, and Gemini
CLI configuration files and launched the pinned official filesystem MCP server:
14 tools, one page, zero tool calls, and two HIGH findings. The project also has
unit coverage, CI configuration, Docker/Compose smoke workflows, report-schema
checks, and runtime gateway tests.

The recorded run did not call a live OpenAI/Anthropic/Gemini/Ollama model or a
live authenticated Streamable HTTP server. Windows, macOS, ARM, enterprise
proxies, and unusual MCP implementations require a short local smoke test.
These boundaries are documented in [WORKFLOW.md](WORKFLOW.md#what-this-evidence-provesand-what-it-does-not).

## Development checks

```bash
.venv/bin/black --check --target-version py311 src/ tests/ argus.py runtime_gateway.py
.venv/bin/flake8 src/ tests/ argus.py runtime_gateway.py
.venv/bin/mypy src/
.venv/bin/pytest -q
PYTHONPATH=. .venv/bin/python -m src.models.schema_generation --check
```

The project requires Python 3.11+; Docker is the most portable runtime path.
