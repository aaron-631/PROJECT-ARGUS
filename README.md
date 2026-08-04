# Project Argus

Argus is a local-first security toolkit for AI agents. It has two layers: a pre-deployment scanner for repositories and an optional runtime gateway that enforces request/response policies while an agent is live.

Think of it as two gates: a pre-deployment release gate and an optional live-traffic policy gate:

```text
agent files ──> static checks ──┐
                                ├──> JSON/Markdown report ──> CI decision
running AI endpoint ─> attacks ─┘
agent traffic ─> runtime gateway ─> model endpoint
```

The scanner and gateway are separate on purpose: the scanner decides whether a release is acceptable; the gateway blocks or redacts traffic for a running placement assistant. Argus is not an IAM system, dashboard, SIEM, sandbox, or guarantee of safety.

## First run: choose one path

If you are new to Argus, start with a local configuration audit. It is safe,
fast, and makes no network call:

```bash
.venv/bin/python argus.py audit --target ./config --output ./reports/first-run
```

Open `reports/first-run/report.md`. Then choose the next level:

1. `--target /path/to/agent` checks source, configuration, MCP declarations,
   tools, and skills.
2. `--endpoint ...` adds authorized live model probes through `--provider`.
3. `docker-compose.runtime.yml` puts the runtime gateway in front of a real
   JSON HTTP model service.

The decision is simple: `PASS` means no defined rule crossed the configured
threshold, `BLOCK` means findings need review, and `ERROR` means the test could
not complete. A PASS is not a universal security guarantee.

## Run it against a real agent repository

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Audit any local agent/LLM repository. This contacts no model endpoint.
.venv/bin/python argus.py audit \
  --target /path/to/your-agent-repository \
  --output ./reports/agent
```

`audit` and `scan` are aliases. Argus reads source, dependency/configuration
files, MCP server definitions, and tool schemas. It reports hardcoded secrets,
unsafe code execution, wildcard filesystem or administrative permissions,
unrestricted network egress, unapproved high-impact tools, unpinned MCP
servers, unsafe TLS settings, and model-behavior results when a live endpoint
is explicitly supplied. It does not execute the target repository.

Use a deployment profile when the same finding should carry different business impact:

```bash
.venv/bin/python argus.py audit \
  --target /path/to/your-agent-repository \
  --profile banking_agent \
  --output ./reports/banking-agent
```

Reports are written to `report.json` and `report.md`.

## Test an authorized live model

Live testing is opt-in. Use the provider adapter that matches the endpoint;
the API key is read from an environment variable and is never written to the
report. OpenAI-compatible gateways use the `openai` adapter too.

```bash
export OPENAI_API_KEY='...'
.venv/bin/python argus.py audit \
  --target /path/to/your-agent-repository \
  --endpoint https://api.openai.com/v1/chat/completions \
  --provider openai \
  --model gpt-4o-mini \
  --output ./reports/openai
```

Anthropic and local Ollama examples:

```bash
export ANTHROPIC_API_KEY='...'
.venv/bin/python argus.py audit --target ./my-agent \
  --endpoint https://api.anthropic.com/v1/messages \
  --provider anthropic --model claude-3-5-haiku-20241022

.venv/bin/python argus.py audit --target ./my-agent \
  --endpoint http://127.0.0.1:11434/api/chat \
  --provider ollama --model llama3.1
```

For an internal API, use `--provider generic`. It sends the same small
contract used by the local fixture: `{"messages":[{"role":"user","content":"..."}]}`.
For an authenticated gateway, keep the secret in an environment variable:

```bash
export ARGUS_GATEWAY_TOKEN='...'
.venv/bin/python argus.py audit --target ./my-agent \
  --endpoint https://llm.company.example/v1/messages \
  --provider generic --api-key-env ARGUS_GATEWAY_TOKEN \
  --auth-header X-API-Key
```

Only test endpoints and repositories you are authorized to evaluate. A failed
live transport is an error, not a passing security result.

## Test the repository's deterministic endpoint

Terminal 1:

```bash
.venv/bin/python tests/mock_server.py
```

Terminal 2:

```bash
.venv/bin/python argus.py audit \
  --target ./config \
  --endpoint http://127.0.0.1:8765/v1/messages \
  --fail-on CRITICAL \
  --output ./reports/live-test
```

`--fail-on CRITICAL` is used here so the intentionally vulnerable demo endpoint can produce a report without making the demo command fail. Remove it to use the normal `HIGH` deployment gate.

The fixture is a CI/test oracle, not a production model. Real company testing
uses the provider commands above.

## What Argus checks in MCP configurations

Point `--target` at the repository containing `mcp.json`, `claude_desktop_config.json`,
`mcpServers`, tool declarations, or server code. Argus understands structured
JSON/YAML/TOML values and common MCP layouts, including examples such as:

```json
{
  "mcpServers": {
    "placements": {
      "command": "npx",
      "args": ["@company/placement-mcp"],
      "env": {"*": "inherit"}
    }
  },
  "tools": [{
    "name": "send_email",
    "description": "Send an email to any address",
    "permissions": ["*"]
  }]
}
```

This produces evidence for broad environment access, wildcard/admin
permissions, missing approval on high-impact tools, unpinned package runners,
and other applicable findings. A static scan cannot discover tools hidden
behind a running server; run it against the server repository and use the
runtime gateway or an authorized live integration test for deployed traffic.

## Audit an OpenClaw installation

OpenClaw skills are instruction files that can cause an agent to use powerful
tools. Audit the config and each skill root after installing or updating skills:

```bash
.venv/bin/python argus.py audit --target "$HOME/.openclaw" --output ./reports/openclaw
.venv/bin/python argus.py audit \
  --target "$HOME/.openclaw/workspace/skills" \
  --output ./reports/openclaw-workspace-skills
.venv/bin/python argus.py audit \
  --target "$HOME/.agents/skills" \
  --output ./reports/openclaw-agent-skills
```

Argus understands OpenClaw JSON5-style config, `mcp.servers`, `mcpServers`,
`SKILL.md` files, skill environment/API-key entries, tool profiles, elevated
execution, and common install commands. It flags authority-override
instructions, arbitrary shell commands, secret harvesting, data exfiltration,
unpinned downloads, and skills with no verifiable provenance metadata. A
missing provenance record means “review required”; it is not by itself proof
that a first-party skill is malicious.

For live MCP connectivity, use OpenClaw's own authorized diagnostic first, then
use Argus for repository evidence:

```bash
openclaw mcp doctor --probe
openclaw mcp list --json > /tmp/openclaw-mcp.json
.venv/bin/python argus.py audit --target /tmp/openclaw-mcp.json
```

Argus does not launch skill code or MCP servers during a static audit. This is
intentional: the scan must be safe to run on an untrusted installation. Use
the V2 runtime gateway for deployed request/tool enforcement.

Only send probes to systems you are authorized to evaluate. See [WORKFLOW.md](WORKFLOW.md) for the complete walkthrough, architecture, design decisions, interview explanation, testing recipes, and troubleshooting guide.

## Audit Claude Code, Codex CLI, or Gemini CLI configuration

Argus does not attach to a running CLI or read conversation history. Point it
at the configuration and MCP files that the operator chooses to review:

```bash
.venv/bin/python argus.py audit --target "$HOME/.claude/settings.json" \
  --output ./reports/claude-code
.venv/bin/python argus.py audit --target "$HOME/.codex/config.toml" \
  --output ./reports/codex
.venv/bin/python argus.py audit --target "$HOME/.gemini/settings.json" \
  --output ./reports/gemini
```

Also scan project-level files such as `.claude/settings.json` or
`.gemini/settings.json`, and any MCP file the CLI actually loads. Paths vary
by installation and operating system, so confirm the active configuration in
that tool first. Never point Argus at credential databases, session history,
or private key stores just to make the scan broader. Gemini's documented
configuration and MCP locations are described in its [configuration guide](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md)
and [MCP guide](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md).
The real installation and official MCP-server verification results are recorded
in [WORKFLOW.md](WORKFLOW.md#661-real-world-verification-run).

## Docker

With Docker and Compose installed:

```bash
docker compose up --build --abort-on-container-exit --exit-code-from argus
```

This starts the local mock endpoint, waits for it to become healthy, runs Argus, and writes reports to `./reports`.

## Runtime gateway (V2)

The practical campus-placement demo puts the agent behind a policy gateway. It blocks prompt injection and dangerous tools, requires approval for record updates/offers/email, restricts external email domains, redacts student contact data, and records sanitized audit events.

```bash
docker compose up --build -d mock runtime
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/metrics
docker compose down
```

The gateway listens on `POST /v1/messages` and `POST /v1/chat/completions`, then forwards allowed JSON traffic to the configured upstream. See [WORKFLOW.md](WORKFLOW.md) for the policy examples, approval flow, audit format, tradeoffs, provider compatibility, and real-time testing walkthrough.

Common `Authorization`, `x-api-key`, and provider-version headers are forwarded by default; the Argus approval header is never forwarded. Custom upstream header allowlists can be set through `ARGUS_RUNTIME_FORWARD_HEADERS`.

To run V2 against your own model service on another computer:

```bash
cp .env.runtime.example .env.runtime
# Edit ARGUS_RUNTIME_UPSTREAM_URL and the secret placeholders.
docker compose --env-file .env.runtime -f docker-compose.runtime.yml up --build
```

The upstream URL must be reachable from the gateway container. For a model running on the host, use `http://host.docker.internal:<port>/...`; for Kubernetes or another machine, use its service/DNS name or reachable HTTPS URL. Send non-streaming JSON (`"stream": false`); the gateway buffers responses so it can inspect them safely.

The mock service is only for deterministic demos and CI. For TLS, authentication, approval, audit shipping, and replicas, use the production profile described in [WORKFLOW.md](WORKFLOW.md).

Production baseline:

```bash
cp .env.production.example .env.production
# Configure DNS, upstream, client token, approval service, and audit collector.
docker compose --env-file .env.production \
  -f docker-compose.production.yml up --build --scale runtime=2
```

Only Caddy is exposed publicly; clients must send `X-Argus-Client-Token`. The approval service and audit collector are external enterprise integrations, intentionally not auto-approved or stored in the demo repository.

## CI and development checks

```bash
.venv/bin/black --check --target-version py311 src/ tests/ argus.py runtime_gateway.py
.venv/bin/flake8 src/ tests/ argus.py runtime_gateway.py
PYTHONPATH=. .venv/bin/mypy src/
PYTHONPATH=. .venv/bin/pytest -q
PYTHONPATH=. .venv/bin/python -m src.models.schema_generation --check
```

The GitHub Actions workflow runs these checks plus a local mock integration scan and Docker validation.

## Scope

Argus V1 checks repository/configuration posture—including MCP servers, tools,
and skill instruction files—and optionally tests model behavior before
deployment. Argus V2 optionally protects live traffic with a small
provider-neutral gateway. Both layers are fail-closed for their defined
policies but do not guarantee safety or replace human review. V2 expects a
reachable JSON HTTP upstream, is not a public-internet TLS/authentication
boundary by itself, and does not support token-by-token streaming by default.

For the reasoning behind the design, read [WORKFLOW.md](WORKFLOW.md).
