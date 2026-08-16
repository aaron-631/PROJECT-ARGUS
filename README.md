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

For a 5-minute practical introduction, see the [Quick-Start Guide](docs/quickstart.md).

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install -e .
.venv/bin/argus doctor
.venv/bin/argus audit --target ./config --output ./reports/first-run
.venv/bin/python examples/indirect-injection/run_demo.py
```

Open `reports/first-run/report.md`. `PASS` means no configured rule crossed the
gate; `BLOCK` means review is required; `ERROR` means the check did not finish.
The lock file gives repeatable installs; use `requirements.txt` when you want
the flexible lower-bound dependency path.

For the complete proof-of-concept, use [POC.md](POC.md). For the architecture,
code walkthrough, decisions, tradeoffs, interview preparation, and limits, use
[WORKFLOW.md](WORKFLOW.md). The compact architecture diagram is in
[docs/architecture.md](docs/architecture.md).
The formal OWASP LLM/Agentic, MITRE ATLAS, and CWE matrix is in
[docs/coverage.md](docs/coverage.md); reproducible safe/vulnerable/RAG evidence
is in [evidence/benchmark/README.md](evidence/benchmark/README.md).

The fastest safe portfolio demo after installation is:

```bash
python scripts/demo.py
```

It writes evidence under `reports/demo/`. Add `--live-mcp` only when you have
explicitly authorized the pinned MCP demo server.

## Choose the right command

| Goal | Command | Network/process behavior |
| --- | --- | --- |
| Check the local setup | `argus doctor` | Read-only checks; does not contact a model or MCP server |
| Review a repository, config, MCP definitions, or skills | `argus audit --target PATH` | Static; launches nothing |
| Gate only new regressions | `argus audit --target PATH --baseline report.json` | Compares against an accepted report |
| Test an authorized live LLM endpoint | `argus audit --target PATH --endpoint URL ...` | Bounded behavior probes |
| Inspect a live MCP server | `argus mcp-probe --transport ... --confirm-live` | `initialize` + paginated `tools/list`; zero tool calls |
| Protect deployed model traffic | `docker-compose.runtime.yml` | Runtime allow/block/redact gateway |
| List available security rules | `argus rules --compliance` | View active rules plus OWASP/ATLAS/CWE mappings |

Detailed guides: [static and dynamic testing](WORKFLOW.md#6-real-time-dynamic-testing),
[live MCP discovery](WORKFLOW.md#live-read-only-mcp-discovery),
[OpenClaw](WORKFLOW.md#66-openclaw-skills-and-mcp-workflow), and
[runtime enforcement](WORKFLOW.md#67-runtime-monitoring-and-blocking-gateway-argus-v2).

## Scan a real agent repository

```bash
.venv/bin/argus audit \
  --target /path/to/agent-repository \
  --output ./reports/agent
```

Argus checks source, JSON/YAML/TOML/Python, secrets, shell execution, MCP
servers, tool schemas, permissions, egress, TLS, unpinned packages, skills,
and explicit RAG trust-boundary/output-validation settings. Its dynamic modules
also include indirect prompt-injection probes that carry retrieved context and
detect dangerous tool proposals.
Claude-style `permissions.allow` entries are interpreted too: bounded commands
can pass, while wildcard high-impact shell grants are reported.

**Language scope.** Configuration rules (JSON/YAML/TOML) and text/secret rules
are language-agnostic. Code-execution rules (`ARGUS_ST_003`, `ARGUS_ST_007`) use
Python's `ast` module and therefore apply to `.py` files only: a shell injection
written in TypeScript or Go is **not** detected today, though a hardcoded
credential in those files still is. Treat Argus as a config-and-Python gate, not
a general-purpose SAST tool for every language.

Use a profile when business context changes the risk:

```bash
.venv/bin/argus audit \
  --target /path/to/agent-repository \
  --profile banking_agent \
  --output ./reports/banking-agent
```

Reports are `report.json`, `report.md`, and `report.sarif`. SARIF can be uploaded
to GitHub Code Scanning. `audit` and `scan` are aliases. The
editable install exposes `argus` and `argus-runtime`; the `python argus.py`
form remains available when running directly from a clone.

For an existing backlog, `--baseline report.json` keeps all current findings in
the report but fails only on new findings, severity increases, or newly unsafe
dynamic probes. Resolved findings are recorded as progress. The full decision
logic is in [WORKFLOW.md](WORKFLOW.md#baseline-diff-mode). Use the `--format`
flag to control which reports are generated; it is repeatable and accepts
`json`, `markdown`, or `sarif` (e.g. `--format json --format sarif`).

Argus never re-ingests its own generated reports, so scanning a directory twice
returns the same result instead of compounding findings; skipped files are listed
in `summary["skipped_files"]`. Use `--exclude` (repeatable, accepts a directory
name or glob) to leave out vendored or generated trees:

```bash
.venv/bin/argus audit --target . --exclude vendor --exclude '*.min.js'
```

## Test a live LLM endpoint

Live testing is opt-in. Credentials come from environment variables and are not
written to reports:

```bash
export OPENAI_API_KEY='...'
.venv/bin/argus audit \
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
.venv/bin/argus mcp-probe \
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
.venv/bin/argus mcp-probe \
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
.venv/bin/argus audit --target "$HOME/.openclaw" --output ./reports/openclaw
.venv/bin/argus audit --target "$HOME/.claude/settings.json" --output ./reports/claude
.venv/bin/argus audit --target "$HOME/.codex/config.toml" --output ./reports/codex
.venv/bin/argus audit --target "$HOME/.gemini/settings.json" --output ./reports/gemini
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

It can require client authentication, normalize and block prompt-injection
variants, enforce an explicit tool allow-list, require approval, redact
sensitive output, expose metrics, and write hash-chained audit events. It
supports `/v1/messages`, `/v1/chat/completions`, and `/v1/responses`, but still
expects buffered JSON HTTP (`stream: false`) and is not, by itself, the complete
public-internet TLS/identity boundary.

Tool execution is deny-by-default. Configure reviewed read-only tools under
`policy.allowed_tools`; write, communication, and other high-impact tools must
be listed under `approval_tools` or `block_tools`. Unknown tool names are
blocked before they reach the upstream model or agent.

`redact_personal_data` currently covers email addresses and Indian mobile
numbers; other national phone formats, postal addresses, and government IDs are
not matched, so do not rely on it as a complete DLP control. Secret-shaped
output (API keys, bearer tokens, JWTs, PEM blocks) is redacted independently of
that setting. See the [deployment and runtime
guide](WORKFLOW.md#9-docker-and-deployment-workflow).

## Proof of concept and evidence

Run the short POC from the repository root:

```bash
mkdir -p reports/poc
.venv/bin/argus audit --target ./config --output ./reports/poc/static
```

Then run the real MCP command from [Inspect a live MCP server](#inspect-a-live-mcp-server)
with `--output ./reports/poc/real-mcp`. The complete runtime, mock-LLM, and
acceptance procedure is in [POC.md](POC.md).

| Evidence | Recorded result |
| --- | --- |
| Installable CLI | Editable package install succeeded; `argus` and `argus-runtime` help commands work |
| Automated quality gate | Full pytest, Black, Flake8, mypy, and schema checks run in CI |
| SARIF export | GitHub-compatible `report.sarif` with stable rule IDs, locations, severity, and fingerprints |
| Current deployment smoke | Claude global/local settings `BLOCK`; Antigravity, Codex, and Gemini general config pass; empty Gemini MCP registry `ERROR` |
| Real MCP server | Official pinned filesystem server: 14 tools, 1 page, 0 tool calls, 2 HIGH findings, `BLOCK` |
| Baseline gate | Existing findings remain visible while new or escalated risk returns exit code `10` |
| Evidence bundle | [Sanitized recorded MCP result](evidence/real-mcp/README.md) with provenance and hashes |
| Real local CLI verification | [Codex, Claude Code, Gemini CLI, and Antigravity settings](evidence/real-cli/README.md) with static and bounded live results |
| Compatibility and supply chain | Cross-platform CI matrix, dependency audit/SBOM, and Docker image advisory scan |
| Performance smoke run | Safe benchmark: 2 files in 0.028s; real MCP discovery: 14 tools in 0.561s with cached `npx --offline`; first `npx` startup was 70.628s on the recorded host |
| Runtime POC | The repository CI/Compose workflow is configured to verify health, `403` prompt blocking, forwarding, metrics, and sanitized audit events |

The real MCP evidence is documented in [WORKFLOW.md](WORKFLOW.md#661-real-world-verification-run).
The reports to retain as proof are `report.md`, `report.json`, and `report.sarif`, plus
`runtime-audit/events.jsonl`. Record the OS, Python/Node versions, package
versions, command, timestamp, and whether each endpoint was mock or real.

The CI workflow already uploads `reports/ci/report.sarif` to GitHub Code
Scanning on pushes and same-repository pull requests. If you add the step to a
different workflow, use the same path:

```yaml
- uses: github/codeql-action/upload-sarif@988661ebb5e81487b3fb31b2185d2856c0a10679 # v4
  if: always()
  with:
    sarif_file: reports/ci/report.sarif
```

<details>
<summary>Captured real Argus run — 2026-08-16</summary>

Environment: Linux/WSL2 workspace, Python 3.14.4, Node.js v24.15.0, npm 11.16.0.
The source commit for this recorded run is stored in the linked evidence record;
rerun the command before presenting a newer release as current evidence.

```text
$ .venv/bin/argus mcp-probe \
    --transport stdio --command npx --arg=--offline --arg=-y \
    --arg=@modelcontextprotocol/server-filesystem@2026.7.10 \
    --arg=/tmp/argus-real-mcp-root --server-name official-filesystem \
    --timeout 120 --confirm-live --output /tmp/argus-real-demo/cli-official-mcp-release

[Argus] Decision: BLOCK
[Argus] MCP transport: stdio; tools discovered: 14
[Argus] Tool calls: 0 (read-only discovery)
[Argus] Performance: 0.561s
[Argus] Report written: /tmp/argus-real-demo/cli-official-mcp-release/report.json
[Argus] Report written: /tmp/argus-real-demo/cli-official-mcp-release/report.md
[Argus] Report written: /tmp/argus-real-demo/cli-official-mcp-release/report.sarif
shell_status:10
```

`10` is Argus's expected “findings crossed the gate” exit code—not a crash.
The generated report contained:

```text
Decision: BLOCK (fail on HIGH)
Findings: 2
HIGH ARGUS_ST_002 — Missing input sanitization schema
HIGH ARGUS_ST_017 — High-impact MCP tool without approval
MCP live probe — 14 tools, 1 page, 0 tool calls
Server — secure-filesystem-server 0.2.0
```

The finding evidence is actionable: add stronger input constraints to
`read_file` and require approval before exposing `write_file`. This is a live
MCP inventory and deterministic report; it is not a claim that every tool
implementation is safe.

</details>

The cached run used `npx --offline`; on the same host the first online `npx`
startup took 70.628 seconds. New machines should omit `--offline` and retain
the 120-second timeout for the first package download.

This evidence does not claim a live commercial LLM test, live authenticated
Streamable HTTP test, every operating system, or every MCP transport. Those
must be run in the target environment before production approval.

## Scope boundary

Argus is a release gate and runtime policy component, not a universal security
certification. It supports Python 3.11+, Docker, real authorized stdio MCP
servers, Streamable HTTP discovery, and provider-specific JSON HTTP model
adapters. Legacy HTTP+SSE, custom MCP transports, live commercial LLM evidence,
and every OS/proxy/server implementation require a target-environment smoke
test. See the [full evidence boundary](WORKFLOW.md#what-this-evidence-provesand-what-it-does-not).

## Library API

Argus can be imported and executed programmatically in your own Python applications. For documentation on configuration, scanning, and custom results, see the [Library API Documentation](docs/library_api.md).

## Plugins

Argus is built with an extensible registry. You can create custom scanners, attack modules, and report formats. See the [Plugin Development Guide](docs/plugins.md) to learn how to add custom functionality.

## Development checks

```bash
.venv/bin/black --check --target-version py311 src/ tests/ argus.py runtime_gateway.py
.venv/bin/flake8 src/ tests/ argus.py runtime_gateway.py
.venv/bin/mypy src/
.venv/bin/pytest -q
PYTHONPATH=. .venv/bin/python -m src.models.schema_generation --check
```

The project requires Python 3.11+; Docker is the most portable runtime path.

Repository policy and maintenance details: [LICENSE](LICENSE),
[SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), and
[CHANGELOG.md](CHANGELOG.md).
