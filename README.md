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

## Run it

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Scan local files only. No network endpoint is contacted.
.venv/bin/python argus.py scan --target ./config --output ./reports
```

Use a deployment profile when the same finding should carry different business impact:

```bash
.venv/bin/python argus.py scan \
  --target ./config \
  --profile banking_agent \
  --output ./reports
```

Reports are written to `report.json` and `report.md`.

## Test a running endpoint

Terminal 1:

```bash
.venv/bin/python tests/mock_server.py
```

Terminal 2:

```bash
.venv/bin/python argus.py scan \
  --target ./config \
  --endpoint http://127.0.0.1:8765/v1/messages \
  --fail-on CRITICAL \
  --output ./reports/live-test
```

`--fail-on CRITICAL` is used here so the intentionally vulnerable demo endpoint can produce a report without making the demo command fail. Remove it to use the normal `HIGH` deployment gate.

Only send probes to systems you are authorized to evaluate. See [WORKFLOW.md](WORKFLOW.md) for the complete walkthrough, architecture, design decisions, interview explanation, testing recipes, and troubleshooting guide.

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

The gateway listens on `POST /v1/messages` and forwards allowed requests to the configured upstream. See [WORKFLOW.md](WORKFLOW.md) for the policy examples, approval flow, audit format, tradeoffs, and real-time testing walkthrough.

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

Argus V1 checks configuration posture and model behavior before deployment. Argus V2 optionally protects live traffic with a small provider-neutral gateway. Both layers are fail-closed for their defined policies but do not guarantee safety or replace human review. Dynamic testing is opt-in, local attack data is versioned and hashed, and the default judge is air-gapped.

For the reasoning behind the design, read [WORKFLOW.md](WORKFLOW.md).
