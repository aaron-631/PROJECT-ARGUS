# Project Argus

Argus is a local-first security check for AI agents before deployment. It scans an agent's files and, when explicitly asked, sends safe test prompts to an authorized AI endpoint.

Think of it as a pre-deployment security gate:

```text
agent files ──> static checks ──┐
                                ├──> JSON/Markdown report ──> CI decision
running AI endpoint ─> attacks ─┘
```

Argus is not a runtime firewall, IAM system, dashboard, or production monitoring service.

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

## CI and development checks

```bash
.venv/bin/black --check --target-version py311 src/ tests/ argus.py
.venv/bin/flake8 src/ tests/ argus.py
PYTHONPATH=. .venv/bin/mypy src/
PYTHONPATH=. .venv/bin/pytest -q
PYTHONPATH=. .venv/bin/python -m src.models.schema_generation --check
```

The GitHub Actions workflow runs these checks plus a local mock integration scan and Docker validation.

## Scope

Argus V1 checks configuration posture and model behavior before deployment. It does not guarantee safety, replace human review, or protect a live system after deployment. Dynamic testing is opt-in, local attack data is versioned and hashed, and the default judge is air-gapped.

For the reasoning behind the design, read [WORKFLOW.md](WORKFLOW.md).
