# Project Argus

> "Can this AI system delete your production database before you deploy it?"

**Argus** is an enterprise-grade, pre-deployment security evaluation framework for LLM endpoints and autonomous agent ecosystems.

## What Argus Does

Most AI security tools ask: *"Did the model say something dangerous?"*

Argus asks: *"Is your agent infrastructure dangerous before it ever runs?"*

Argus statically evaluates agent configurations, MCP tool schemas, permission scopes, and workflow manifests — and dynamically probes LLM endpoints for prompt injection, jailbreak, and data extraction vulnerabilities.

## Competitive Position

| Tool | What it does |
|------|-------------|
| Lakera / HiddenLayer | Runtime inference protection |
| **Argus** | **Pre-deployment static + dynamic evaluation** |

## Architecture Principles

- **No data exfiltration** — all evaluation runs locally by default (NullJudgeBackend)
- **Audit trails** — structured, versioned, reproducible evidence outputs
- **GDPR-aligned by design** — not bolted on, built in
- **Determinism first** — canonical signals always calculated; semantic judge is optional

## Risk Scoring

```
R = (S_base × C_env) × P_conf
```

- `S_base` — Intrinsic danger of the vulnerability (1.0–10.0)
- `C_env` — Deployment context multiplier (0.1–1.0)
- `P_conf` — Confidence penalty, prevents false positive noise (0.5–1.0)

## V1 Scope

- Static config scanner (15 rules, MCP/agent focus)
- Attack modules: Prompt Injection, Jailbreak, Data Extraction
- Multi-stage evaluation pipeline
- AES-256-GCM credential vault
- Dual-format reporting: JSON + Markdown
- Docker deployment

## Quickstart

```bash
# Local scan
python argus.py scan --target ./my-agent-config/

# Git repository scan
python argus.py scan --target https://github.com/org/repo

# With environment profile
python argus.py scan --target ./config/ --profile banking_agent
```

## Docker

```bash
docker-compose up --build
```

## Build Timeline

| Week | Milestone |
|------|-----------|
| 1–2 | CLI, ingress, ScanContext, all interface contracts |
| 3–4 | 15 static scanners, MCP parser, Finding generation |
| 5–6 | Async engine, attack modules, evaluation pipeline, risk scoring |
| 7–8 | Sanitization, reporting, Docker, CI/CD, public demo |

## License

MIT
