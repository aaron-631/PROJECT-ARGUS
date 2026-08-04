# Project Argus

Argus is a local-first, pre-deployment security evaluator for LLM endpoints and autonomous-agent configuration. It combines deterministic static posture analysis with optional, explicitly enabled dynamic probes.

## Capabilities

- 15 deterministic rules for MCP schemas, tool permissions, workflows, environment handling, secrets, dependencies, and network configuration.
- Prompt-injection, jailbreak, and system-prompt/data-extraction attack families using versioned local payloads.
- Bounded concurrency, token-bucket rate limiting, timeouts, retry/backoff, and `429` handling.
- Canonical evaluation always runs. A `NullJudgeBackend` is the default; mock and provider-neutral HTTP judges are optional.
- Pydantic-validated findings, attack results, configurations, and reports. Pydantic is the single source of truth; `src/models/schema_generation.py` generates the committed JSON Schema artifacts.
- Structured JSON, YAML, and TOML parsing with explicit per-rule capability contracts. Python rules use ASTs; structured rules use key paths; plain-text rules alone use patterns.
- AES-256-GCM vaulting for sensitive artifacts, versioned envelopes, random nonces, key identifiers, atomic writes, and previous-key rotation support.
- Reproducible JSON and actionable Markdown reports suitable for local review or CI artifacts.

Argus V1 is a pre-deployment evaluator. It is not a runtime gateway, an IAM system, a dashboard, a multi-tenant service, or an autonomous red-team agent. Dynamic probes are opt-in and should only target systems you are authorized to evaluate.

## Quickstart

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Static local scan; no external endpoint is contacted.
.venv/bin/python argus.py scan --target ./my-agent-config --output ./reports

# Apply an environment profile.
.venv/bin/python argus.py scan --target ./config --profile banking_agent

# Increase diagnostic logging while developing a rule or integration.
.venv/bin/python argus.py scan --target ./config --verbose
```

Reports are written as `report.json` and `report.md` by default. A scan exits with status `10` when it meets the configured severity threshold (`HIGH` by default), `0` when it passes, and `1` for an input or execution error.

## Dynamic evaluation

Dynamic network execution must be explicit:

```bash
.venv/bin/python argus.py scan \
  --target ./my-agent-config \
  --endpoint http://127.0.0.1:8765/v1/messages
```

The endpoint adapter accepts common JSON response shapes. CI can use the deterministic local mock server:

```bash
.venv/bin/python tests/mock_server.py
```

No cloud account, GPU, hosted model, or external judge is required for the default scan or test suite.

## Docker

With a host Docker daemon available, the local mock endpoint and Argus scan can be started together:

```bash
docker compose up --build
```

The Compose file uses only the repository image, local configuration, and local report/vault directories.

## Configuration and profiles

`config/default_config.yaml` controls engine limits, report formats, the judge backend, and vaulting. Profiles in `config/profiles/` set deployment context through `c_env` (for example, `banking_agent: 1.0` and `public_faq: 0.1`).

`c_env` is an explicit profile input, not an inferred claim about the target. The built-in contexts are `production`, `human_in_loop`, `public`, and `sandbox`; custom profiles may use `custom` with a bounded multiplier.

The risk formula is:

```text
R = (S_base * C_env) * P_conf
```

Scores are clamped to documented bounds, and confidence never claims absolute certainty. Reports identify `canonical_only` versus `canonical+semantic` methodology.

## Security and privacy model

The default judge is air-gapped (`NullJudgeBackend`). Raw target responses are not placed in ordinary reports. Untrusted content is normalized, secret patterns are redacted, control and invisible Unicode characters are removed, and judge delimiters are escaped. The optional HTTP judge receives the target output as data in a separate system/user-message boundary, has no tools, requests a strict JSON schema, and rejects malformed or extra-field responses.

Generate a vault key with:

```bash
PYTHONPATH=. .venv/bin/python -c 'from src.utils.crypto import generate_vault_key; print(generate_vault_key())'
```

Set it as `ARGUS_VAULT_KEY` outside source control. To rotate, configure the new key as current and the old key in `Vault(previous_keys={old_key_id: old_key})`, then call `rotate`; the old key is used only for decryption. Missing keys, unknown key IDs, tampering, and unsafe vault filenames fail closed.

Attack payloads are local and cannot change silently: `data/attacks/manifest.json` records the dataset version and SHA-256 for every payload file. Loaders reject version mismatches, duplicate IDs, malformed files, and hash drift. The mock endpoint can simulate `429`, `5xx`, slow/timeout responses, malformed JSON, and connection resets through query modes or its resettable test state.

The committed JSON Schemas are generated artifacts, never a second hand-maintained model definition:

```bash
PYTHONPATH=. .venv/bin/python -m src.models.schema_generation
PYTHONPATH=. .venv/bin/python -m src.models.schema_generation --check
```

Local ingestion rejects oversized, binary, non-UTF-8, and path-escaping inputs. Git ingestion is shallow and disables repository hooks. Only repositories you are authorized to inspect should be supplied.

## Development

```bash
.venv/bin/black --check src/ tests/ argus.py
.venv/bin/flake8 src/ tests/ argus.py --max-line-length=100
PYTHONPATH=. .venv/bin/python -m mypy src/
PYTHONPATH=. .venv/bin/python -m src.models.schema_generation --check
PYTHONPATH=. .venv/bin/python -m pytest -q
```

The GitHub Actions workflow runs formatting, linting, type checking, unit tests, schema validation, and local integration checks. Reports belong in local `reports/` or CI artifacts; they are intentionally not uploaded by Argus.

## License

MIT
