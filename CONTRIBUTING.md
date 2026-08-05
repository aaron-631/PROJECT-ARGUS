# Contributing to Argus

## Local setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install -e .
.venv/bin/argus doctor
```

Run the complete local gate before opening a pull request:

```bash
.venv/bin/black --check --target-version py311 src/ tests/ argus.py runtime_gateway.py scripts
.venv/bin/flake8 src/ tests/ argus.py runtime_gateway.py scripts
.venv/bin/mypy src/
.venv/bin/pytest tests/ -q
.venv/bin/python -m src.models.schema_generation --check
.venv/bin/pip check
.venv/bin/pip-audit -r requirements.lock
python scripts/demo.py
```

## Change expectations

- Keep security decisions deterministic and explainable.
- Add or update tests for behavior changes.
- Never commit credentials, private reports, customer data, or raw model
  responses.
- Keep live MCP and provider tests opt-in and read-only where possible.
- Update `README.md` for the short path, `WORKFLOW.md` for decisions and
  trade-offs, and `CHANGELOG.md` for user-visible changes.

Pull requests should explain the threat model, the new trust boundary, the
failure behavior, and the known false-positive or false-negative trade-off.

## Architecture Overview

- **src/core**: The heart of the async orchestrator, evaluation pipeline, registry, and data ingestion logic.
- **src/modules**: Concrete implementations of scanners and attack modules.
- **src/runtime**: The runtime gateway and HTTP proxy interceptors.
- **src/interfaces**: Abstract base classes defining contracts for plugins (Scanners, Attack Modules, Exporters, Judges).
- **src/models**: Pydantic models for type-safe data boundaries (`Finding`, `ScanContext`, `AttackResult`).
- **src/reporting**: Exporters for generating reports (JSON, Markdown, SARIF).

## How to Add a New Rule

Built-in rules live in `src/modules/scanners/`. Adding one touches three places:

1. Add the rule metadata to `_RULES` in `src/modules/scanners/mcp_scanner.py` as
   a `(Severity, title, description, base_score, remediation)` tuple, keyed by a
   new `ARGUS_ST_XYZ` id.
2. Declare what the rule can analyze in `RULE_CAPABILITIES` in
   `src/modules/scanners/rules.py` so it only runs against file types it
   understands (`python_ast`, `structured`, or `pattern`).
3. Implement the detection inside `MCPScanner.scan`, calling the local `add()`
   helper with the rule id, path, evidence, and line number.
4. Add a test under `tests/unit/` covering both a true positive and a case that
   must not fire. False positives erode trust as fast as false negatives.

Run `argus rules --verbose` to confirm the rule is listed.

To add a rule without modifying this repository, ship a scanner plugin instead —
see [docs/plugins.md](docs/plugins.md).

## How to Add Attack Payloads

1. Attack payloads live under `data/attacks/` as JSON files, grouped by attack
   type (`data_extraction/`, `jailbreaks/`, `prompt_injection/`).
2. Register the file in `data/attacks/manifest.json` with its `attack_type`,
   relative `path`, and `sha256`.
3. The manifest hash is verified at load time, so a stale hash fails the run
   rather than silently scanning a modified dataset.

## Code Style

We strictly follow these tools for code quality:
- **black**: Code formatting (we target `py311`).
- **flake8**: Linting for syntax and style errors.
- **mypy**: Static type checking.
All CI checks must pass before a pull request can be merged.

Optionally install the hooks so these run before each commit:

```bash
.venv/bin/pip install pre-commit
.venv/bin/pre-commit install
```

The `argus-scan` hook scans `src/` against `.argus/src-baseline.json`. The
baseline holds three reviewed `subprocess.run` invocations that pass fixed
argument lists to `git` — it fails the commit on new findings, not on those.
Regenerate it only when a finding has been reviewed and accepted:

```bash
.venv/bin/argus scan --target ./src --format json --output ./reports
cp reports/report.json .argus/src-baseline.json
```

## Testing

To run the test suite locally:
```bash
.venv/bin/pytest tests/ -q
```
When adding new features or rules, please include corresponding unit or integration tests in the `tests/` directory. Use `tests/mock_server.py` to simulate LLM responses deterministically.
