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
