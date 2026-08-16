# Reproducible benchmark evidence

This evidence pack is intentionally small: a clean fixture, a vulnerable
fixture, and the isolated indirect-injection proof. It is designed to be
re-run on another machine after cloning the repository.

## Commands

From the repository root:

```bash
.venv/bin/python -m pytest -q
.venv/bin/argus audit --target examples/safe-agent --format json --output reports/benchmark-safe
.venv/bin/argus audit --target examples/vulnerable-agent --format json --output reports/benchmark-vulnerable
.venv/bin/python examples/indirect-injection/run_demo.py
```

The CLI exits `0` for the safe fixture and `10` for the vulnerable fixture at
the default `HIGH` gate. The indirect demo exits `0` when the dangerous tool
proposal is blocked and prints `side_effects: 0`.

## What the benchmark proves

| Case | Expected proof |
|---|---|
| `examples/safe-agent` | A bounded, verified read-only configuration passes static checks. |
| `examples/vulnerable-agent` | Deliberate MCP, skill, permission, secret, and unsafe-code findings produce a blocking report. |
| `examples/indirect-injection` | A poisoned retrieved SQLite document reaches a fake agent proposal, but the runtime policy blocks `execute_command` before execution; the canary remains unchanged. |

## Recorded run

Recorded on 2026-08-16 from source commit
`81991c8eab08a03fb3b6d9e7e37401935b37e62a`, using Argus `0.2.0`, Python
`3.14.4`, Node.js `v24.15.0`, and npm `11.16.0`.
The elapsed values below are the Argus internal scan timing; shell startup time
is shown separately only to make the result reproducible on this machine.

| Command | Files | Findings | Decision | Exit | Argus elapsed | Wall elapsed |
|---|---:|---:|---|---:|---:|---:|
| safe fixture | 2 | 0 | PASS | 0 | 0.018s | host-dependent |
| vulnerable fixture | 5 | 22 (10 critical, 9 high) | BLOCK | 10 | 0.018s | host-dependent |
| isolated indirect proof | — | — | BLOCK at tool boundary | 0 | — | 0.85s |

The benchmark was run without an LLM credential or external endpoint. It
demonstrates scanner correctness and the local enforcement boundary; use the
authorized live-LLM and live-MCP procedures in `POC.md` for transport evidence.

## What it does not prove

- It is not a complete OWASP, MITRE ATLAS, or compliance certification.
- The local indirect demo does not contact a provider or execute host commands.
- Dynamic model probes require an explicitly authorized endpoint and their
  evaluator is deterministic and bounded.

## Recording a new run

Record the commit SHA, UTC timestamp, Python version, OS, Argus version, test
result, fixture exit codes, file count, finding counts, and elapsed time. Do not
commit API keys, live model output, student data, or private MCP responses.
