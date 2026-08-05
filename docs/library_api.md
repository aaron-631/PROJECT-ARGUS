# Library API

Argus is usable as a Python library, not only a CLI. This is the same interface
the `argus` command uses internally, so anything below is exercised on every scan.

Every example on this page is executable against a clone with `pip install -e .`.

## Import paths

Argus ships as top-level packages under `src.*`, plus the `argus` console script.
When importing programmatically, use `src.*`:

```python
from src.core.config import load_config
from src.core.engine import ArgusEngine
from src.core.ingress import ingest
```

## Run a scan

`ArgusEngine.run` is async and returns a plain `dict` — the same structure
written to `report.json`.

```python
import asyncio

from src.core.config import load_config
from src.core.engine import ArgusEngine
from src.core.ingress import ingest


async def main() -> None:
    context = ingest("./examples/vulnerable-agent")
    config = load_config(profile="default")
    results = await ArgusEngine(config).run(context)

    summary = results["summary"]
    print(summary["decision"])            # PASS | BLOCK | ERROR
    print(summary["finding_count"])
    print(summary["skipped_file_count"])  # files not read (binary/non-UTF-8)

    for finding in results["findings"]:
        print(finding["rule_id"], finding["severity"], finding["title"])


asyncio.run(main())
```

`ingest` accepts a local path or a Git URL. Call `ingest_local` or `ingest_git`
directly to bypass the URL heuristic.

## Result structure

`run()` returns five top-level keys:

| Key | Contents |
| --- | --- |
| `metadata` | Schema version, profile, scan id, source |
| `configuration` | Effective configuration, secrets redacted |
| `findings` | Static findings |
| `attack_results` | Dynamic probe results (empty unless an endpoint is set) |
| `summary` | Counts, decision, errors, performance |

Findings use the fields on the `Finding` model: `rule_id`, `severity`, `title`,
`description`, `confidence_score`, `evidence`, `source_file`, `line`,
`deployment_context`, `base_score`, `risk_score`, `evaluation_methodology`, and
`remediation`.

Fields on `summary` worth knowing:

- `decision` — `PASS`, `BLOCK`, or `ERROR`. `ERROR` means the scan did not
  complete cleanly and must not be read as a pass.
- `skipped_file_count` / `skipped_files` — files deliberately not read. A scan
  that skipped files is not full coverage; check this before trusting a `PASS`.
- `suppressed_rules` — rules silenced via `disabled_rules`, recorded so a
  suppressed scan is never indistinguishable from a clean one.
- `errors` / `error_count` — parse failures and scanner crashes.

## Configuration

`load_config` returns a pydantic `ArgusConfig`. Override with `model_copy`
rather than mutating in place:

```python
from src.core.config import load_config

config = load_config(profile="default")

reporting = config.reporting.model_copy(update={"fail_on": "CRITICAL"})
config = config.model_copy(
    update={"reporting": reporting, "disabled_rules": ["ARGUS_ST_001"]}
)
```

`ArgusEngine` also accepts a plain `dict`, which is validated into an
`ArgusConfig`.

## Probe an MCP server

Both probes are read-only: they call `initialize` and paginate `tools/list`, and
never invoke a tool. Only run them against servers you are authorized to contact.

```python
import asyncio

from src.core.mcp_probe import MCPProbeLimits, build_probe_context, probe_stdio


async def main() -> None:
    result = await probe_stdio(
        ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/approved/dir"],
        limits=MCPProbeLimits(timeout_seconds=120),
    )
    print(result.protocol_version, len(result.tools))

    # Feed discovered tools through the normal scanning pipeline.
    context = build_probe_context(result)


asyncio.run(main())
```

Use `probe_streamable_http(endpoint, headers=...)` for HTTP transports. On
failure both raise `MCPProbeError`; the message includes the server's stderr
tail with secrets redacted.

## Export reports

Exporters take the results dict and a **full destination file path**, and return
the path written.

```python
from pathlib import Path

from src.reporting import JSONExporter, MarkdownExporter, SARIFExporter

output_dir = Path("./reports")
output_dir.mkdir(parents=True, exist_ok=True)

print(JSONExporter().export(results, output_dir / "report.json"))
print(MarkdownExporter().export(results, output_dir / "report.md"))
print(SARIFExporter().export(results, output_dir / "report.sarif"))
```

## Baseline comparison

`apply_baseline` attaches a comparison under `summary["baseline"]` without
changing the findings themselves, so only new or worsened findings gate a build:

```python
from src.core.baseline import apply_baseline

apply_baseline(results, "./reports/baseline.json")
print(results["summary"]["baseline"]["gate"])
```

## Inspect the registry

```python
from src.core.registry import get_registry

registry = get_registry()
print(list(registry["scanners"]))
print(list(registry["exporters"]))
```

See [plugins.md](plugins.md) to add your own.
