# Recorded real MCP evidence

This is a redacted portfolio record from the real pinned-server run described
in `WORKFLOW.md`. It contains no credentials, private configuration, tool
arguments, or tool execution results.

## Run

- Source baseline commit: `f1cae6a`; this recorded run was executed from the
  `feature/argus-taxonomy-indirect-injection` working tree after the taxonomy,
  dataset, and reporting changes described in this branch
- Host: Linux/WSL2
- Python: 3.14.4
- Node.js: 24.15.0
- npm: 11.16.0
- Server: `@modelcontextprotocol/server-filesystem@2026.7.10`
- Transport: stdio
- Application root: isolated temporary directory
- MCP operations: `initialize`, `notifications/initialized`, paginated `tools/list`
- Tool calls: 0
- Exit code: 10 (`BLOCK` because findings crossed the configured HIGH gate)

## Result

- 14 tools discovered on 1 page;
- 2 HIGH findings;
- 1.016 seconds on this warm local run (cold `npx` startup is host-dependent);
- OWASP/Agentic/ATLAS metadata is present in the generated report;
- JSON/Markdown/SARIF reports generated;
- report hashes and the sanitized machine-readable record are in `record.json`.

The finding details are preserved in [`report.md`](report.md). Re-run the
command in the workflow to regenerate the full report for the current host.
