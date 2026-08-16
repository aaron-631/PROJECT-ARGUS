# Recorded real MCP evidence

This is a redacted portfolio record from the real pinned-server run described
in `WORKFLOW.md`. It contains no credentials, private configuration, tool
arguments, or tool execution results.

## Run

- Source baseline commit: `85a5ab032751d00c9f451082e5bbd5ca019ae17c`
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
- 0.624 seconds on this cached `npx --offline` run; the first online startup took
  70.628 seconds on this host;
- OWASP/Agentic/ATLAS metadata is present in the generated report;
- JSON/Markdown/SARIF reports generated;
- report hashes and the sanitized machine-readable record are in `record.json`.

The finding details are preserved in [`report.md`](report.md), with the exact
machine-readable [`report.json`](report.json) and GitHub-compatible
[`report.sarif`](report.sarif) beside it. Re-run the command in the workflow to
regenerate the report for the current host.
