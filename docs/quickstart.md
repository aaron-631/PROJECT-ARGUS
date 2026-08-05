# Quick-Start Guide

Get from zero to first scan in 5 minutes with Argus.

## Prerequisites
- Python 3.11+
- Optional: Node.js (for testing standard MCP filesystem servers)

## Installation
Run these four commands to get Argus set up locally:
```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install -e .
.venv/bin/argus doctor
```

## Your First Scan
Test against the included vulnerable agent example:
```bash
.venv/bin/argus scan --target ./examples/vulnerable-agent
```

## Understanding Results
- **PASS**: No configured rule crossed the gate. The target configuration looks secure.
- **BLOCK**: Review is required. One or more critical/high severity rules were violated.
- **ERROR**: The check did not finish due to a configuration or runtime issue.

**Severity Levels:**
- **CRITICAL**: Immediate action required (e.g., unrestricted shell access).
- **HIGH**: High-impact risk (e.g., broad environment variables).
- **MEDIUM**: Warning or missing best practices.

## Scan Your Own Project
To scan your own local project or repository:
```bash
.venv/bin/argus scan --target /path/to/your/agent
```

## Probe a Live MCP Server
Check a read-only filesystem MCP server instance:
```bash
.venv/bin/argus mcp-probe \
  --transport stdio \
  --command npx \
  --arg=-y \
  --arg=@modelcontextprotocol/server-filesystem@2026.7.10 \
  --arg=/approved/directory \
  --timeout 120 \
  --confirm-live \
  --output ./reports/mcp-live
```

## CI/CD Integration
Add this GitHub Actions YAML snippet to use SARIF scanning:
```yaml
name: Argus Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install Argus
        run: |
          python -m venv .venv
          .venv/bin/pip install -e .
      - name: Run Scan
        run: .venv/bin/argus scan --target . --output ./reports
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/report.sarif
```

## Next Steps
- Read the [README.md](../README.md) for deeper overview.
- Read [WORKFLOW.md](../WORKFLOW.md) for architectural trade-offs.
- Explore different rule severities via `--profile`.
