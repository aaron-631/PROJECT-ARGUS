# Safe agent fixture

This is a deliberately small clean fixture for regression evidence. It uses a
read-only placement lookup, a constrained input schema, a verified local MCP
command, and an explicit untrusted-context boundary for retrieval.

Run it from the repository root:

```bash
.venv/bin/argus audit --target examples/safe-agent --format json --output reports/example-safe-agent
```

Expected result: `PASS`, zero static findings, and no dynamic requests because
no endpoint was supplied.
