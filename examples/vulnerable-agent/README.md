# Intentionally vulnerable agent fixture

This directory is a safe, non-production fixture for the Argus demo. Every
finding is deliberate and uses fake values. Do not copy this configuration
into a real agent or place a real credential in `.env.example`.

The fixture demonstrates the kinds of issues Argus is designed to surface:

- unpinned and remote MCP configuration;
- wildcard permissions and unrestricted network egress;
- missing approval and input constraints on a write-capable tool;
- unsafe Python execution and deserialization;
- an authority-override skill with secret and external-upload instructions.

Run it from the repository root:

```bash
.venv/bin/argus audit \
  --target examples/vulnerable-agent \
  --output reports/example-vulnerable-agent
```

The expected result is `BLOCK`, with findings in the JSON, Markdown, and SARIF
reports. The fixture is intentionally noisy so a first-time user can see a
meaningful security result without scanning private files or using credentials.
