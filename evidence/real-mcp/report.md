# Argus Security Evaluation Report

- Source: `stdio:npx`
- Profile: `default`
- Evaluation methodology: `canonical_only`
- Decision: **BLOCK** (fail on `HIGH`)

## Summary

Findings: **2**
Dynamic attack results: **0**
Dynamic transport errors: **0**
Maximum risk: **3.91 / 10**

## Performance

- MCP tools discovered: **14**
- Elapsed: **70.655 seconds**

## Findings

### HIGH: Missing input sanitization schema (`ARGUS_ST_002`)

A tool accepts structured input without a validation pattern or equivalent
constraint.

**Remediation:** Add JSON Schema types, bounds, enums, and patterns for
user-controlled fields.

### HIGH: High-impact MCP tool without approval (`ARGUS_ST_017`)

A tool can send, change, export, grant, or execute a high-impact action without
an explicit approval checkpoint.

**Remediation:** Add human approval immediately before the side effect and
validate the tool arguments against a strict schema.

## MCP live probe

- Transport: `stdio`
- Protocol: `2025-06-18`
- Pages read: **1**
- Tools discovered: **14**
- Tool calls made: **0** (read-only discovery)
- Server info: `secure-filesystem-server 0.2.0`

This is a real discovery result, not a claim that every implementation behind
the tools is safe.
