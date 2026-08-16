# Argus Security Evaluation Report

- Source: `stdio:npx`
- Profile: `default`
- Scan ID: `cdb3ff8d3b628c99`
- Evaluation methodology: `canonical_only`
- Decision: **BLOCK** (fail on `HIGH`)

## Summary

Findings: **2**
Dynamic attack results: **0**
Dynamic transport errors: **0**
Maximum risk: **3.91 / 10**

## Standards coverage

- OWASP LLM Top 10 (2025): tested `LLM01, LLM02, LLM03, LLM04, LLM05, LLM06, LLM08, LLM10`; not covered `LLM07, LLM09`
- OWASP Agentic (2026): tested `ASI01, ASI02, ASI03, ASI04, ASI05, ASI06, ASI08`; not covered `ASI07, ASI09, ASI10`
- MITRE ATLAS mappings: `AML.T0046, AML.T0048, AML.T0049, AML.T0051, AML.T0051.001, AML.T0052`

## Performance

- MCP tools discovered: **14**
- Elapsed: **1.016 seconds**

## Findings

### HIGH: Missing input sanitization schema (`ARGUS_ST_002`)

A tool accepts structured input without a validation pattern or equivalent
constraint.

- OWASP: `LLM05, ASI02`; ATLAS: `unmapped`; CWE: `CWE-20`

**Remediation:** Add JSON Schema types, bounds, enums, and patterns for
user-controlled fields.

### HIGH: High-impact MCP tool without approval (`ARGUS_ST_017`)

A tool can send, change, export, grant, or execute a high-impact action without
an explicit approval checkpoint.

- OWASP: `LLM06, ASI02`; ATLAS: `AML.T0052`; CWE: `CWE-862`

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
