# Argus Security Evaluation Report

- Source: `stdio:npx`
- Profile: `default`
- Scan ID: `322ab801bd0a8dfa`
- Evaluation methodology: `canonical_only`
- Overall findings: **BLOCK** (fail on `HIGH`)

## Summary

Findings: **2**
Dynamic attack results: **0**
Dynamic transport errors: **0**
Maximum risk: **3.91 / 10**

- CI gate decision: **BLOCK**

## Standards coverage

- OWASP LLM Top 10 (2025): tested `LLM01, LLM02, LLM03, LLM04, LLM05, LLM06, LLM08, LLM10`; not covered `LLM07, LLM09`
- OWASP Agentic (2026): tested `ASI01, ASI02, ASI03, ASI04, ASI05, ASI06, ASI08`; not covered `ASI07, ASI09, ASI10`
- MITRE ATLAS mappings: `AML.T0046, AML.T0048, AML.T0049, AML.T0051, AML.T0051.001, AML.T0052`

## Performance

- MCP tools discovered: **14**
- Elapsed: **0.561 seconds**

## Static findings

### HIGH: Missing input sanitization schema (`ARGUS_ST_002`)

A tool accepts structured input without a validation pattern or equivalent constraint.

- Evidence: `mcp-probe.json` line `1`
- Risk: **3.22 / 10**; confidence: **0.92**
- Methodology: `deterministic_static`
- OWASP: `LLM05, ASI02`; ATLAS: `unmapped`; CWE: `CWE-20`


**Remediation:** Add JSON Schema types, bounds, enums, and patterns for user-controlled fields.

### HIGH: High-impact MCP tool without approval (`ARGUS_ST_017`)

A tool can send, change, export, grant, or execute a high-impact action without an explicit approval checkpoint.

- Evidence: `mcp-probe.json` line `1`
- Risk: **3.91 / 10**; confidence: **0.92**
- Methodology: `deterministic_static`
- OWASP: `LLM06, ASI02`; ATLAS: `AML.T0052`; CWE: `CWE-862`


**Remediation:** Add human approval immediately before the side effect and validate the tool arguments against a strict schema.

## Dynamic evaluation

Dynamic attacks were not run; provide an explicit target endpoint to enable them.
## MCP inventory

Declared MCP servers: **1**
Declared MCP tools: **14**

### Servers

- `official-filesystem` (stdio, npx, unverified) from `mcp-probe.json`

### Tools

- `create_directory` (no approval metadata) from `mcp-probe.json`
- `directory_tree` (no approval metadata) from `mcp-probe.json`
- `edit_file` (no approval metadata) from `mcp-probe.json`
- `get_file_info` (no approval metadata) from `mcp-probe.json`
- `list_allowed_directories` (no approval metadata) from `mcp-probe.json`
- `list_directory` (no approval metadata) from `mcp-probe.json`
- `list_directory_with_sizes` (no approval metadata) from `mcp-probe.json`
- `move_file` (no approval metadata) from `mcp-probe.json`
- `read_file` (no approval metadata) from `mcp-probe.json`
- `read_media_file` (no approval metadata) from `mcp-probe.json`
- `read_multiple_files` (no approval metadata) from `mcp-probe.json`
- `read_text_file` (no approval metadata) from `mcp-probe.json`
- `search_files` (no approval metadata) from `mcp-probe.json`
- `write_file` (no approval metadata) from `mcp-probe.json`

## MCP live probe

- Transport: `stdio`
- Target: `stdio:npx`
- Protocol: `2025-06-18`
- Pages read: **1**
- Tools discovered: **14**
- Tool calls made: **0** (read-only discovery)
- Server info: `{'name': 'secure-filesystem-server', 'version': '0.2.0'}`

## Skill inventory

Discovered skills: **0**
