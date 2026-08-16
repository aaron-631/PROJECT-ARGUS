# Changelog

All notable changes to Argus are documented here. The project follows a
lightweight Keep a Changelog style; releases are versioned in `pyproject.toml`.

## [Unreleased]

## [0.2.1] - 2026-08-16

### Security

- Baseline identities now include finding locations, so duplicate occurrences
  cannot collapse into an accepted baseline.
- Dynamic scans treat non-2xx provider responses as explicit errors and bound
  target and judge response bodies.
- Report sanitization removes URL credentials/query strings and all header values;
  MCP responses are correlated to their JSON-RPC request IDs.
- Runtime admission now has bounded concurrency/rate/audit-shipping controls,
  and audit storage failures fail closed with a structured `503` response.

### Delivery

- Entry-point attack plugins can stream probes and use the shared evaluator.
- GitHub Actions are pinned to immutable commit SHAs and the dependency lock
  contains hashes for every published artifact of each exact version.

## [0.2.0] - 2026-08-16

### Security

- Runtime prompt policies now normalize Unicode/control obfuscation and inspect
  OpenAI Responses `input` messages.
- Runtime tool enforcement is deny-by-default and recognizes OpenAI Responses
  `function_call` output items.
- Existing audit chains are verified before append and flushed to durable storage
  with `fsync`.
- Local and Git ingress enforce file-count and aggregate-byte limits before
  reading repository content.

### Delivery

- Production and runtime Compose profiles use immutable base-image digests,
  non-root containers, read-only filesystems, dropped capabilities, resource
  limits, and no-new-privileges.
- Baseline reports now distinguish overall findings from the CI gate decision.

### Fixed

- Entry-point scanner plugins now actually run. `scanners` defaulted to
  `["mcp_scanner"]`, so an installed plugin was registered and then silently
  filtered out, producing no findings and no error. An empty list now means
  "every registered scanner".
- Plugin rule IDs are accepted. `Finding.rule_id` required `ARGUS_ST_NNN`, so the
  documented plugin example could not construct a finding. Any
  `UPPER_SNAKE_CASE` ID is valid and the `ARGUS_` prefix is reserved for
  built-ins.
- A plugin that fails to load is reported in `summary["errors"]` and forces
  `ERROR` instead of being silently skipped.
- `ARGUS_ST_004`/`ARGUS_ST_006` no longer fire on a policy deny-list. Matching
  the serialized mapping meant `block_tools: ["delete*"]` was reported as a
  destructive tool, inverting the meaning of a security control.
- Equivalent YAML and JSON configurations now reach the same verdict; word-boundary
  matching previously made the result depend on glob punctuation.
- Argus no longer re-ingests its own generated reports. Repeated scans of one
  directory compounded findings (15 → 24 → 25) with no code change. A project's
  own unrelated `reports/` data is still scanned.
- A single-file target that cannot be read is an error rather than an empty `PASS`.

### Added

- `--exclude` (repeatable) to skip directory names or globs under the target.

### Documentation

- Stated that unsafe-code rules are Python-only, so TypeScript and Go shell
  injection is not detected today.
- Stated that `redact_personal_data` covers email and Indian mobile numbers only.
- Corrected the recorded test count and the documented result-key list.

### Previously

- Added baseline/diff gating so CI can fail on new or more-severe findings while
  existing findings are being remediated.
- Added a cross-platform Python portfolio demo and an intentionally vulnerable
  example agent.
- Added a Mermaid architecture diagram, sanitized real-MCP evidence record,
  repository security policy, contribution guide, and license.
- Added CI compatibility and dependency supply-chain checks.

## [0.1.0]

- Added static agent, MCP, and skill analysis.
- Added bounded LLM probes and read-only stdio/Streamable HTTP MCP discovery.
- Added JSON, Markdown, and SARIF reporting.
- Added the optional runtime policy gateway with metrics and hash-chained audit
  events.
