# Changelog

All notable changes to Argus are documented here. The project follows a
lightweight Keep a Changelog style; releases are versioned in `pyproject.toml`.

## [Unreleased]

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
