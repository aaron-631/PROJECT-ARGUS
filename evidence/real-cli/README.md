# Recorded local CLI verification

This is a sanitized local verification record. It shows what Argus can check
on installed agent CLIs without scanning credentials, conversation history,
session databases, logs, caches, or crash dumps. No secret value or model
response is committed.

Recorded: 2026-08-16 on Linux/WSL2, Python 3.14.4.

## Static configuration checks

| Client | Version | Surfaces checked | Result |
|---|---:|---|---|
| Antigravity local settings | local settings associated with Gemini CLI | one settings file | PASS; 0 findings |
| Gemini CLI | 0.49.0 | general config | PASS; 0 findings |
| Gemini CLI MCP registry | 0.49.0 | MCP config | ERROR; file is empty, so Argus did not call it safe |
| Codex CLI | 0.146.0 | `config.toml`, user rules | PASS; 0 findings |
| Claude Code | 2.1.199 | global settings | BLOCK; 1 critical credential-shaped value |
| Claude Code | 2.1.199 | local settings | BLOCK; 2 critical credential-shaped values and 9 distinct unbounded high-impact shell permission families |
| Claude Code state | 2.1.199 | top-level state/MCP metadata | PASS; 0 findings |

Claude’s native permission list was the useful finding. Entries such as
`Bash(curl:*)` are now interpreted as policy, while bounded entries such as
`Bash(git status)` are not flagged. The reports contain the permission family
and remediation; the actual settings and secret values remain local.

## Live headless smoke checks

The prompt for each check was a harmless fixed sentence requesting a marker.
No tool calls, file changes, or project modifications were requested.

| Client | Result | Meaning |
|---|---|---|
| Codex CLI | PASS; exit 0 | Ephemeral read-only headless execution returned the expected marker |
| Claude Code | TIMEOUT after 20 seconds | No response or error output; no success claim is made |
| Gemini CLI | ERROR; HTTP 401 | CLI reached the provider path, but the local authentication was rejected |
| Gemini CLI sandbox | ERROR before model call | The configured Docker sandbox image for 0.49.0 was unavailable locally |

The live checks prove CLI integration behavior only for the exact local
installation and credentials at that time. A `PASS` static scan does not prove
the provider account, model, skills, MCP implementations, or runtime behavior
are safe. The Claude timeout and Gemini authentication error require operator
environment fixes before those clients can receive a live dynamic security
assessment through Argus.

## Reproduce locally

Use explicit configuration paths and keep private files out of the target:

```bash
argus audit --target "$HOME/.codex/config.toml" --output reports/real-cli/codex
argus audit --target "$HOME/.claude/settings.json" --output reports/real-cli/claude
argus audit --target "$HOME/.gemini/config/config.json" --output reports/real-cli/gemini
```

For a live model endpoint, use `argus audit --endpoint` with an authorized
provider adapter. Argus does not pretend that an interactive CLI is the same
thing as a JSON HTTP endpoint; the CLI smoke test and endpoint probe are
separate evidence types.
