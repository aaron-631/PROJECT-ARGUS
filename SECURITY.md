# Security policy

Argus is itself a security-sensitive project. Please do not include API keys,
private configuration, model responses, or customer data in an issue or pull
request.

## Reporting a vulnerability

Use a private GitHub Security Advisory for this repository when available. If
that channel is unavailable, contact the repository maintainer privately
through the GitHub account that owns the repository. Do not disclose an
unfixed vulnerability in a public issue.

Please include:

- the affected commit or release;
- a minimal reproduction with secrets removed;
- impact and realistic attack conditions;
- a suggested remediation, if known.

Argus is a defensive evaluation tool. Only run live probes against systems and
MCP servers you are authorized to test. `--confirm-live` records operator
intent; it is not a sandbox or permission grant.

## Scope and limitations

The project does not promise complete safety certification. It supports
deterministic static checks, bounded authorized endpoint probes, read-only MCP
discovery, and an optional runtime policy gateway. TLS termination, identity,
durable audit storage, and high availability belong in deployment
infrastructure.
