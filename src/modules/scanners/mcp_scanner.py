"""Deterministic static checks for agent and MCP server repositories."""

from __future__ import annotations

import ast
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from src.core.registry import register_scanner
from src.core.documents import parse_file
from src.models import Finding, ScanContext, Severity
from src.interfaces.scanner import BaseStaticScanner
from src.models.documents import DocumentKind, ParsedDocument
from .rules import RULE_CAPABILITIES, CONFIG_EXTENSIONS

_RULES: dict[str, tuple[Severity, str, str, float, str]] = {
    "ARGUS_ST_001": (
        Severity.CRITICAL,
        "Wildcard filesystem access",
        "A tool exposes a filesystem wildcard that can reach outside an explicit resource boundary.",  # noqa: E501
        9.0,
        "Replace wildcards with an allowlisted directory or object set.",
    ),
    "ARGUS_ST_002": (
        Severity.HIGH,
        "Missing input sanitization schema",
        "A tool accepts structured input without a validation pattern or equivalent constraint.",
        7.0,
        "Add JSON Schema types, bounds, enums, and patterns for user-controlled fields.",
    ),
    "ARGUS_ST_003": (
        Severity.CRITICAL,
        "Unsafe code execution",
        "Dynamic evaluation or subprocess execution is reachable from scanned code without a verifiable strict argument boundary.",  # noqa: E501
        10.0,
        "Remove eval/exec; use an allowlisted operation map and fixed subprocess arguments.",
    ),
    "ARGUS_ST_004": (
        Severity.HIGH,
        "Destructive database operation without approval",
        "A database tool permits destructive SQL operations without an explicit approval gate.",
        8.0,
        "Require human approval and parameterized queries for destructive database actions.",
    ),
    "ARGUS_ST_005": (
        Severity.MEDIUM,
        "Blind trust of external input",
        "Tool guidance instructs an agent to trust external content without verification.",
        5.0,
        "Treat external content as untrusted data and validate it before tool execution.",
    ),
    "ARGUS_ST_006": (
        Severity.HIGH,
        "Missing destructive-action approval gate",
        "A destructive action is configured without require_approval or an equivalent checkpoint.",
        8.0,
        "Add an approval checkpoint immediately before every destructive action.",
    ),
    "ARGUS_ST_007": (
        Severity.CRITICAL,
        "Unsafe deserialization",
        "Workflow code uses a deserializer that can execute arbitrary object constructors.",
        9.0,
        "Use JSON or a restricted schema and never deserialize untrusted pickle/YAML objects.",
    ),
    "ARGUS_ST_008": (
        Severity.HIGH,
        "Excessive autonomy loop limit",
        "A workflow permits an unusually large number of recursive or autonomous iterations.",
        7.0,
        "Set a bounded iteration limit appropriate to the workflow and require escalation.",
    ),
    "ARGUS_ST_009": (
        Severity.MEDIUM,
        "Circular tool dependency",
        "Tool dependencies form a cycle that can exhaust context or cause repeated execution.",
        5.0,
        "Break the dependency cycle and add a bounded workflow state transition.",
    ),
    "ARGUS_ST_010": (
        Severity.CRITICAL,
        "Hardcoded credential",
        "A likely API key, token, password, or secret is embedded in a configuration file.",
        9.0,
        "Load credentials from a secret manager or environment injection at runtime.",
    ),
    "ARGUS_ST_011": (
        Severity.HIGH,
        "Broad environment ingestion",
        "The configuration passes all environment variables into an agent or tool.",
        8.0,
        "Pass only the named variables required by the tool.",
    ),
    "ARGUS_ST_012": (
        Severity.HIGH,
        "Unencrypted dotenv file",
        "A .env file is part of the scanned repository context.",
        7.0,
        "Remove .env files from source control and use managed runtime secrets.",
    ),
    "ARGUS_ST_013": (
        Severity.HIGH,
        "Unverified remote MCP server",
        "A remote MCP server is configured without a signature, checksum, or explicit verification policy.",  # noqa: E501
        8.0,
        "Pin the server identity and verify its signature or immutable digest.",
    ),
    "ARGUS_ST_014": (
        Severity.MEDIUM,
        "Outdated agent framework",
        "A known agent framework dependency is unpinned or below the V1 supported security baseline.",  # noqa: E501
        5.0,
        "Pin a current supported framework release and maintain dependency security updates.",
    ),
    "ARGUS_ST_015": (
        Severity.MEDIUM,
        "Insecure HTTP endpoint",
        "A network configuration uses HTTP where HTTPS should protect credentials and prompts in transit.",  # noqa: E501
        5.0,
        "Use HTTPS with certificate validation; allow HTTP only for explicit localhost test fixtures.",  # noqa: E501
    ),
    "ARGUS_ST_016": (
        Severity.CRITICAL,
        "Wildcard or administrative MCP permission",
        "An MCP server or tool grants a wildcard, all-resource, root, admin, or sudo-style permission.",  # noqa: E501
        9.0,
        "Replace broad permissions with the smallest named files, resources, commands, and scopes required.",  # noqa: E501
    ),
    "ARGUS_ST_017": (
        Severity.HIGH,
        "High-impact MCP tool without approval",
        "A tool can send, change, export, grant, or execute a high-impact action without an "
        "explicit approval checkpoint.",
        8.5,
        "Add human approval immediately before the side effect and validate the tool arguments against a strict schema.",  # noqa: E501
    ),
    "ARGUS_ST_018": (
        Severity.HIGH,
        "Unrestricted MCP network egress",
        "An MCP server or tool can reach every host, domain, URL, or network destination.",
        8.0,
        "Use an outbound allowlist of named domains or service identities and deny everything "
        "else.",
    ),
    "ARGUS_ST_019": (
        Severity.HIGH,
        "Unpinned MCP package command",
        "An MCP server is launched through a package runner without a version or immutable reference.",  # noqa: E501
        7.0,
        "Pin the package version or digest and verify it through the deployment lockfile or artifact registry.",  # noqa: E501
    ),
    "ARGUS_ST_020": (
        Severity.HIGH,
        "MCP service bound publicly",
        "A configured MCP service binds to every network interface, which can expose an administrative or tool endpoint.",  # noqa: E501
        7.5,
        "Bind to a private interface and place public access behind authenticated TLS and an explicit gateway.",  # noqa: E501
    ),
    "ARGUS_ST_021": (
        Severity.HIGH,
        "TLS certificate verification disabled",
        "The MCP or model connection disables certificate verification, enabling interception of prompts or tool data.",  # noqa: E501
        8.0,
        "Keep certificate verification enabled and install the correct private CA instead of bypassing TLS checks.",  # noqa: E501
    ),
    "ARGUS_ST_022": (
        Severity.HIGH,
        "Skill attempts to override agent authority",
        "A skill contains instructions that try to supersede system policy, hide actions, or disable safety controls.",  # noqa: E501
        8.0,
        "Treat the skill as untrusted input, remove authority-override language, and review it before enabling the skill.",  # noqa: E501
    ),
    "ARGUS_ST_023": (
        Severity.CRITICAL,
        "Skill contains dangerous command execution",
        "A skill instructs an agent to run arbitrary shell commands, destructive filesystem actions, or untrusted code.",  # noqa: E501
        9.5,
        "Use a narrow allowlist of fixed operations, sandbox execution, and approval for any destructive command.",  # noqa: E501
    ),
    "ARGUS_ST_024": (
        Severity.CRITICAL,
        "Skill requests secrets or broad environment access",
        "A skill asks the agent to read credentials, private keys, dotenv files, or the entire process environment.",  # noqa: E501
        9.0,
        "Inject only the named secret into an isolated process and never place credentials in prompts or tool output.",  # noqa: E501
    ),
    "ARGUS_ST_025": (
        Severity.HIGH,
        "Skill installs unpinned remote code",
        "A skill downloads or installs dependencies without an immutable version, checksum, or trusted artifact boundary.",  # noqa: E501
        7.5,
        "Pin dependencies, verify checksums/signatures, and install only through a reviewed build or policy service.",  # noqa: E501
    ),
    "ARGUS_ST_026": (
        Severity.HIGH,
        "Skill sends data to an external destination",
        "A skill directs the agent to upload, POST, or transmit local or user data to an external endpoint.",  # noqa: E501
        8.0,
        "Allowlist the destination, minimize the data, require consent for sensitive transfers, and log the action.",  # noqa: E501
    ),
    "ARGUS_ST_027": (
        Severity.MEDIUM,
        "Skill provenance is not verifiable",
        "A discovered skill has no adjacent origin, integrity, or verification metadata that ties it to a reviewed source.",  # noqa: E501
        5.0,
        "Verify the skill with the source registry or a signed internal artifact, record its version/digest, and review updates before enabling it.",  # noqa: E501
    ),
}

_SECRET_RE = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|secret|password|private[_-]?key)\s*[:=]\s*['\"]?([^\s,'\"]{8,})"  # noqa: E501
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)(?:sk|pk)_(?:live|test)_[A-Za-z0-9_-]{12,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
)
_DESTRUCTIVE_RE = re.compile(r"(?i)\b(drop|delete|truncate|update)\b")
_TRUST_RE = re.compile(
    r"(?i)\b(trust|assume|treat)\b.{0,50}\b(untrusted|external|user|input)\b|ignore\s+(?:all\s+)?validation"  # noqa: E501
)
_REMOTE_RE = re.compile(r"\bhttps?://[^\s'\"]+")
_BROAD_PERMISSION_VALUES = {"*", "all", "full", "admin", "root", "sudo", "/**", "/*"}
_BROAD_SCOPE_KEYS = {
    "access",
    "allowed_domains",
    "allowed_hosts",
    "allowed_urls",
    "filesystem",
    "elevated",
    "profile",
    "permissions",
    "resources",
    "scope",
    "scopes",
}
_NETWORK_SCOPE_KEYS = {
    "allowed_domains",
    "allowed_hosts",
    "allowed_urls",
    "egress",
    "network",
    "networks",
}
_HIGH_IMPACT_RE = re.compile(
    r"(?i)\b(send[_ -]?email|issue[_ -]?offer|update[_ -]?student|export(?:\s+all)?|"
    r"grant|revoke|invite|write[_ -]?file|execute[_ -]?command|shell|run[_ -]?command)\b"
)
_PACKAGE_RUNNERS = {"npx", "uvx", "pipx"}
_SKILL_AUTHORITY_RE = re.compile(
    r"(?i)(?:ignore|disregard|override).{0,60}(?:system|developer|previous|safety|policy)|"
    r"(?:disable|bypass).{0,40}(?:approval|sandbox|safety)|"
    r"do not (?:tell|show|ask) the user"
)
_SKILL_COMMAND_RE = re.compile(
    r"(?im)(?:curl|wget)[^\n]{0,160}\|\s*(?:sh|bash)|"
    r"\brm\s+-rf\s+/|\bsudo\b|\beval\s*\(|"
    r"\b(?:run|execute)\s+(?:any|arbitrary|untrusted)\s+(?:shell\s+)?commands?"
)
_SKILL_SECRET_RE = re.compile(
    r"(?i)(?:read|print|dump|send|upload|include).{0,80}(?:all|every|entire).{0,40}"
    r"(?:environment|env|secrets?|credentials?)|(?:\.env|~?/.ssh|private[_ -]?key|"
    r"api[_ -]?key).{0,100}"
    r"(?:send|upload|include|print|dump)|(?:send|upload|include).{0,100}"
    r"(?:\.env|~?/.ssh|private[_ -]?key|api[_ -]?key|local files?)"
)
_SKILL_INSTALL_RE = re.compile(
    r"(?i)\b(?:pip3?|uv)\s+install\s+[A-Za-z0-9_.-]+(?!\s*(?:==|>=|<=|~=|@))|"
    r"\bnpm\s+install\s+@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?!@[0-9])|"
    r"\bgit\s+clone\s+https?://[^\s]+(?:\s+--branch\s+main)?"
)
_SKILL_EXFIL_RE = re.compile(
    r"(?i)(?:\bcurl\b|\bwget\b|\b(?:http|https)\s*(?:post|upload)|\bwebhook\b).{0,120}"
    r"(?:send|post|upload|transmit|local files?|user data|conversation|secrets?)|"
    r"(?:send|post|upload|transmit).{0,120}"
    r"(?:local files?|user data|conversation|secrets?|\.env|~?/.ssh)"
)


def _is_skill_path(path: str) -> bool:
    lowered = path.lower()
    return lowered.endswith(("/skill.md", "/skills.md", "skill.md", "skills.md"))


def _skill_has_provenance(context: ScanContext, path: str) -> bool:
    skill_directory = str(Path(path).parent).replace("\\", "/")
    return any(
        candidate.startswith(skill_directory + "/.clawhub/")
        and candidate.lower().endswith("origin.json")
        and re.search(r"(?i)integrity|sha256|signature|version", record.content)
        for candidate, record in context.files.items()
    )


_FRAMEWORK_RE = re.compile(
    r"(?i)\b(langchain|langgraph|autogen|crewai|semantic-kernel)\b(?:\s*[<>=!~]+\s*([0-9][^\s,;]*))?"  # noqa: E501
)


def _line_for(content: str, needle: str) -> int | None:
    index = content.lower().find(needle.lower())
    return content.count("\n", 0, index) + 1 if index >= 0 else None


def _iter_values(value: Any, path: str = "") -> Iterable[tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_values(child, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_values(child, f"{path}[{index}]")


def _is_mcp_server_location(location: str) -> bool:
    """Recognize known MCP server registry paths, not generic project URLs."""

    tokens = location.lower().replace("-", "_").split(".")
    return (
        "mcpservers" in tokens
        or "mcp_servers" in tokens
        or ("mcp" in tokens and any(token in {"server", "servers"} for token in tokens))
    )


@register_scanner
class MCPScanner(BaseStaticScanner):
    scanner_id = "mcp_scanner"
    version = "1.0.0"
    supported_extensions = CONFIG_EXTENSIONS | {".py", ".txt", ".md", ".env", ".in"}
    supported_document_kinds = frozenset(kind.value for kind in DocumentKind)
    rule_capabilities = RULE_CAPABILITIES

    @classmethod
    def _supports(cls, rule_id: str, path: str, document: ParsedDocument | None) -> bool:
        return cls.rule_capabilities[rule_id].supports(path, document)  # type: ignore[union-attr]

    @staticmethod
    def inventory(context: ScanContext) -> dict[str, list[dict[str, Any]]]:
        """Return a safe inventory of declared MCP servers and tools.

        Inventory is intentionally metadata-only: it excludes environment
        values, tool descriptions, URLs with query strings, and raw arguments.
        Findings remain the authoritative security decisions.
        """

        servers: list[dict[str, Any]] = []
        tools: list[dict[str, Any]] = []
        skills: list[dict[str, Any]] = []
        for record in context.iter_files():
            if _is_skill_path(record.path):
                name_match = re.search(r"(?im)^name\s*:\s*([^\n#]+)", record.content)
                skills.append(
                    {
                        "name": (
                            name_match.group(1).strip().strip("'\"")
                            if name_match
                            else Path(record.path).parent.name
                        ),
                        "file": record.path,
                        "provenance": (
                            "verified_metadata"
                            if _skill_has_provenance(context, record.path)
                            else "review_required"
                        ),
                    }
                )
            document = context.documents.get(record.path)
            if not isinstance(document, ParsedDocument):
                document = parse_file(record)
            if not isinstance(document, ParsedDocument) or document.kind not in {
                DocumentKind.JSON,
                DocumentKind.YAML,
                DocumentKind.TOML,
            }:
                continue
            value = document.value
            if not isinstance(value, dict):
                continue
            server_maps: list[dict[str, Any]] = []

            def collect_server_maps(node: Any, location: str = "") -> None:
                if not isinstance(node, dict):
                    return
                for key, child in node.items():
                    normalized_key = key.lower().replace("-", "_")
                    child_location = f"{location}.{normalized_key}" if location else normalized_key
                    if (
                        isinstance(child, dict) and normalized_key in {"mcpservers", "mcp_servers"}
                    ) or (
                        isinstance(child, dict)
                        and normalized_key == "servers"
                        and location.lower().endswith("mcp")
                    ):
                        server_maps.append(child)
                    else:
                        collect_server_maps(child, child_location)

            collect_server_maps(value)
            for server_map in server_maps:
                for name, settings in server_map.items():
                    if not isinstance(settings, dict):
                        continue
                    endpoint = settings.get("url", settings.get("endpoint"))
                    servers.append(
                        {
                            "name": str(name),
                            "file": record.path,
                            "transport": "http" if endpoint else "stdio",
                            "command": (
                                Path(str(settings.get("command"))).name
                                if settings.get("command")
                                else None
                            ),
                            "host": urlparse(str(endpoint)).hostname if endpoint else None,
                            "verified": bool(
                                settings.get("signature")
                                or settings.get("checksum")
                                or settings.get("sha256")
                                or settings.get("verified") is True
                            ),
                        }
                    )

            def collect_tools(node: Any, location: str = "") -> None:
                if isinstance(node, dict):
                    lowered_location = location.lower()
                    if ("tool" in lowered_location or "mcp" in lowered_location) and node.get(
                        "name"
                    ):
                        approval = any(
                            key.lower().replace("-", "_")
                            in {
                                "require_approval",
                                "approval",
                                "approval_required",
                                "human_approval",
                            }
                            and bool(child)
                            for key, child in node.items()
                        )
                        tools.append(
                            {
                                "name": str(node["name"]),
                                "file": record.path,
                                "approval_required": approval,
                            }
                        )
                    for key, child in node.items():
                        child_location = f"{location}.{key}" if location else str(key)
                        collect_tools(child, child_location)
                elif isinstance(node, list):
                    for index, child in enumerate(node):
                        collect_tools(child, f"{location}[{index}]")

            collect_tools(value)
        return {
            "mcp_servers": sorted(servers, key=lambda item: (item["file"], item["name"])),
            "mcp_tools": sorted(tools, key=lambda item: (item["file"], item["name"])),
            "skills": sorted(skills, key=lambda item: (item["file"], item["name"])),
        }

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        parsed: list[tuple[str, Any, str, ParsedDocument]] = []
        for record in context.iter_files():
            parsed_document = context.documents.get(record.path)
            if not isinstance(parsed_document, ParsedDocument):
                parsed_document = parse_file(record)
            if parsed_document.value is not None and parsed_document.kind in {
                DocumentKind.JSON,
                DocumentKind.YAML,
                DocumentKind.TOML,
            }:
                parsed.append((record.path, parsed_document.value, record.content, parsed_document))

        def add(rule_id: str, path: str, evidence: dict[str, Any], line: int | None = None) -> None:
            severity, title, description, base_score, remediation = _RULES[rule_id]
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    description=description,
                    confidence_score=0.92,
                    evidence={"file": path, **evidence},
                    source_file=path,
                    line=line,
                    deployment_context=context.deployment_context,
                    base_score=base_score,
                    risk_score=round(base_score * context.context_multiplier * 0.92, 3),
                    evaluation_methodology="deterministic_static",
                    remediation=remediation,
                )
            )

        for record in context.iter_files():
            path, content = record.path, record.content
            parsed_document = context.documents.get(path)
            if not isinstance(parsed_document, ParsedDocument):
                parsed_document = parse_file(record)
            if parsed_document.kind == DocumentKind.PYTHON_AST and self._supports(
                "ARGUS_ST_003", path, parsed_document
            ):
                try:
                    tree = parsed_document.value
                    for ast_node in ast.walk(tree):
                        if (
                            isinstance(ast_node, ast.Call)
                            and isinstance(ast_node.func, ast.Name)
                            and ast_node.func.id in {"eval", "exec"}
                        ):
                            add("ARGUS_ST_003", path, {"call": ast_node.func.id}, ast_node.lineno)
                        if (
                            isinstance(ast_node, ast.Call)
                            and isinstance(ast_node.func, ast.Attribute)
                            and ast_node.func.attr == "run"
                        ):
                            safe_literal_args = (
                                bool(ast_node.args)
                                and isinstance(ast_node.args[0], (ast.List, ast.Tuple))
                                and all(
                                    isinstance(item, ast.Constant) and isinstance(item.value, str)
                                    for item in ast_node.args[0].elts
                                )
                            )
                            shell_enabled = any(
                                keyword.arg == "shell"
                                and isinstance(keyword.value, ast.Constant)
                                and keyword.value.value is True
                                for keyword in ast_node.keywords
                            )
                            if (
                                isinstance(ast_node.func.value, ast.Name)
                                and ast_node.func.value.id == "subprocess"
                                and (not safe_literal_args or shell_enabled)
                            ):
                                add(
                                    "ARGUS_ST_003",
                                    path,
                                    {"call": "subprocess.run"},
                                    ast_node.lineno,
                                )  # noqa: E501
                        if (
                            isinstance(ast_node, ast.Call)
                            and isinstance(ast_node.func, ast.Attribute)
                            and ast_node.func.attr in {"unsafe_load", "load"}
                        ):
                            if (
                                isinstance(ast_node.func.value, ast.Name)
                                and ast_node.func.value.id == "yaml"
                            ):
                                add(
                                    "ARGUS_ST_007",
                                    path,
                                    {"call": f"yaml.{ast_node.func.attr}"},
                                    ast_node.lineno,
                                )
                    if re.search(
                        r"(?i)\bimport\s+pickle\b|\bpickle\.loads?\s*\(", content
                    ) and self._supports("ARGUS_ST_007", path, parsed_document):
                        add(
                            "ARGUS_ST_007",
                            path,
                            {"match": "pickle deserialization"},
                            _line_for(content, "pickle"),
                        )
                except SyntaxError:
                    pass
            # Pattern rules intentionally run only on unstructured text.  Structured
            # documents are handled below through parsed key/value nodes.
            if self._supports("ARGUS_ST_008", path, parsed_document) and re.search(
                r"(?i)(?:max_?(?:iterations|loops)|loop_limit|recursion_limit)[\"']?\s*[:=]\s*(?:[1-9][0-9]{2,}|[5-9][0-9])\b",  # noqa: E501
                content,
            ):
                add(
                    "ARGUS_ST_008", path, {"match": "large loop limit"}, _line_for(content, "limit")
                )
            if (
                self._supports("ARGUS_ST_010", path, parsed_document)
                and _SECRET_RE.search(content)
                and not path.lower().endswith((".example", ".sample"))
            ):
                secret_match = _SECRET_RE.search(content)
                if (
                    secret_match
                    and not re.search(r"(?i)(?:[_-]env|environment)\s*[:=]", secret_match.group(0))
                    and not (
                        re.fullmatch(r"[A-Z][A-Z0-9_]+", secret_match.group(1))
                        and "_" in secret_match.group(1)
                    )
                    and secret_match.group(1)
                    not in {
                        "${SECRET}",
                        "${API_KEY}",
                        "changeme",
                        "change-me",
                        "your-secret",
                    }
                ):
                    add(
                        "ARGUS_ST_010",
                        path,
                        {"match": secret_match.group(0).split(":")[0]},
                        _line_for(content, secret_match.group(0)),
                    )
            if self._supports("ARGUS_ST_011", path, parsed_document) and re.search(  # noqa: E501
                r"(?i)pass[_-]?env[\"']?\s*[:=].*[\[\"']\s*\*|environment[\"']?\s*[:=]\s*\*",
                content,
            ):
                add(
                    "ARGUS_ST_011",
                    path,
                    {"match": "all environment variables"},
                    _line_for(content, "pass_env"),
                )
            if self._supports("ARGUS_ST_012", path, parsed_document) and (
                path == ".env" or path.endswith("/.env")
            ):
                add("ARGUS_ST_012", path, {"match": ".env"}, 1)
            if self._supports("ARGUS_ST_005", path, parsed_document) and _TRUST_RE.search(content):
                add(
                    "ARGUS_ST_005",
                    path,
                    {"match": "untrusted input guidance"},
                    _line_for(content, "trust"),
                )
            for match in (
                re.finditer(r"http://[^\s'\"]+", content)
                if self._supports("ARGUS_ST_015", path, parsed_document)
                and parsed_document.kind
                not in {DocumentKind.JSON, DocumentKind.YAML, DocumentKind.TOML}
                else []
            ):
                host = match.group(0).split("//", 1)[1].split("/", 1)[0].split(":", 1)[0]
                if host not in {"localhost", "127.0.0.1", "::1"}:
                    add(
                        "ARGUS_ST_015",
                        path,
                        {"url": match.group(0)},
                        _line_for(content, match.group(0)),
                    )
            for match in (
                _FRAMEWORK_RE.finditer(content)
                if self._supports("ARGUS_ST_014", path, parsed_document)
                else []
            ):
                version = match.group(2) or "unpinned"
                if version == "unpinned" or version.startswith("0."):
                    add(
                        "ARGUS_ST_014",
                        path,
                        {"framework": match.group(1), "version": version},
                        _line_for(content, match.group(1)),
                    )
            if _is_skill_path(path):
                skill_checks = (
                    ("ARGUS_ST_022", _SKILL_AUTHORITY_RE, "authority override"),
                    ("ARGUS_ST_023", _SKILL_COMMAND_RE, "dangerous command"),
                    ("ARGUS_ST_024", _SKILL_SECRET_RE, "secret or broad environment access"),
                    ("ARGUS_ST_025", _SKILL_INSTALL_RE, "unpinned install or clone"),
                    ("ARGUS_ST_026", _SKILL_EXFIL_RE, "external data transfer"),
                )
                for rule_id, pattern, match_name in skill_checks:
                    if self._supports(rule_id, path, parsed_document):
                        skill_match = pattern.search(content)
                        if skill_match:
                            add(
                                rule_id,
                                path,
                                {"match": match_name, "text": skill_match.group(0)[:160]},
                                _line_for(content, skill_match.group(0)),
                            )
                if (
                    self._supports("ARGUS_ST_027", path, parsed_document)
                    and not _skill_has_provenance(context, path)
                    and not re.search(r"(?i)\b(?:verified|integrity|sha256|signature)\b", content)
                ):
                    add(
                        "ARGUS_ST_027",
                        path,
                        {"match": "missing skill provenance metadata"},
                        1,
                    )

        # Schema-aware rules operate on parsed JSON/YAML documents.
        dependency_graph: dict[str, set[str]] = defaultdict(set)
        for path, document, raw, parsed_document in parsed:
            values = list(_iter_values(document))
            for location, value in values:
                key_name = location.rsplit(".", 1)[-1].split("[", 1)[0].lower()
                if (
                    self._supports("ARGUS_ST_001", path, parsed_document)
                    and isinstance(value, str)
                    and ("path" in key_name or "file" in key_name or value in {"*", "/*", "/**"})
                    and re.search(r"(?:/\*{1,2}|\\\*{1,2}|^\*$)", value)
                ):
                    add(
                        "ARGUS_ST_001",
                        path,
                        {"key_path": location, "match": value},
                        parsed_document.line_for(key_name),
                    )
                if (
                    self._supports("ARGUS_ST_005", path, parsed_document)
                    and isinstance(value, str)
                    and _TRUST_RE.search(value)
                ):
                    add(
                        "ARGUS_ST_005",
                        path,
                        {"key_path": location, "match": "untrusted input guidance"},
                        parsed_document.line_for(key_name),
                    )
                if (
                    self._supports("ARGUS_ST_008", path, parsed_document)
                    and isinstance(value, (int, float))
                    and value >= 50
                    and any(term in key_name for term in ("iteration", "loop", "recursion"))
                ):
                    add(
                        "ARGUS_ST_008",
                        path,
                        {"key_path": location, "value": value},
                        parsed_document.line_for(key_name),
                    )
                if (
                    self._supports("ARGUS_ST_010", path, parsed_document)
                    and isinstance(value, str)
                    and (
                        any(
                            term in key_name.replace("_", "")
                            for term in ("secret", "token", "password", "apikey", "privatekey")
                        )
                        or _SECRET_VALUE_RE.search(value) is not None
                    )
                    and not key_name.endswith("env")
                    and not (
                        key_name.replace("_", "") in {"apikey", "token"}
                        and re.fullmatch(r"[A-Z][A-Z0-9_]+", value)
                        and "_" in value
                    )
                    and value
                    not in {"${SECRET}", "${API_KEY}", "changeme", "change-me", "your-secret"}
                    and len(value) >= 8
                ):
                    add(
                        "ARGUS_ST_010",
                        path,
                        {"key_path": location, "match": key_name},
                        parsed_document.line_for(key_name),
                    )
                if (
                    self._supports("ARGUS_ST_015", path, parsed_document)
                    and isinstance(value, str)
                    and value.startswith("http://")
                    and key_name not in {"$schema", "schema_url"}
                    and not value.startswith(("http://localhost", "http://127.0.0.1", "http://::1"))
                ):
                    add(
                        "ARGUS_ST_015",
                        path,
                        {"key_path": location, "url": value},
                        parsed_document.line_for(key_name),
                    )
                if (
                    self._supports("ARGUS_ST_014", path, parsed_document)
                    and isinstance(value, str)
                    and any(
                        framework in key_name
                        for framework in (
                            "langchain",
                            "langgraph",
                            "autogen",
                            "crewai",
                            "semantic_kernel",
                        )
                    )
                    and ("0." in value or value.startswith(("<", "<=", "==")))
                ):
                    add(
                        "ARGUS_ST_014",
                        path,
                        {"key_path": location, "framework": key_name, "version": value},
                        parsed_document.line_for(key_name),
                    )
                if isinstance(value, dict):
                    name = str(value.get("name", location))
                    description = str(value.get("description", ""))
                    combined = f"{name} {description} {json.dumps(value, default=str)}"
                    for key, child in value.items():
                        if key.lower().replace("-", "_") in {
                            "pass_env",
                            "environment",
                            "env",
                        }:
                            if child == "*" or (isinstance(child, list) and "*" in child):
                                add(  # noqa: E501
                                    "ARGUS_ST_011",
                                    path,
                                    {"match": "all environment variables"},
                                    _line_for(raw, key),
                                )
                            if isinstance(child, dict) and "*" in child:
                                add(
                                    "ARGUS_ST_011",
                                    path,
                                    {"match": "all environment variables"},
                                    _line_for(raw, key),
                                )
                    if self._supports("ARGUS_ST_016", path, parsed_document):
                        for key, child in value.items():
                            normalized_key = key.lower().replace("-", "_")
                            if normalized_key not in _BROAD_SCOPE_KEYS:
                                continue
                            candidates = child if isinstance(child, list) else [child]
                            broad = next(
                                (
                                    candidate
                                    for candidate in candidates
                                    if isinstance(candidate, str)
                                    and candidate.lower() in _BROAD_PERMISSION_VALUES
                                ),
                                None,
                            )
                            if broad is not None:
                                add(
                                    "ARGUS_ST_016",
                                    path,
                                    {"key_path": location + "." + key, "permission": broad},
                                    _line_for(raw, key),
                                )
                            if (
                                normalized_key == "elevated"
                                and isinstance(child, dict)
                                and child.get("enabled") is True
                            ):
                                add(
                                    "ARGUS_ST_016",
                                    path,
                                    {"key_path": location + "." + key, "permission": "elevated"},
                                    _line_for(raw, key),
                                )
                    if self._supports("ARGUS_ST_017", path, parsed_document):
                        is_tool = (
                            any(
                                key.lower().replace("-", "_")
                                in {"name", "tool", "tool_name", "input_schema", "inputschema"}
                                for key in value
                            )
                            or ".tools" in location.lower()
                        )
                        approval = any(
                            key.lower().replace("-", "_")
                            in {
                                "require_approval",
                                "approval",
                                "approval_required",
                                "human_approval",
                            }
                            and bool(child)
                            for key, child in value.items()
                        )
                        if is_tool and not approval and _HIGH_IMPACT_RE.search(combined):
                            impact_match = _HIGH_IMPACT_RE.search(combined)
                            add(
                                "ARGUS_ST_017",
                                path,
                                {
                                    "tool": name,
                                    "operation": (
                                        impact_match.group(0)
                                        if impact_match
                                        else "high-impact action"
                                    ),
                                },
                                _line_for(raw, name),
                            )
                    if self._supports("ARGUS_ST_018", path, parsed_document):
                        for key, child in value.items():
                            normalized_key = key.lower().replace("-", "_")
                            if normalized_key not in _NETWORK_SCOPE_KEYS:
                                continue
                            candidates = child if isinstance(child, list) else [child]
                            broad = next(
                                (
                                    candidate
                                    for candidate in candidates
                                    if isinstance(candidate, str)
                                    and candidate.lower() in _BROAD_PERMISSION_VALUES
                                ),
                                None,
                            )
                            if broad is not None:
                                add(
                                    "ARGUS_ST_018",
                                    path,
                                    {"key_path": location + "." + key, "destination": broad},
                                    _line_for(raw, key),
                                )
                    if self._supports("ARGUS_ST_019", path, parsed_document):
                        command = value.get("command")
                        arguments = value.get("args", value.get("arguments", []))
                        command_name = Path(str(command)).name if command else ""
                        argument_text = (
                            " ".join(str(item) for item in arguments)
                            if isinstance(arguments, list)
                            else str(arguments)
                        )
                        package_is_pinned = re.search(
                            r"(?:@[0-9]+\.[0-9]+(?:\.[0-9]+)?|@[A-Za-z0-9_.-]+@[0-9]"
                            r"|==[0-9]|#[0-9a-f]{7,}|sha256[:=][0-9a-f]{12,})",
                            argument_text,
                        )
                        if command_name in _PACKAGE_RUNNERS and not package_is_pinned:
                            add(
                                "ARGUS_ST_019",
                                path,
                                {"command": command_name, "arguments": argument_text[:240]},
                                _line_for(raw, str(command)),
                            )
                    if self._supports("ARGUS_ST_020", path, parsed_document):
                        for key in ("host", "bind", "bind_host", "listen", "address"):
                            candidate = value.get(key)
                            if candidate in {"0.0.0.0", "::", "[::]"}:
                                add(
                                    "ARGUS_ST_020",
                                    path,
                                    {"key_path": location + "." + key, "address": candidate},
                                    _line_for(raw, key),
                                )
                    if self._supports("ARGUS_ST_021", path, parsed_document):
                        for key, child in value.items():
                            normalized_key = key.lower().replace("-", "_")
                            if (
                                normalized_key
                                in {
                                    "verify_ssl",
                                    "ssl_verify",
                                    "tls_verify",
                                    "reject_unauthorized",
                                }
                                and child is False
                            ):
                                add(
                                    "ARGUS_ST_021",
                                    path,
                                    {"key_path": location + "." + key, "value": False},
                                    _line_for(raw, key),
                                )
                    destructive_match = _DESTRUCTIVE_RE.search(combined)  # noqa: E501
                    if destructive_match and self._supports("ARGUS_ST_004", path, parsed_document):
                        approval = any(
                            key.lower()
                            in {
                                "require_approval",
                                "approval",
                                "approval_required",
                                "human_approval",
                            }
                            and bool(child)
                            for key, child in value.items()
                        )
                        if not approval:
                            add(
                                "ARGUS_ST_004",
                                path,
                                {
                                    "tool": name,
                                    "operation": destructive_match.group(0),
                                },
                                _line_for(raw, name),
                            )
                            if self._supports("ARGUS_ST_006", path, parsed_document):
                                add("ARGUS_ST_006", path, {"tool": name}, _line_for(raw, name))
                    if self._supports("ARGUS_ST_002", path, parsed_document) and {
                        key.lower() for key in value
                    }.intersection({"inputschema", "schema", "parameters"}):
                        schema = value.get(
                            "inputSchema", value.get("schema", value.get("parameters", {}))
                        )
                        properties = (
                            schema.get("properties", {}) if isinstance(schema, dict) else {}
                        )
                        if (
                            isinstance(properties, dict)
                            and properties
                            and not any(
                                isinstance(prop, dict)
                                and (
                                    "pattern" in prop
                                    or "enum" in prop
                                    or "minimum" in prop
                                    or "maxLength" in prop
                                )
                                for prop in properties.values()
                            )
                        ):
                            add(
                                "ARGUS_ST_002",
                                path,
                                {"tool": name, "fields": sorted(properties)},
                                _line_for(raw, name),
                            )
                    dependencies = value.get("depends_on", value.get("dependencies", []))
                    if isinstance(dependencies, list):
                        for dependency in dependencies:
                            dependency_graph[name].add(str(dependency))
                    elif isinstance(dependencies, dict):
                        for dependency, children in dependencies.items():
                            if isinstance(children, list):
                                dependency_graph[str(dependency)].update(
                                    str(child) for child in children
                                )
                    remote = value.get("url", value.get("endpoint", value.get("server")))
                    verification = [
                        child
                        for key, child in value.items()
                        if key.lower()
                        in {
                            "signature",
                            "checksum",
                            "sha256",
                            "verified",
                            "verify",
                            "allowlist",
                        }
                    ]
                    if (
                        self._supports("ARGUS_ST_013", path, parsed_document)
                        and isinstance(remote, str)
                        and _REMOTE_RE.search(remote)
                        and _is_mcp_server_location(location)
                        and not any(verification)
                    ):
                        add("ARGUS_ST_013", path, {"server": remote}, _line_for(raw, remote))
        # Detect cycles with a deterministic DFS.
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str, trail: list[str]) -> None:
            if node in visiting:
                add("ARGUS_ST_009", "<workflow>", {"cycle": trail[trail.index(node) :] + [node]}, 1)
                return
            if node in visited:
                return
            visiting.add(node)
            for child in sorted(dependency_graph.get(node, set())):
                visit(child, trail + [child])
            visiting.remove(node)
            visited.add(node)

        for graph_node in sorted(dependency_graph):
            visit(graph_node, [graph_node])

        findings.sort(
            key=lambda item: (item.rule_id, item.source_file or "", item.line or 0, item.title)
        )
        unique: list[Finding] = []
        seen: set[tuple[str, str | None, int | None]] = set()
        for finding in findings:
            key = (finding.rule_id, finding.source_file, finding.line)
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique


__all__ = ["MCPScanner"]
