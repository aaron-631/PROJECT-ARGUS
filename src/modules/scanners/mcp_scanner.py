"""Deterministic implementation of Argus' 15 canonical static rules."""

from __future__ import annotations

import ast
import json
import re
from collections import defaultdict
from typing import Any, Iterable

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
                if secret_match and secret_match.group(1) not in {
                    "${SECRET}",
                    "${API_KEY}",
                    "changeme",
                    "change-me",
                    "your-secret",
                }:
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
                        if key.lower().replace("-", "_") in {"pass_env", "environment"}:
                            if child == "*" or (isinstance(child, list) and "*" in child):
                                add(  # noqa: E501
                                    "ARGUS_ST_011",
                                    path,
                                    {"match": "all environment variables"},
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
