"""Authoritative security taxonomy metadata for Argus findings and attacks.

The registry is deliberately code-owned and version-pinned.  Reports, SARIF,
the CLI, and documentation all read this registry so a mapping cannot drift
between outputs.  A missing CWE is intentional: CWE is only emitted where the
relationship is specific enough to defend in a security review.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

OWASP_LLM_EDITION = "2025"
OWASP_AGENTIC_EDITION = "2026"
MITRE_ATLAS_REFERENCE = "live-matrix"


@dataclass(frozen=True)
class TaxonomyEntry:
    identifier: str
    title: str
    owasp_ids: tuple[str, ...] = ()
    atlas_ids: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    status: Literal["implemented", "partial", "not_covered"] = "implemented"
    evidence: tuple[str, ...] = ()
    limitation: str = ""


def _entry(
    identifier: str,
    title: str,
    *,
    owasp: tuple[str, ...] = (),
    atlas: tuple[str, ...] = (),
    cwe: tuple[str, ...] = (),
    status: Literal["implemented", "partial", "not_covered"] = "implemented",
    evidence: tuple[str, ...] = (),
    limitation: str = "",
) -> TaxonomyEntry:
    return TaxonomyEntry(
        identifier=identifier,
        title=title,
        owasp_ids=owasp,
        atlas_ids=atlas,
        cwe_ids=cwe,
        status=status,
        evidence=evidence,
        limitation=limitation,
    )


# OWASP identifiers are kept without the edition suffix in findings.  The
# edition is emitted once in the report metadata and coverage summary.
RULE_TAXONOMY: dict[str, TaxonomyEntry] = {
    "ARGUS_ST_001": _entry(
        "ARGUS_ST_001",
        "Wildcard filesystem access",
        owasp=("LLM06", "ASI02"),
        atlas=("AML.T0052",),
        cwe=("CWE-22",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_002": _entry(
        "ARGUS_ST_002",
        "Missing input sanitization schema",
        owasp=("LLM05", "ASI02"),
        cwe=("CWE-20",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_003": _entry(
        "ARGUS_ST_003",
        "Unsafe code execution",
        owasp=("LLM05", "ASI05"),
        atlas=("AML.T0049",),
        cwe=("CWE-78", "CWE-95"),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_004": _entry(
        "ARGUS_ST_004",
        "Destructive database operation without approval",
        owasp=("LLM06", "ASI02"),
        cwe=("CWE-862",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_005": _entry(
        "ARGUS_ST_005",
        "Blind trust of external input",
        owasp=("LLM01", "LLM08", "ASI01"),
        atlas=("AML.T0051",),
        status="partial",
        evidence=("tests/unit/test_ingress_and_scanner.py",),
        limitation="This static check cannot prove runtime retrieval provenance.",
    ),
    "ARGUS_ST_006": _entry(
        "ARGUS_ST_006",
        "Missing destructive-action approval gate",
        owasp=("LLM06", "ASI02"),
        cwe=("CWE-862",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_007": _entry(
        "ARGUS_ST_007",
        "Unsafe deserialization",
        owasp=("LLM05", "ASI05"),
        atlas=("AML.T0049",),
        cwe=("CWE-502",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_008": _entry(
        "ARGUS_ST_008",
        "Excessive autonomy loop limit",
        owasp=("LLM10", "ASI08"),
        cwe=("CWE-400",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_009": _entry(
        "ARGUS_ST_009",
        "Circular tool dependency",
        owasp=("LLM10", "ASI08"),
        cwe=("CWE-835",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_010": _entry(
        "ARGUS_ST_010",
        "Hardcoded credential",
        owasp=("LLM02", "ASI03"),
        cwe=("CWE-798",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_011": _entry(
        "ARGUS_ST_011",
        "Broad environment ingestion",
        owasp=("LLM02", "ASI03"),
        cwe=("CWE-200",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_012": _entry(
        "ARGUS_ST_012",
        "Unencrypted dotenv file",
        owasp=("LLM02", "ASI03"),
        cwe=("CWE-798",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_013": _entry(
        "ARGUS_ST_013",
        "Unverified remote MCP server",
        owasp=("LLM03", "ASI04"),
        atlas=("AML.T0046",),
        status="partial",
        evidence=("tests/unit/test_ingress_and_scanner.py",),
        limitation=(
            "Argus checks declared verification metadata; it does not verify "
            "a registry signature."
        ),
    ),
    "ARGUS_ST_014": _entry(
        "ARGUS_ST_014",
        "Outdated agent framework",
        owasp=("LLM03", "ASI04"),
        cwe=("CWE-1104",),
        status="partial",
        evidence=("tests/unit/test_ingress_and_scanner.py",),
        limitation="The baseline is heuristic and is not a complete dependency advisory feed.",
    ),
    "ARGUS_ST_015": _entry(
        "ARGUS_ST_015",
        "Insecure HTTP endpoint",
        owasp=("LLM03", "LLM02"),
        cwe=("CWE-319",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_016": _entry(
        "ARGUS_ST_016",
        "Wildcard or administrative agent permission",
        owasp=("LLM06", "ASI02", "ASI03"),
        atlas=("AML.T0052",),
        cwe=("CWE-250",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_017": _entry(
        "ARGUS_ST_017",
        "High-impact MCP tool without approval",
        owasp=("LLM06", "ASI02"),
        atlas=("AML.T0052",),
        cwe=("CWE-862",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_018": _entry(
        "ARGUS_ST_018",
        "Unrestricted MCP network egress",
        owasp=("LLM06", "ASI02"),
        atlas=("AML.T0048",),
        status="partial",
        evidence=("tests/unit/test_ingress_and_scanner.py",),
        limitation="Static configuration analysis does not validate the live network boundary.",
    ),
    "ARGUS_ST_019": _entry(
        "ARGUS_ST_019",
        "Unpinned MCP package command",
        owasp=("LLM03", "ASI04"),
        cwe=("CWE-1104",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_020": _entry(
        "ARGUS_ST_020",
        "MCP service bound publicly",
        owasp=("LLM06", "ASI02"),
        cwe=("CWE-668",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_021": _entry(
        "ARGUS_ST_021",
        "TLS certificate verification disabled",
        owasp=("LLM03", "LLM02"),
        cwe=("CWE-295",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_022": _entry(
        "ARGUS_ST_022",
        "Skill attempts to override agent authority",
        owasp=("LLM01", "ASI01"),
        atlas=("AML.T0051",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_023": _entry(
        "ARGUS_ST_023",
        "Skill contains dangerous command execution",
        owasp=("LLM05", "LLM06", "ASI02", "ASI05"),
        atlas=("AML.T0049",),
        cwe=("CWE-78",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_024": _entry(
        "ARGUS_ST_024",
        "Skill requests secrets or broad environment access",
        owasp=("LLM02", "ASI03"),
        cwe=("CWE-200",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_025": _entry(
        "ARGUS_ST_025",
        "Skill installs unpinned remote code",
        owasp=("LLM03", "ASI04"),
        cwe=("CWE-1104",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_026": _entry(
        "ARGUS_ST_026",
        "Skill sends data to an external destination",
        owasp=("LLM02", "LLM06", "ASI02", "ASI03"),
        atlas=("AML.T0048",),
        evidence=("tests/unit/test_ingress_and_scanner.py",),
    ),
    "ARGUS_ST_027": _entry(
        "ARGUS_ST_027",
        "Skill provenance is not verifiable",
        owasp=("LLM03", "ASI04"),
        status="partial",
        evidence=("tests/unit/test_ingress_and_scanner.py",),
        limitation=(
            "Presence of local provenance metadata is not equivalent to a "
            "trusted signature service."
        ),
    ),
    "ARGUS_ST_028": _entry(
        "ARGUS_ST_028",
        "Retrieved context lacks a trust boundary",
        owasp=("LLM04", "LLM08", "ASI06"),
        atlas=("AML.T0051.001",),
        status="partial",
        evidence=(
            "tests/unit/test_ingress_and_scanner.py",
            "tests/integration/test_indirect_injection.py",
        ),
        limitation=(
            "A declaration check cannot validate the quality or provenance "
            "of the retrieved corpus."
        ),
    ),
    "ARGUS_ST_029": _entry(
        "ARGUS_ST_029",
        "Tool output is trusted without validation",
        owasp=("LLM05", "LLM06", "ASI02"),
        cwe=("CWE-20",),
        status="partial",
        evidence=("tests/unit/test_ingress_and_scanner.py",),
        limitation=(
            "The rule catches explicit unsafe settings; absence of a setting "
            "is not treated as proof of vulnerability."
        ),
    ),
}


ATTACK_TAXONOMY: dict[str, TaxonomyEntry] = {
    "prompt_injection": _entry(
        "prompt_injection",
        "Direct prompt injection",
        owasp=("LLM01", "ASI01"),
        atlas=("AML.T0051",),
        status="partial",
        evidence=("tests/unit/test_indirect_injection.py",),
        limitation=(
            "The deterministic corpus is bounded and does not prove resistance "
            "to all jailbreaks."
        ),
    ),
    "jailbreak": _entry(
        "jailbreak",
        "Jailbreak and safety-boundary evasion",
        owasp=("LLM01", "ASI01"),
        atlas=("AML.T0054",),
        status="partial",
        evidence=("tests/unit/test_indirect_injection.py",),
        limitation="This is response-signal testing, not a guarantee against adaptive adversaries.",
    ),
    "data_extraction": _entry(
        "data_extraction",
        "Sensitive data and system-prompt extraction",
        owasp=("LLM02", "LLM07"),
        atlas=("AML.T0056",),
        status="partial",
        evidence=("tests/unit/test_indirect_injection.py",),
        limitation=(
            "Detection is based on bounded response signals; it does not "
            "inspect provider-side logs."
        ),
    ),
    "indirect_prompt_injection": _entry(
        "indirect_prompt_injection",
        "Indirect prompt injection through retrieved context",
        owasp=("LLM01", "LLM06", "LLM08", "ASI01", "ASI02"),
        atlas=("AML.T0051.001",),
        status="implemented",
        evidence=("tests/integration/test_indirect_injection.py",),
        limitation=(
            "The built-in demo uses deterministic local retrieval; live RAG "
            "connectors remain opt-in adapters."
        ),
    ),
}


OWASP_LLM_CATEGORIES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

OWASP_AGENTIC_CATEGORIES: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}


def taxonomy_for_rule(rule_id: str) -> TaxonomyEntry:
    return RULE_TAXONOMY.get(
        rule_id,
        _entry(
            rule_id,
            "Unmapped rule",
            status="not_covered",
            limitation="No authoritative mapping has been reviewed yet.",
        ),
    )


def taxonomy_for_attack(module_id: str) -> TaxonomyEntry:
    return ATTACK_TAXONOMY.get(
        module_id,
        _entry(
            module_id,
            "Unmapped attack module",
            status="not_covered",
            limitation="No authoritative mapping has been reviewed yet.",
        ),
    )


def taxonomy_as_dict(entry: TaxonomyEntry) -> dict[str, object]:
    return {
        "identifier": entry.identifier,
        "title": entry.title,
        "owasp_ids": list(entry.owasp_ids),
        "atlas_ids": list(entry.atlas_ids),
        "cwe_ids": list(entry.cwe_ids),
        "status": entry.status,
        "evidence": list(entry.evidence),
        "limitation": entry.limitation,
    }


def coverage_summary(
    rule_ids: list[str] | tuple[str, ...], attack_ids: list[str] | tuple[str, ...]
) -> dict[str, object]:
    entries = [taxonomy_for_rule(item) for item in rule_ids] + [
        taxonomy_for_attack(item) for item in attack_ids
    ]
    owasp_ids = sorted({identifier for entry in entries for identifier in entry.owasp_ids})
    atlas_ids = sorted({identifier for entry in entries for identifier in entry.atlas_ids})
    cwe_ids = sorted({identifier for entry in entries for identifier in entry.cwe_ids})
    return {
        "owasp_llm": {
            "edition": OWASP_LLM_EDITION,
            "tested": [item for item in owasp_ids if item in OWASP_LLM_CATEGORIES],
            "not_covered": [item for item in OWASP_LLM_CATEGORIES if item not in owasp_ids],
        },
        "owasp_agentic": {
            "edition": OWASP_AGENTIC_EDITION,
            "tested": [item for item in owasp_ids if item in OWASP_AGENTIC_CATEGORIES],
            "not_covered": [item for item in OWASP_AGENTIC_CATEGORIES if item not in owasp_ids],
        },
        "mitre_atlas": {"reference": MITRE_ATLAS_REFERENCE, "mapped": atlas_ids},
        "cwe": {"mapped": cwe_ids},
        "rule_ids": sorted(set(rule_ids)),
        "attack_modules": sorted(set(attack_ids)),
    }


__all__ = [
    "ATTACK_TAXONOMY",
    "MITRE_ATLAS_REFERENCE",
    "OWASP_AGENTIC_CATEGORIES",
    "OWASP_AGENTIC_EDITION",
    "OWASP_LLM_CATEGORIES",
    "OWASP_LLM_EDITION",
    "RULE_TAXONOMY",
    "TaxonomyEntry",
    "coverage_summary",
    "taxonomy_as_dict",
    "taxonomy_for_attack",
    "taxonomy_for_rule",
]
