# Argus security coverage matrix

This is the authoritative coverage explanation for Argus. The executable
registry is [`src/core/taxonomy.py`](../src/core/taxonomy.py); the Markdown,
JSON, SARIF, and `argus rules --compliance` outputs use that registry. A
mapping means Argus has a relevant check or probe. It does not mean Argus
proves the whole OWASP category is secure.

## Standards pinned by this release

- OWASP Top 10 for LLM Applications **2025**. The identifiers below are
  rendered as `LLM01` in reports and the edition is carried separately.
- OWASP Top 10 for Agentic Applications **2026**. Agentic identifiers are
  rendered as `ASI01` to `ASI10`.
- MITRE ATLAS is a living matrix. The IDs below were reviewed against the
  public matrix when this release was prepared; they are emitted as mappings,
  not as a claim of full ATLAS compliance.
- CWE is included only where the relationship is specific enough to defend.
  An empty CWE column is deliberate.

References: [OWASP LLM Top 10 2025](https://genai.owasp.org/llm-top-10/),
[OWASP Agentic Top 10](https://genai.owasp.org/initiatives/agentic-security-initiative/),
and [MITRE ATLAS](https://atlas.mitre.org/).

## OWASP LLM coverage

| ID | Category | Argus surface | Honest status |
|---|---|---|---|
| LLM01 | Prompt Injection | ST_005, ST_022, direct and indirect probes | Partial: bounded corpus and local RAG proof |
| LLM02 | Sensitive Information Disclosure | ST_010–ST_012, ST_024, ST_026, extraction probes, runtime redaction | Partial: deterministic patterns, not a universal DLP engine |
| LLM03 | Supply Chain | ST_013–ST_015, ST_019, ST_021, ST_025, ST_027 | Partial: declared metadata and pinning heuristics |
| LLM04 | Data and Model Poisoning | ST_028, retrieved-document probe | Partial: configuration and context-boundary checks, not training-data analysis |
| LLM05 | Improper Output Handling | ST_002, ST_003, ST_007, ST_023, ST_029 | Partial: explicit unsafe settings and Python checks |
| LLM06 | Excessive Agency | ST_001, ST_004, ST_006, ST_016–ST_018, ST_023, ST_026, indirect probe | Partial: declared permissions and tool boundary |
| LLM07 | System Prompt Leakage | ST_010, data-extraction probes | Partial: response signals only |
| LLM08 | Vector and Embedding Weaknesses | ST_005, ST_028, indirect retrieved-context probe | Partial: no vector database quality or access-control audit |
| LLM09 | Misinformation | No dedicated check | Not covered |
| LLM10 | Unbounded Consumption | ST_008, ST_009 | Partial: loop and dependency heuristics, no cost/provider quota analysis |

## OWASP Agentic coverage

| ID | Category | Argus surface |
|---|---|---|
| ASI01 | Agent Goal Hijack | ST_005, ST_022, direct/indirect probes |
| ASI02 | Tool Misuse and Exploitation | permissions, approvals, egress checks, indirect tool-boundary proof |
| ASI03 | Identity and Privilege Abuse | secrets, environment, permissions, and skill checks |
| ASI04 | Agentic Supply Chain Vulnerabilities | remote MCP, pinning, framework, skill provenance |
| ASI05 | Unexpected Code Execution | ST_003, ST_007, ST_023 |
| ASI06 | Memory and Context Poisoning | ST_028 and retrieved-context probe; partial |
| ASI07 | Insecure Inter-Agent Communication | No dedicated check; not covered |
| ASI08 | Cascading Failures | loop/cycle checks; partial |
| ASI09 | Human-Agent Trust Exploitation | No dedicated check; not covered |
| ASI10 | Rogue Agents | No dedicated check; not covered |

## Static rule mapping

`implemented` means the rule has deterministic detection and tests. `partial`
means the check is intentionally bounded and cannot validate a live provider or
external trust service.

| Rule | OWASP | MITRE ATLAS | CWE | Status / evidence |
|---|---|---|---|---|
| ARGUS_ST_001 | LLM06, ASI02 | AML.T0052 | CWE-22 | implemented |
| ARGUS_ST_002 | LLM05, ASI02 | — | CWE-20 | implemented |
| ARGUS_ST_003 | LLM05, ASI05 | AML.T0049 | CWE-78, CWE-95 | implemented |
| ARGUS_ST_004 | LLM06, ASI02 | — | CWE-862 | implemented |
| ARGUS_ST_005 | LLM01, LLM08, ASI01 | AML.T0051 | — | partial; static text only |
| ARGUS_ST_006 | LLM06, ASI02 | — | CWE-862 | implemented |
| ARGUS_ST_007 | LLM05, ASI05 | AML.T0049 | CWE-502 | implemented |
| ARGUS_ST_008 | LLM10, ASI08 | — | CWE-400 | implemented |
| ARGUS_ST_009 | LLM10, ASI08 | — | CWE-835 | implemented |
| ARGUS_ST_010 | LLM02, ASI03 | — | CWE-798 | implemented |
| ARGUS_ST_011 | LLM02, ASI03 | — | CWE-200 | implemented |
| ARGUS_ST_012 | LLM02, ASI03 | — | CWE-798 | implemented |
| ARGUS_ST_013 | LLM03, ASI04 | AML.T0046 | — | partial; metadata declaration only |
| ARGUS_ST_014 | LLM03, ASI04 | — | CWE-1104 | partial; heuristic baseline |
| ARGUS_ST_015 | LLM03, LLM02 | — | CWE-319 | implemented |
| ARGUS_ST_016 | LLM06, ASI02, ASI03 | AML.T0052 | CWE-250 | implemented |
| ARGUS_ST_017 | LLM06, ASI02 | AML.T0052 | CWE-862 | implemented |
| ARGUS_ST_018 | LLM06, ASI02 | AML.T0048 | — | partial; static egress declaration |
| ARGUS_ST_019 | LLM03, ASI04 | — | CWE-1104 | implemented |
| ARGUS_ST_020 | LLM06, ASI02 | — | CWE-668 | implemented |
| ARGUS_ST_021 | LLM03, LLM02 | — | CWE-295 | implemented |
| ARGUS_ST_022 | LLM01, ASI01 | AML.T0051 | — | implemented |
| ARGUS_ST_023 | LLM05, LLM06, ASI02, ASI05 | AML.T0049 | CWE-78 | implemented |
| ARGUS_ST_024 | LLM02, ASI03 | — | CWE-200 | implemented |
| ARGUS_ST_025 | LLM03, ASI04 | — | CWE-1104 | implemented |
| ARGUS_ST_026 | LLM02, LLM06, ASI02, ASI03 | AML.T0048 | — | implemented |
| ARGUS_ST_027 | LLM03, ASI04 | — | — | partial; local provenance metadata |
| ARGUS_ST_028 | LLM04, LLM08, ASI06 | AML.T0051.001 | — | partial; retrieval trust-boundary declaration |
| ARGUS_ST_029 | LLM05, LLM06, ASI02 | — | CWE-20 | partial; explicit unsafe setting only |

Evidence paths in the registry point to the scanner tests and the isolated
indirect-injection integration test. Use `pytest -q` to reproduce them.

## Dynamic attack mapping

| Module | OWASP | MITRE ATLAS | Evidence | Limitation |
|---|---|---|---|---|
| prompt_injection | LLM01, ASI01 | AML.T0051 | hashed 1.1.0 corpus | bounded response signals |
| jailbreak | LLM01, ASI01 | AML.T0054 | hashed 1.1.0 corpus | not adaptive red teaming |
| data_extraction | LLM02, LLM07 | AML.T0056 | hashed 1.1.0 corpus | no provider-side inspection |
| indirect_prompt_injection | LLM01, LLM06, LLM08, ASI01, ASI02 | AML.T0051.001 | `tests/integration/test_indirect_injection.py` and local demo | live RAG connectors are opt-in |

## What “covered” does not mean

Argus is a bounded pre-deployment scanner and runtime policy component. A
passing report does not certify a model, a provider, a vector store, a live MCP
server, or an organization against the full standards. Dynamic probing must be
authorized, and host-level RCE is deliberately not executed. The strongest
claim supported by this matrix is that Argus emits traceable mappings and has
reproducible checks for the surfaces listed above.
