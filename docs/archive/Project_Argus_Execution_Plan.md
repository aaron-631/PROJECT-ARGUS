> **Historical Document** — This execution plan has been completed. See [README.md](../README.md) for current project status.


# Project Argus: Execution & Engineering Plan

As your Lead Enterprise Software Engineer and Cybersecurity/ML Architect, I have reviewed the `README.md`, `argus-framework-final.md`, and `Argus_DO_Integration_Plan.md`. 

The architecture is exceptionally well thought out. Transitioning from "AI security as prompt testing" to **"AI security as infrastructural and agentic validation"** is the right enterprise play. We will build this to be deterministic, extensible, GDPR-aligned, and deeply modular.

Here is the structured engineering plan to bring **Argus V1** to completion, adhering to strict enterprise software principles (SOLID, DRY, dependency injection via the Registry).

---

## 🏗️ Phase 1: Core Foundations & Interface Enforcement
*Status in codebase: Stubbed, needs robust implementation.*

**Goal:** Establish the unbreakable contracts that all modules will use, and build the data ingestion layer.
1.  **Data Models (`src/models/`)**: Replace `.json` stubs with strict **Pydantic** models (`Finding`, `ScanContext`, `AttackResult`). This guarantees type safety across the async boundaries.
2.  **Interface Contracts (`src/interfaces/`)**: Solidify `BaseAttackModule`, `BaseStaticScanner`, `JudgeBackend`, and `BaseExporter` with Python `abc` (Abstract Base Classes) and strict type hints.
3.  **Module Registry (`src/core/registry.py`)**: Implement the decorator-based registration system (`@register_scanner`, `@register_attack`). This prevents tight coupling.
4.  **Ingress Engine (`src/core/ingress.py`)**: Implement secure Git cloning (hook-disabled) and local directory traversal, normalizing everything into the `ScanContext`.
5.  **Configuration Layer**: Wire up `argus.py` to parse `config/profiles/` and hydrate the application state.

---

## 🛡️ Phase 2: Static Security Engine (The Bread & Butter)
*Status in codebase: Planned.*

**Goal:** Build the deterministic rule engine and the 15 canonical scanners.
1.  **Scanner Pipeline (`src/core/evaluation.py`)**: The orchestrator that takes a `ScanContext` and runs registered static scanners concurrently.
2.  **MCP & Tool Scanners (`src/modules/scanners/`)**:
    *   `ARGUS_ST_001` - `ARGUS_ST_005`: File path wildcards, `eval()` detection, destructive DB commands, schema validation.
3.  **Workflow & Env Scanners**:
    *   `ARGUS_ST_006` - `ARGUS_ST_012`: Missing approval gates, unsafe deserialization (pickle/yaml), hardcoded secrets, broad env ingestion.
4.  **Dependencies & Network**:
    *   `ARGUS_ST_013` - `ARGUS_ST_015`: Unverified remote MCPs, outdated agent frameworks, HTTP usage.

---

## ⚔️ Phase 3: Async Attack Engine & Dynamic Evaluation
*Status in codebase: Planned.*

**Goal:** Safely probe LLM endpoints with real network resilience and calculate enterprise risk scores.
1.  **Async Orchestrator (`src/core/engine.py`)**: Implement `asyncio` execution with a Token-Bucket rate limiter and exponential backoff for `429 Too Many Requests`.
2.  **Attack Modules (`src/modules/attacks/`)**:
    *   `PromptInjectionModule`: System override, context smuggling.
    *   `JailbreakModule`: Obfuscation, adversarial suffixes.
    *   `ExtractionModule`: System prompt leakage, synthetic PII extraction.
3.  **Risk Matrix Engine (`src/core/risk_engine.py`)**: Implement the Argus Formula `R = (S_base × C_env) × P_conf`.
4.  **Judge Backends (`src/interfaces/judge.py`)**: Build the `NullJudgeBackend` (default), `MockJudgeBackend` (testing), and `APIJudgeBackend` (semantic). 

---

## 🔒 Phase 4: Sanitization, Reporting & Enterprise Polish
*Status in codebase: Planned.*

**Goal:** Ensure zero data leakage and produce the artifacts enterprises pay for.
1.  **Data Sanitization & Vault (`src/core/sanitization.py`)**: Strip control characters and implement the AES-256-GCM payload vault for sensitive findings.
2.  **Exporters (`src/interfaces/exporter.py`)**: Build the JSON and Markdown report generators. The Markdown report must be beautiful, actionable, and include the `evaluation_methodology`.
3.  **Testing & Mocking (`tests/mock_server.py`)**: Build out the deterministic local mock server so the CI/CD pipeline requires no hosted model or external service.
4.  **Containerization**: Finalize the `Dockerfile` and `docker-compose.yml` for seamless enterprise deployment.

---

## 🚀 Execution Strategy

To execute this massive undertaking efficiently, I highly recommend we use a structured workflow. 

Since you requested "plan mode", you can officially kick off this exact plan by using the **`/plan`** slash command in our chat, or if you want me to autonomously tackle this entire multi-phase project end-to-end without stopping, you can use the **`/goal`** command. If you want a swarm of agents to work on different phases concurrently, **`/teamwork-preview`** is also an excellent option.

How would you like to proceed? We can start with Phase 1 immediately.
