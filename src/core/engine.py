"""Async Argus orchestration engine."""

from __future__ import annotations

import asyncio
from hashlib import sha256
from typing import Any

from src.core.evaluation import EvaluationPipeline
from src.core.rate_limiter import TokenBucketRateLimiter, parse_retry_after
from src.core.sanitization import sanitize, sanitize_value
from src.core.registry import get_enabled_modules, plugin_errors
from src.core.target_client import HTTPTargetClient, TargetClient, resolve_api_key
from src.core.taxonomy import coverage_summary, taxonomy_for_attack, taxonomy_for_rule
from src.interfaces.judge import HTTPJudgeBackend, MockJudgeBackend, NullJudgeBackend
from src.models import SEVERITY_ORDER, AttackProbe, AttackResult, Finding, ScanContext
from src.models.config import ArgusConfig
from src.modules.attacks.dataset import dataset_version
from src import __version__


class ArgusEngine:
    """Coordinate static scanners and explicitly enabled dynamic attacks."""

    def __init__(
        self, config: dict[str, Any] | ArgusConfig, target_client: TargetClient | None = None
    ) -> None:
        self.config = (
            config if isinstance(config, ArgusConfig) else ArgusConfig.model_validate(config)
        )
        self.target_client = target_client
        self._errors: list[str] = []
        self._suppressed_rules: list[str] = []

    def _judge(self):
        name = self.config.judge.backend
        if name == "MockJudgeBackend":
            return MockJudgeBackend()
        if name in {"HTTPJudgeBackend", "APIJudgeBackend"} and self.config.judge.endpoint:
            api_key = None
            if self.config.judge.api_key_env:
                import os

                api_key = os.getenv(self.config.judge.api_key_env)
            return HTTPJudgeBackend(
                self.config.judge.endpoint,
                model=self.config.judge.model,
                api_key=api_key,
                headers=self.config.judge.headers,
                timeout_seconds=self.config.engine.timeout_seconds,
                max_response_bytes=self.config.engine.max_http_response_bytes,
            )
        return NullJudgeBackend()

    async def _run_scanners(
        self, context: ScanContext, registry: dict[str, dict[str, type[Any]]]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for scanner_id, scanner_cls in registry["scanners"].items():
            try:
                findings.extend(scanner_cls().scan(context))
            except Exception as exc:
                # A plugin failure is represented as no finding; callers still
                # get a complete report and can inspect the engine error list.
                # The cause is included because "ValidationError" alone leaves a
                # plugin author with nothing to act on.
                detail = sanitize(" ".join(str(exc).split()))[:300]
                self._errors.append(f"scanner {scanner_id}: {type(exc).__name__}: {detail}")
        disabled = set(getattr(self.config, "disabled_rules", []))
        if disabled:
            self._suppressed_rules = sorted({f.rule_id for f in findings if f.rule_id in disabled})
            findings = [f for f in findings if f.rule_id not in disabled]
        findings = [
            item.model_copy(
                update={
                    "owasp_ids": item.owasp_ids or list(taxonomy_for_rule(item.rule_id).owasp_ids),
                    "atlas_ids": item.atlas_ids or list(taxonomy_for_rule(item.rule_id).atlas_ids),
                    "cwe_ids": item.cwe_ids or list(taxonomy_for_rule(item.rule_id).cwe_ids),
                }
            )
            for item in findings
        ]
        return sorted(
            findings, key=lambda item: (item.rule_id, item.source_file or "", item.line or 0)
        )

    def _inventory(
        self, context: ScanContext, registry: dict[str, dict[str, type[Any]]]
    ) -> dict[str, Any]:
        inventory: dict[str, Any] = {"mcp_servers": [], "mcp_tools": [], "skills": []}
        for scanner_id, scanner_cls in registry["scanners"].items():
            collect = getattr(scanner_cls, "inventory", None)
            if collect is None:
                continue
            try:
                discovered = collect(context)
                for key in inventory:
                    inventory[key].extend(discovered.get(key, []))
            except Exception as exc:
                self._errors.append(f"scanner inventory {scanner_id}: {type(exc).__name__}")
        for key in inventory:
            inventory[key] = sorted(
                inventory[key], key=lambda item: (item.get("file", ""), item.get("name", ""))
            )
        return inventory

    async def _attack_one(
        self,
        module: Any,
        probe: dict[str, Any],
        limiter: TokenBucketRateLimiter,
        semaphore: asyncio.Semaphore,
        evaluator: EvaluationPipeline,
    ) -> AttackResult:
        async with semaphore:
            response_text = ""
            error: str | None = None
            response_status = 0
            for attempt in range(self.config.engine.max_retries + 1):
                try:
                    await limiter.acquire()
                    client = self.target_client
                    if client is None:
                        raise RuntimeError("target client is not configured")
                    send_probe = getattr(client, "send_probe", None)
                    if callable(send_probe):
                        response = await send_probe(probe, attack_type=module.module_id)
                    else:
                        # Existing custom TargetClient implementations remain
                        # valid; only the built-in adapter consumes metadata.
                        response = await client.send(probe["payload"], attack_type=module.module_id)
                    response_status = response.status_code
                    response_text = response.text
                    if 200 <= response.status_code < 300:
                        error = None
                        break
                    if response.status_code != 429 and response.status_code < 500:
                        error = f"HTTP {response.status_code}"
                        break
                    if response.status_code == 429:
                        retry_after = parse_retry_after(response.headers.get("Retry-After"))
                        limiter.penalize(min(max(retry_after, 0.0), 60.0))
                    if attempt < self.config.engine.max_retries and (
                        response.status_code == 429 or response.status_code >= 500
                    ):
                        await asyncio.sleep(
                            min(
                                60.0,
                                self.config.engine.backoff_base_seconds * (2**attempt),
                            )
                        )
                except Exception as exc:
                    # Exception text can contain endpoint query secrets or model output.
                    error = f"{type(exc).__name__}: request failed"
                    if attempt < self.config.engine.max_retries:
                        await asyncio.sleep(
                            min(60.0, self.config.engine.backoff_base_seconds * (2**attempt))
                        )
                    else:
                        break
            if response_status == 429 or response_status >= 500:
                error = error or (
                    f"HTTP {response_status} after {self.config.engine.max_retries + 1} attempts"
                )
            elif response_status and not 200 <= response_status < 300:
                error = f"HTTP {response_status}"
            if error or (response_status == 0 and not response_text):
                taxonomy = taxonomy_for_attack(module.module_id)
                return AttackResult(
                    module_id=module.module_id,
                    module_version=module.version,
                    attack_type=module.attack_type,
                    payload_id=probe["payload_id"],
                    payload=probe["payload"],
                    raw_response="",
                    canonical_result={"attack_succeeded": False, "signals": []},
                    evaluation_methodology="canonical_only",
                    error=error or "request failed",
                    owasp_ids=list(taxonomy.owasp_ids),
                    atlas_ids=list(taxonomy.atlas_ids),
                    cwe_ids=list(taxonomy.cwe_ids),
                    metadata=self._probe_metadata(probe),
                )
            evaluation = await evaluator.evaluate(
                response_text,
                {
                    "attack_type": module.attack_type,
                    "status_code": response_status,
                    "source_channel": probe.get("metadata", {}).get("source_channel"),
                    "tool_calls": getattr(response, "tool_calls", []),
                },
            )
            taxonomy = taxonomy_for_attack(module.module_id)
            return AttackResult(
                module_id=module.module_id,
                module_version=module.version,
                attack_type=module.attack_type,
                payload_id=probe["payload_id"],
                payload=probe["payload"],
                raw_response="",
                canonical_result={**evaluation["canonical_result"], "http_status": response_status},
                heuristic_score=evaluation["heuristic_score"],
                judge_score=evaluation["judge_score"],
                risk_score=evaluation["risk_score"],
                evaluation_methodology=evaluation["evaluation_methodology"],
                error=error,
                owasp_ids=list(taxonomy.owasp_ids),
                atlas_ids=list(taxonomy.atlas_ids),
                cwe_ids=list(taxonomy.cwe_ids),
                metadata=self._probe_metadata(probe),
            )

    @staticmethod
    def _probe_metadata(probe: dict[str, Any]) -> dict[str, Any]:
        """Keep context provenance while preventing retrieved text in reports."""

        metadata = probe.get("metadata", {})
        if not isinstance(metadata, dict):
            return {}
        result: dict[str, Any] = {}
        source_channel = metadata.get("source_channel")
        if isinstance(source_channel, str):
            result["source_channel"] = source_channel[:80]
        documents = metadata.get("retrieved_documents")
        if isinstance(documents, list) and all(isinstance(item, str) for item in documents):
            joined = "\n\n".join(documents)
            result["retrieved_document_count"] = len(documents)
            result["retrieved_context_sha256"] = sha256(joined.encode("utf-8")).hexdigest()
        dataset_version_value = metadata.get("dataset_version")
        if isinstance(dataset_version_value, str):
            result["dataset_version"] = dataset_version_value
        return result

    async def _run_attacks(
        self, context: ScanContext, registry: dict[str, dict[str, type[Any]]]
    ) -> list[AttackResult]:
        local_dataset_version = dataset_version()
        if local_dataset_version != self.config.dataset_version:
            raise ValueError(
                f"configured dataset version {self.config.dataset_version} does not match "
                f"local dataset {local_dataset_version}"
            )
        endpoint = context.target_endpoint or self.config.target_endpoint
        if not endpoint and self.target_client is None:
            return []
        if self.target_client is None:
            if endpoint is None:
                raise RuntimeError("dynamic attacks require a target endpoint")
            self.target_client = HTTPTargetClient(
                endpoint,
                self.config.engine.timeout_seconds,
                target=self.config.target,
                api_key=resolve_api_key(self.config.target),
                max_response_bytes=self.config.engine.max_http_response_bytes,
            )
        limiter = TokenBucketRateLimiter(self.config.engine.rate_limit_rps)
        semaphore = asyncio.Semaphore(self.config.engine.max_concurrent_attacks)
        evaluator = EvaluationPipeline(self._judge(), self.config.c_env)
        tasks = []
        for module_cls in registry["attack_modules"].values():
            module = module_cls()
            try:
                probes = await self._module_probes(module, endpoint)
            except Exception as exc:
                detail = sanitize(" ".join(str(exc).split()))[:300]
                self._errors.append(
                    f"attack module {module.module_id}: {type(exc).__name__}: {detail}"
                )
                continue
            for probe in probes:
                tasks.append(self._attack_one(module, probe, limiter, semaphore, evaluator))
        results = await asyncio.gather(*tasks) if tasks else []
        return sorted(results, key=lambda item: (item.module_id, item.payload_id))

    @staticmethod
    async def _module_probes(module: Any, endpoint: str | None) -> list[dict[str, Any]]:
        """Load built-in and entry-point probes through one validated contract."""

        raw_probes = list(module.probes())
        # Built-ins expose a synchronous dataset.  Entry-point plugins commonly
        # implement the documented async stream instead, so an empty sync list
        # falls back to it.
        if not raw_probes:
            stream = module.probe_stream(endpoint)
            async for raw in stream:
                raw_probes.append(raw)
        normalized: list[dict[str, Any]] = []
        for raw in raw_probes:
            if isinstance(raw, AttackProbe):
                normalized.append(raw.model_dump(mode="json"))
                continue
            if isinstance(raw, dict):
                candidate = dict(raw)
                # Accept the older plugin example's ``prompt`` spelling while
                # keeping AttackProbe as the canonical public schema.
                if "payload" not in candidate and isinstance(candidate.get("prompt"), str):
                    candidate["payload"] = candidate.pop("prompt")
                normalized.append(AttackProbe.model_validate(candidate).model_dump(mode="json"))
                continue
            raise TypeError(f"attack module emitted unsupported probe type: {type(raw).__name__}")
        return normalized

    async def run(self, scan_context: ScanContext) -> dict[str, Any]:
        self._errors = []
        self._suppressed_rules = []
        context = (
            scan_context
            if isinstance(scan_context, ScanContext)
            else ScanContext.model_validate(scan_context)
        )
        context = context.model_copy(
            update={
                "profile": self.config.profile,
                "deployment_context": self.config.deployment_context,
                "context_multiplier": self.config.c_env,
            }
        )
        registry = get_enabled_modules(self.config)
        findings = await self._run_scanners(context, registry)
        inventory = self._inventory(context, registry)
        attack_results = await self._run_attacks(context, registry)
        if self.target_client is not None:
            close = getattr(self.target_client, "close", None)
            if close is not None:
                await close()
        scan_id = sha256(
            (
                context.model_dump_json(exclude={"target_endpoint", "documents"})
                + self.config.model_dump_json()
            ).encode("utf-8")
        ).hexdigest()[:16]
        methodology = (
            "canonical+semantic"
            if any(item.judge_score is not None for item in attack_results)
            else "canonical_only"
        )
        fail_threshold = SEVERITY_ORDER[self.config.reporting.fail_on]
        blocked = any(
            SEVERITY_ORDER.get(item.severity.value, 0) >= fail_threshold for item in findings
        ) or any(
            item.canonical_result.get("attack_succeeded")
            and fail_threshold <= SEVERITY_ORDER["HIGH"]
            for item in attack_results
        )
        dynamic_errors = sum(bool(item.error) for item in attack_results)
        execution_errors = [*context.document_errors, *self._errors, *plugin_errors()]
        available_rule_ids = sorted(
            {
                rule_id
                for scanner_cls in registry["scanners"].values()
                for rule_id in getattr(scanner_cls, "rule_capabilities", {})
            }
        )
        compliance = coverage_summary(
            available_rule_ids,
            sorted({item.module_id for item in attack_results}),
        )
        decision = "ERROR" if dynamic_errors or execution_errors else "BLOCK" if blocked else "PASS"
        return {
            "metadata": {
                "schema_version": "1.0",
                "argus_version": __version__,
                "source_type": context.source_type,
                "source": context.source_path,
                "profile": self.config.profile,
                "dataset_version": self.config.dataset_version,
                "scan_id": scan_id,
            },
            "configuration": sanitize_value(self.config.as_dict()),
            "findings": [item.model_dump(mode="json") for item in findings],
            "attack_results": [item.model_dump(mode="json") for item in attack_results],
            "summary": {
                "finding_count": len(findings),
                "attack_count": len(attack_results),
                "critical_count": sum(item.severity.value == "CRITICAL" for item in findings),
                "high_count": sum(item.severity.value == "HIGH" for item in findings),
                "max_risk": max(
                    [item.risk_score for item in findings]
                    + [item.risk_score for item in attack_results]
                    + [0.0]
                ),
                "errors": execution_errors,
                "error_count": len(execution_errors) + dynamic_errors,
                "dynamic_error_count": dynamic_errors,
                "skipped_file_count": len(context.skipped_files),
                "skipped_files": list(context.skipped_files),
                "suppressed_rules": list(self._suppressed_rules),
                "fail_on": self.config.reporting.fail_on,
                "decision": decision,
                "overall_decision": decision,
                "gate_decision": decision,
                "compliance_coverage": compliance,
                **inventory,
            },
            "evaluation_methodology": methodology,
        }


__all__ = ["ArgusEngine"]
