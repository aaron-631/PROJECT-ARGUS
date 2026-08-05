"""Async Argus orchestration engine."""

from __future__ import annotations

import asyncio
from hashlib import sha256
from typing import Any

from src.core.evaluation import EvaluationPipeline
from src.core.rate_limiter import TokenBucketRateLimiter, parse_retry_after
from src.core.sanitization import sanitize_value
from src.core.registry import get_enabled_modules
from src.core.target_client import HTTPTargetClient, TargetClient, resolve_api_key
from src.interfaces.judge import HTTPJudgeBackend, MockJudgeBackend, NullJudgeBackend
from src.models import SEVERITY_ORDER, AttackResult, Finding, ScanContext
from src.models.config import ArgusConfig
from src.modules.attacks.dataset import dataset_version


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
                self._errors.append(f"scanner {scanner_id}: {type(exc).__name__}")
        disabled = set(getattr(self.config, "disabled_rules", []))
        if disabled:
            self._suppressed_rules = sorted({f.rule_id for f in findings if f.rule_id in disabled})
            findings = [f for f in findings if f.rule_id not in disabled]
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
                    response = await client.send(probe["payload"], attack_type=module.module_id)
                    response_status = response.status_code
                    response_text = response.text
                    if response.status_code != 429 and response.status_code < 500:
                        error = None
                        break
                    if response.status_code == 429:
                        retry_after = parse_retry_after(response.headers.get("Retry-After"))
                        limiter.penalize(min(max(retry_after, 0.0), 60.0))
                    if attempt < self.config.engine.max_retries:
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
            if response_status == 0 and not response_text:
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
                )
            evaluation = await evaluator.evaluate(
                response_text, {"attack_type": module.attack_type, "status_code": response_status}
            )
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
            )

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
            )
        limiter = TokenBucketRateLimiter(self.config.engine.rate_limit_rps)
        semaphore = asyncio.Semaphore(self.config.engine.max_concurrent_attacks)
        evaluator = EvaluationPipeline(self._judge(), self.config.c_env)
        tasks = []
        for module_cls in registry["attack_modules"].values():
            module = module_cls()
            for probe in module.probes():
                tasks.append(
                    self._attack_one(
                        module, probe.model_dump(mode="json"), limiter, semaphore, evaluator
                    )
                )
        results = await asyncio.gather(*tasks) if tasks else []
        return sorted(results, key=lambda item: (item.module_id, item.payload_id))

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
        execution_errors = [*context.document_errors, *self._errors]
        decision = "ERROR" if dynamic_errors or execution_errors else "BLOCK" if blocked else "PASS"
        return {
            "metadata": {
                "schema_version": "1.0",
                "argus_version": "1.0.0",
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
                **inventory,
            },
            "evaluation_methodology": methodology,
        }


__all__ = ["ArgusEngine"]
