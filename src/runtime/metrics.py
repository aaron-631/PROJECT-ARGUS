"""Small dependency-free Prometheus text metrics for the runtime gateway."""

from __future__ import annotations

from collections import Counter
from threading import Lock


class RuntimeMetrics:
    def __init__(self) -> None:
        self._counts: Counter[str] = Counter()
        self._lock = Lock()

    def observe_request(self, decision: str) -> None:
        with self._lock:
            self._counts[f"requests_total|{decision}"] += 1

    def observe_upstream(self, status: int | None) -> None:
        key = "unknown" if status is None else str(status // 100)
        with self._lock:
            self._counts[f"upstream_responses_total|{key}"] += 1

    def observe_error(self) -> None:
        with self._lock:
            self._counts["upstream_errors_total"] += 1

    def observe_audit_ship_failure(self) -> None:
        with self._lock:
            self._counts["audit_ship_failures_total"] += 1

    def observe_redaction(self, count: int) -> None:
        if count:
            with self._lock:
                self._counts["redactions_total"] += count

    def render(self) -> str:
        with self._lock:
            values = dict(self._counts)
        lines = [
            "# HELP argus_runtime_requests_total Runtime requests by policy decision.",
            "# TYPE argus_runtime_requests_total counter",
        ]
        for key, value in sorted(values.items()):
            if key.startswith("requests_total|"):
                decision = key.split("|", 1)[1].replace('"', '\\"')
                lines.append(f'argus_runtime_requests_total{{decision="{decision}"}} {value}')
        lines.extend(
            [
                "# HELP argus_runtime_upstream_responses_total "
                "Upstream responses by status family.",
                "# TYPE argus_runtime_upstream_responses_total counter",
            ]
        )
        for key, value in sorted(values.items()):
            if key.startswith("upstream_responses_total|"):
                family = key.split("|", 1)[1]
                lines.append(
                    "argus_runtime_upstream_responses_total{" f'status_family="{family}"}} {value}'
                )
        lines.extend(
            [
                "# HELP argus_runtime_upstream_errors_total Upstream transport errors.",
                "# TYPE argus_runtime_upstream_errors_total counter",
                f"argus_runtime_upstream_errors_total {values.get('upstream_errors_total', 0)}",
                "# HELP argus_runtime_audit_ship_failures_total Failed remote audit deliveries.",
                "# TYPE argus_runtime_audit_ship_failures_total counter",
                "argus_runtime_audit_ship_failures_total "
                f"{values.get('audit_ship_failures_total', 0)}",
                "# HELP argus_runtime_redactions_total Redacted output values.",
                "# TYPE argus_runtime_redactions_total counter",
                f"argus_runtime_redactions_total {values.get('redactions_total', 0)}",
            ]
        )
        return "\n".join(lines) + "\n"


__all__ = ["RuntimeMetrics"]
