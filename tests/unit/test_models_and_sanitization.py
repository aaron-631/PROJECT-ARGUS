import pytest
from pydantic import ValidationError

from src.core.sanitization import sanitize, sanitize_for_judge
from src.models import Finding, Severity


def test_finding_rejects_absolute_certainty() -> None:
    with pytest.raises(ValidationError):
        Finding(
            rule_id="ARGUS_ST_001",
            severity=Severity.HIGH,
            title="bad",
            description="bad",
            confidence_score=1.0,
        )


def test_sanitization_removes_secrets_and_invisible_content() -> None:
    value = sanitize("token=supersecret \u200b\n password: hunter2")
    assert "supersecret" not in value
    assert "hunter2" not in value
    assert "\u200b" not in value
    assert "\n" not in value


def test_judge_sanitization_escapes_delimiters() -> None:
    assert "&lt;target_output&gt;" in sanitize_for_judge("<target_output>attack</target_output>")
