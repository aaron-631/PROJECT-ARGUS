"""
Structured logging — all output in structured format.
Secrets must never appear in logs (sanitization layer enforces this upstream).
"""

import logging
import json

from src.core.sanitization import sanitize_value


def configure_logging(verbose: bool = False) -> None:
    """Configure CLI logging without ever emitting unsanitized payloads."""

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
    )


class ArgusLogger:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)

    def info(self, event: str, **kwargs):
        self.logger.info(json.dumps({"event": event, **sanitize_value(kwargs)}, default=str))

    def debug(self, event: str, **kwargs):
        self.logger.debug(json.dumps({"event": event, **sanitize_value(kwargs)}, default=str))

    def warning(self, event: str, **kwargs):
        self.logger.warning(json.dumps({"event": event, **sanitize_value(kwargs)}, default=str))

    def error(self, event: str, **kwargs):
        self.logger.error(json.dumps({"event": event, **sanitize_value(kwargs)}, default=str))
