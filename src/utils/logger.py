"""
Structured logging — all output in structured format.
Secrets must never appear in logs (sanitization layer enforces this upstream).
"""
import logging
import json


class ArgusLogger:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)

    def info(self, event: str, **kwargs):
        self.logger.info(json.dumps({"event": event, **kwargs}))

    def warning(self, event: str, **kwargs):
        self.logger.warning(json.dumps({"event": event, **kwargs}))

    def error(self, event: str, **kwargs):
        self.logger.error(json.dumps({"event": event, **kwargs}))
