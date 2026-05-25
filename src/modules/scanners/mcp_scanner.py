"""
MCP Security Scanner — evaluates MCP tool schemas and permission scopes.
Implements rules: ARGUS_ST_001 through ARGUS_ST_005.
"""
from src.interfaces.scanner import BaseStaticScanner
from src.core.registry import register_scanner


@register_scanner
class MCPScanner(BaseStaticScanner):
    scanner_id = "mcp_scanner"

    def scan(self, context) -> list:
        # TODO: Week 3-4 — parse MCP schemas, check tool declarations
        raise NotImplementedError
