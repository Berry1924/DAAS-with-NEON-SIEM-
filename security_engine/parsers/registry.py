from typing import Dict, Optional
from security_engine.parsers.base import BaseParser
from security_engine.parsers.linux_auth import LinuxAuthParser
from security_engine.parsers.json_parser import JsonParser

class ParserRegistry:
    """Registry mapping source types to concrete BaseParser implementations."""

    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {}
        # Register default supported parsers
        self.register("linux_auth", LinuxAuthParser())
        self.register("json", JsonParser())

    def register(self, source_type: str, parser: BaseParser) -> None:
        """Register a parser instance for a specific source_type."""
        self._parsers[source_type.lower()] = parser

    def get_parser(self, source_type: str) -> BaseParser:
        """Retrieve parser for source_type or raise ValueError if unsupported."""
        st_clean = source_type.strip().lower()
        parser = self._parsers.get(st_clean)
        if not parser:
            raise ValueError(f"No parser registered for source_type: '{source_type}'")
        return parser

# Global parser registry instance
parser_registry = ParserRegistry()
