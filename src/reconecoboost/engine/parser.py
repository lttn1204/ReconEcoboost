"""Parser layer — turns raw tool text into typed records, and nothing else.

A parser is a *pure* function of its input: no I/O, no DB, no network. It maps
raw stdout (preferably a tool's structured/JSON output) into ``ParsedRecord``
objects. Parsing is tool-coupled; normalization is domain-coupled — keeping them
separate means a new tool needs only a new parser (architecture doc 08).

Tool-specific parsers (subfinder, httpx, ...) are added with their recon
modules. This module provides the base class and registry only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..core.entities import Relation


@dataclass
class ParsedRecord:
    """One fact extracted from tool output, before canonicalization.

    ``asset_type`` and ``key`` identify the entity; ``attributes`` carry domain
    detail; ``relations`` are optional edge hints the tool's output implies.
    """

    asset_type: str
    key: str
    attributes: dict[str, Any] = field(default_factory=dict)
    tool: str | None = None
    raw_ref: str | None = None
    relations: list[Relation] = field(default_factory=list)


class Parser(ABC):
    """Base class for tool-output parsers. Implementations must be pure."""

    #: Logical tool/format name this parser handles (e.g. "subfinder").
    tool: str = ""

    @abstractmethod
    def parse(self, raw: str) -> list[ParsedRecord]:
        """Convert raw tool output into a list of records."""
        raise NotImplementedError


class ParserRegistry:
    """Maps logical tool/format names to parser instances."""

    def __init__(self) -> None:
        self._parsers: dict[str, Parser] = {}

    def register(self, parser: Parser) -> Parser:
        name = getattr(parser, "tool", "")
        if not name:
            raise ValueError(f"Parser {parser!r} must define a non-empty 'tool'.")
        self._parsers[name] = parser
        return parser

    def get(self, name: str) -> Parser:
        return self._parsers[name]

    def has(self, name: str) -> bool:
        return name in self._parsers

    def all(self) -> dict[str, Parser]:
        return dict(self._parsers)


#: Default process-wide parser registry.
PARSERS = ParserRegistry()


def register_parser(parser_cls: type[Parser]) -> type[Parser]:
    """Class decorator: instantiate and register a parser with the default registry."""
    PARSERS.register(parser_cls())
    return parser_cls
