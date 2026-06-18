"""Engine services layer — the deterministic execution muscle (architecture doc 08).

Exposes the four chokepoint services:

* :class:`CommandExecutor` — all process execution (argv-only, timeout/retry/capture).
* :class:`ToolManager` — binary discovery, version detection, dependency validation.
* :class:`Parser` / :class:`ParserRegistry` — raw text -> typed records (pure).
* :class:`Normalizer` — records -> canonical, deduplicated entities + relations.

Tool-specific parsers are added alongside their recon modules; only the
infrastructure lives here.
"""

from .executor import (
    CommandExecutor,
    ExecutionResult,
    ExecutionStatus,
    RetryPolicy,
)
from .normalizer import Normalizer, NormalizationResult, canonical_key
from .parser import PARSERS, ParsedRecord, Parser, ParserRegistry, register_parser
from .toolmanager import ToolHandle, ToolManager

__all__ = [
    "CommandExecutor",
    "ExecutionResult",
    "ExecutionStatus",
    "RetryPolicy",
    "ToolManager",
    "ToolHandle",
    "Parser",
    "ParserRegistry",
    "ParsedRecord",
    "PARSERS",
    "register_parser",
    "Normalizer",
    "NormalizationResult",
    "canonical_key",
]
