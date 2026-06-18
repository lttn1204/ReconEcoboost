"""Typed exception hierarchy shared across the framework."""

from __future__ import annotations


class ReconEcoboostError(Exception):
    """Base class for all framework errors."""


class ConfigError(ReconEcoboostError):
    """Raised when configuration is missing, malformed, or invalid."""


class PipelineError(ReconEcoboostError):
    """Raised when a pipeline cannot be resolved (e.g. dependency cycle)."""


class ModuleError(ReconEcoboostError):
    """Raised for module-level failures surfaced to the orchestrator."""


class ToolError(ReconEcoboostError):
    """Base class for tool-resolution / tool-management failures."""


class ToolNotFoundError(ToolError):
    """Raised when a required tool binary cannot be located."""


class ExecutionError(ReconEcoboostError):
    """Raised for unrecoverable process-execution failures."""


class ParserError(ReconEcoboostError):
    """Raised when tool output cannot be parsed into records."""


class AIError(ReconEcoboostError):
    """Raised for AI-provider failures (missing SDK, auth, malformed output)."""


class PromptError(ReconEcoboostError):
    """Raised when a prompt template is missing or cannot be rendered."""
