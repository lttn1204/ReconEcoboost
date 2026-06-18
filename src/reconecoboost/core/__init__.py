"""Foundation layer: Context, BaseModule, canonical models, scope, errors.

This layer has no dependencies on any layer above it (see architecture doc 01/07).
"""

from .context import Context
from .errors import (
    ConfigError,
    ModuleError,
    PipelineError,
    ReconEcoboostError,
)
from .models import Domain, ModuleResult, ModuleStatus, Stage
from .module import BaseModule
from .scope import Scope

__all__ = [
    "Context",
    "BaseModule",
    "Scope",
    "Domain",
    "Stage",
    "ModuleResult",
    "ModuleStatus",
    "ReconEcoboostError",
    "ConfigError",
    "PipelineError",
    "ModuleError",
]
