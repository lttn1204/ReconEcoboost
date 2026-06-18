"""Orchestration layer: module registry and the pipeline DAG runner.

This is the only layer that knows execution *order*. Parallel/distributed
schedulers will slot in here without touching modules (architecture doc 16/17).
"""

from .pipeline import Pipeline
from .registry import REGISTRY, ModuleRegistry, register

__all__ = ["Pipeline", "ModuleRegistry", "REGISTRY", "register"]
