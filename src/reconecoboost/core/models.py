"""Canonical, domain-agnostic data models used across layers.

These are deliberately small and free of behaviour. They define the vocabulary
(domains, stages, statuses, the per-module result record) that modules, the
pipeline, and the logging layer all share.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Domain(str, Enum):
    """The recon domains the framework is designed to support over time.

    Only ``WEB`` is exercised in v1; the rest are declared so modules and the
    schema can reference them without churn when they are added later.
    """

    WEB = "web"
    API = "api"
    HOST = "host"
    NETWORK = "network"
    AD = "ad"
    CLOUD = "cloud"
    K8S = "k8s"
    CONTAINER = "container"
    MOBILE = "mobile"


class Stage(str, Enum):
    """Logical category of a module within a domain pipeline."""

    DISCOVERY = "discovery"
    PROBING = "probing"
    COLLECTION = "collection"
    ANALYSIS = "analysis"


class ModuleStatus(str, Enum):
    """Lifecycle status of a single module execution."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ModuleResult:
    """The append-only record a module contributes to the run ledger.

    The pipeline owns timing and status transitions; modules may return a
    populated result, but recon-specific payloads live in the database, never
    here (see architecture doc 07).
    """

    module: str
    status: ModuleStatus = ModuleStatus.PENDING
    produced: int = 0
    duration_s: float = 0.0
    error: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)
