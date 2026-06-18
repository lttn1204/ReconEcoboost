"""Module registry.

Modules self-register via the :func:`register` decorator. A default registry
instance is provided for the common case; tests and embedders may construct
their own :class:`ModuleRegistry` for isolation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..core.models import Domain

if TYPE_CHECKING:
    from ..core.module import BaseModule


class ModuleRegistry:
    """Catalogue of available module classes, keyed by their stable name."""

    def __init__(self) -> None:
        self._modules: dict[str, type["BaseModule"]] = {}
        self._order: list[str] = []  # registration order, for deterministic plans

    def register(self, cls: type["BaseModule"]) -> type["BaseModule"]:
        """Register a module class. Returns the class so it can be used as a decorator."""
        name = getattr(cls, "name", "")
        if not name:
            raise ValueError(f"Module {cls!r} must define a non-empty 'name'.")
        if name in self._modules and self._modules[name] is not cls:
            raise ValueError(f"Duplicate module name registered: {name!r}")
        if name not in self._modules:
            self._order.append(name)
        self._modules[name] = cls
        return cls

    def get(self, name: str) -> type["BaseModule"]:
        return self._modules[name]

    def all(self) -> list[type["BaseModule"]]:
        return [self._modules[name] for name in self._order]

    def for_domain(self, domain: Domain) -> list[type["BaseModule"]]:
        return [cls for cls in self.all() if cls.domain == domain]


#: Default process-wide registry used by the ``@register`` decorator.
REGISTRY = ModuleRegistry()


def register(cls: type["BaseModule"]) -> type["BaseModule"]:
    """Decorator that registers a module class with the default registry."""
    return REGISTRY.register(cls)
