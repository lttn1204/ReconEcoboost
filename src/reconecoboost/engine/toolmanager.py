"""ToolManager — maps logical tool names to real, validated binaries.

Owns binary discovery (PATH + config overrides), best-effort version detection,
and pre-run dependency validation (architecture doc 08). Modules ask for a tool
by logical name and receive a :class:`ToolHandle`; they never hardcode paths or
probe the filesystem themselves.

Version detection runs through the :class:`CommandExecutor`, so it inherits the
same timeout/logging guarantees as any other invocation.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from typing import Any

from ..core.errors import ToolNotFoundError
from ..logging.setup import get_logger
from .executor import CommandExecutor, RetryPolicy

_log = get_logger("engine.toolmanager")


def deshadowed_which(binary: str) -> str | None:
    """Like ``shutil.which`` but never returns a binary inside the active venv.

    External recon tools (e.g. ``httpx``) can be shadowed by a same-named Python
    console script installed in the project's virtualenv (ProjectDiscovery httpx
    vs the Python `httpx` library's CLI). When running inside a venv and the
    found binary lives in the venv's bin dir, search the rest of PATH first.
    """
    candidate = shutil.which(binary)
    if not candidate or sys.prefix == sys.base_prefix:
        return candidate  # not in a venv, or not found — nothing to deshadow
    venv_bin = os.path.realpath(os.path.join(sys.prefix, "bin"))
    if os.path.realpath(os.path.dirname(candidate)) != venv_bin:
        return candidate  # not shadowed by the venv
    rest = os.pathsep.join(
        d for d in os.environ.get("PATH", "").split(os.pathsep)
        if d and os.path.realpath(d) != venv_bin
    )
    return shutil.which(binary, path=rest) or candidate

#: Default args/pattern for version probes when a tool doesn't override them.
_DEFAULT_VERSION_ARGS = ("--version",)
_DEFAULT_VERSION_PATTERN = r"v?(\d+\.\d+(?:\.\d+)?)"


@dataclass
class ToolHandle:
    """A resolved tool: logical name, binary name, absolute path, version."""

    name: str
    binary: str
    path: str
    version: str | None = None

    def argv(self, *args: str) -> list[str]:
        """Build an argument vector rooted at this tool's binary path."""
        return [self.path, *args]


class ToolManager:
    """Resolves and validates tools from the ``tools.yaml`` configuration."""

    def __init__(
        self,
        tools_config: dict[str, Any] | None = None,
        executor: CommandExecutor | None = None,
    ) -> None:
        # ``tools_config`` is the parsed tools.yaml: {defaults: {...}, tools: {...}}
        self._config = tools_config or {}
        self._executor = executor
        self._cache: dict[str, ToolHandle] = {}

    # -- discovery ----------------------------------------------------------

    def _spec(self, name: str) -> dict[str, Any]:
        return self._config.get("tools", {}).get(name, {}) or {}

    def resolve(self, name: str) -> ToolHandle:
        """Locate a tool's binary, caching the result. Raises if not found."""
        if name in self._cache:
            return self._cache[name]

        spec = self._spec(name)
        binary = spec.get("binary", name)
        path = spec.get("path") or deshadowed_which(binary)
        if not path:
            raise ToolNotFoundError(
                f"Tool '{name}' (binary '{binary}') not found on PATH or via config."
            )

        handle = ToolHandle(name=name, binary=binary, path=path)
        self._cache[name] = handle
        return handle

    def is_available(self, name: str) -> bool:
        try:
            self.resolve(name)
            return True
        except ToolNotFoundError:
            return False

    # -- version ------------------------------------------------------------

    def version(self, name: str) -> str | None:
        """Best-effort version detection. Returns ``None`` if undetectable."""
        handle = self.resolve(name)
        if handle.version is not None:
            return handle.version
        if self._executor is None:
            return None

        spec = self._spec(name)
        args = tuple(spec.get("version_args", _DEFAULT_VERSION_ARGS))
        pattern = spec.get("version_pattern", _DEFAULT_VERSION_PATTERN)

        result = self._executor.run(
            handle.argv(*args), timeout_s=10, retry=RetryPolicy.none()
        )
        match = re.search(pattern, f"{result.stdout}\n{result.stderr}")
        handle.version = match.group(1) if match else None
        return handle.version

    # -- validation ---------------------------------------------------------

    def preflight(self, names: list[str], strict: bool = True) -> dict[str, ToolHandle | None]:
        """Resolve every name up front; report (and optionally fail on) missing.

        Returns a mapping of name -> handle (or ``None`` if missing). When
        ``strict`` is True and any tool is missing, raises with the full list so
        the operator sees everything to fix at once.
        """
        report: dict[str, ToolHandle | None] = {}
        missing: list[str] = []
        for name in names:
            try:
                report[name] = self.resolve(name)
            except ToolNotFoundError:
                report[name] = None
                missing.append(name)

        if missing:
            _log.warning("Missing tools: %s", ", ".join(missing))
            if strict:
                raise ToolNotFoundError(f"Missing required tools: {', '.join(missing)}")
        return report

    # -- future hook --------------------------------------------------------

    def install(self, name: str) -> None:
        """Future automatic installation hook (architecture doc 08). Not yet implemented."""
        raise NotImplementedError(
            f"Automatic installation of '{name}' is not implemented yet."
        )
