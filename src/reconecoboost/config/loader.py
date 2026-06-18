"""Config loader.

Loads the four concern-split YAML files (tools / pipeline / wordlists / ai),
applies environment-variable overrides, then any explicit override dict, and
returns a typed :class:`Config`. Secrets are never read from these files — they
come from the environment.

The loader holds configuration *data* only. It does not interpret AI, tool, or
database settings — those layers consume the dicts when they are implemented.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.errors import ConfigError

#: Section name -> filename. One file per concern (architecture doc 13).
SECTION_FILES: dict[str, str] = {
    "tools": "tools.yaml",
    "pipeline": "pipeline.yaml",
    "wordlists": "wordlists.yaml",
    "ai": "ai.yaml",
    "scope": "scope.yaml",
}

#: Environment variables with this prefix override config, nested by "__".
#: e.g. ``RECONECOBOOST__AI__PROVIDER=ollama`` sets ai.provider.
ENV_PREFIX = "RECONECOBOOST__"


@dataclass
class Config:
    """Typed, merged configuration for a run."""

    tools: dict[str, Any] = field(default_factory=dict)
    pipeline: dict[str, Any] = field(default_factory=dict)
    wordlists: dict[str, Any] = field(default_factory=dict)
    ai: dict[str, Any] = field(default_factory=dict)
    scope: dict[str, Any] = field(default_factory=dict)
    #: The full merged mapping, keyed by section (escape hatch / debugging).
    raw: dict[str, Any] = field(default_factory=dict)

    def profile_stages(self, profile: str) -> list[str] | None:
        """Return the stage list for a named pipeline profile, if defined."""
        profiles = self.pipeline.get("profiles", {})
        entry = profiles.get(profile)
        if isinstance(entry, dict):
            stages = entry.get("stages")
            if isinstance(stages, list):
                return list(stages)
        return None


class ConfigLoader:
    """Loads and merges configuration from a directory of YAML files."""

    def __init__(self, config_dir: str | Path) -> None:
        self.config_dir = Path(config_dir)

    def load(self, overrides: dict[str, Any] | None = None) -> Config:
        """Load all sections, apply env vars, then ``overrides``."""
        data: dict[str, Any] = {}
        for section, filename in SECTION_FILES.items():
            path = self.config_dir / filename
            data[section] = self._load_yaml(path) if path.exists() else {}
            # Merge a machine-local override (gitignored) over the shared config,
            # e.g. tools.local.yaml to pin a binary path without committing it.
            local = self.config_dir / filename.replace(".yaml", ".local.yaml")
            if local.exists():
                data[section] = self._deep_merge(data[section], self._load_yaml(local))

        self._apply_env(data, os.environ)
        if overrides:
            data = self._deep_merge(data, overrides)

        return Config(
            tools=data.get("tools", {}),
            pipeline=data.get("pipeline", {}),
            wordlists=data.get("wordlists", {}),
            ai=data.get("ai", {}),
            scope=data.get("scope", {}),
            raw=data,
        )

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _load_yaml(path: Path) -> dict[str, Any]:
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise ConfigError(
                "PyYAML is required to load configuration. Install with "
                "'pip install reconecoboost' or 'pip install pyyaml'."
            ) from exc

        try:
            with path.open("r", encoding="utf-8") as handle:
                loaded = yaml.safe_load(handle)
        except OSError as exc:
            raise ConfigError(f"Could not read config file: {path}") from exc
        except yaml.YAMLError as exc:
            raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

        if loaded is None:
            return {}
        if not isinstance(loaded, dict):
            raise ConfigError(f"Top level of {path} must be a mapping.")
        return loaded

    @classmethod
    def _deep_merge(cls, base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        merged = dict(base)
        for key, value in override.items():
            if (
                key in merged
                and isinstance(merged[key], dict)
                and isinstance(value, dict)
            ):
                merged[key] = cls._deep_merge(merged[key], value)
            else:
                merged[key] = value
        return merged

    @staticmethod
    def _apply_env(data: dict[str, Any], environ: Any) -> None:
        """Apply ``RECONECOBOOST__SECTION__KEY=value`` overrides in place."""
        for env_key, env_value in environ.items():
            if not env_key.startswith(ENV_PREFIX):
                continue
            path = env_key[len(ENV_PREFIX):].lower().split("__")
            if not path:
                continue
            cursor = data
            for part in path[:-1]:
                nxt = cursor.get(part)
                if not isinstance(nxt, dict):
                    nxt = {}
                    cursor[part] = nxt
                cursor = nxt
            cursor[path[-1]] = env_value
