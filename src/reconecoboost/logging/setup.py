"""Logging configuration.

Provides a console formatter and an optional JSON formatter, plus a helper to
obtain a logger pre-bound with correlation fields (``run_id``, ``module``).
Redaction and the machine-readable per-run log file are described in the
architecture doc; only the wiring exists in the skeleton.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

ROOT_LOGGER_NAME = "reconecoboost"

#: Correlation fields surfaced into structured log records when present.
_CORRELATION_FIELDS = ("run_id", "module", "tool_run")


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON for machine consumption."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for field in _CORRELATION_FIELDS:
            if hasattr(record, field):
                payload[field] = getattr(record, field)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", json_logs: bool = False) -> logging.Logger:
    """Configure the framework's root logger and return it.

    Idempotent: clears existing handlers so repeated calls (tests, re-runs) do
    not duplicate output.
    """
    logger = logging.getLogger(ROOT_LOGGER_NAME)
    logger.setLevel(level.upper())
    logger.handlers.clear()
    logger.propagate = False

    handler = logging.StreamHandler(sys.stderr)
    if json_logs:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)-7s %(name)s :: %(message)s",
                datefmt="%H:%M:%S",
            )
        )
    logger.addHandler(handler)
    return logger


def get_logger(name: str, **correlation: Any) -> logging.Logger | logging.LoggerAdapter:
    """Return a namespaced logger, optionally bound with correlation fields.

    ``get_logger("cli", run_id=ctx.run_id)`` yields a logger whose records carry
    ``run_id`` for the structured formatter.
    """
    full_name = name if name.startswith(ROOT_LOGGER_NAME) else f"{ROOT_LOGGER_NAME}.{name}"
    logger = logging.getLogger(full_name)
    if correlation:
        return logging.LoggerAdapter(logger, dict(correlation))
    return logger
