"""CommandExecutor — the single chokepoint for all external process execution.

Every tool invocation in the framework goes through here. Modules never call
``subprocess`` directly (architecture doc 08): this class owns argv-only
execution (no shell), timeouts with process-tree termination, retries with
backoff, separate stdout/stderr capture, timing, redacted structured logging,
and typed results instead of leaked exceptions.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from ..logging.setup import get_logger

_log = get_logger("engine.executor")

#: Flags whose following value is masked in logs (best-effort secret hygiene).
_SENSITIVE_FLAGS = frozenset(
    {"-H", "--header", "-u", "--user", "-p", "--password", "--token", "--api-key", "--auth"}
)
_REDACTED = "***"


def redact_argv(argv: list[str]) -> str:
    """Render an argv as a string with sensitive flag-values masked.

    Public helper so callers (e.g. modules recording a tool_run) log/store the
    same redacted form the executor uses.
    """
    parts: list[str] = []
    mask_next = False
    for token in argv:
        if mask_next:
            parts.append(_REDACTED)
            mask_next = False
            continue
        parts.append(token)
        if token in _SENSITIVE_FLAGS:
            mask_next = True
    return " ".join(parts)


class ExecutionStatus(str, Enum):
    """Outcome of a process invocation."""

    SUCCESS = "success"        # spawned, completed, exit code 0
    NONZERO = "nonzero"        # spawned, completed, non-zero exit code
    TIMEOUT = "timeout"        # killed after exceeding the timeout
    SPAWN_ERROR = "spawn_error"  # could not spawn (missing binary, OS error)


@dataclass
class RetryPolicy:
    """How transient failures are retried."""

    max_attempts: int = 1
    backoff_s: float = 2.0
    retry_on_timeout: bool = False
    retry_on_exit_codes: tuple[int, ...] = ()

    @classmethod
    def none(cls) -> "RetryPolicy":
        return cls(max_attempts=1)


@dataclass
class ExecutionResult:
    """Typed result of a (possibly retried) invocation."""

    argv: list[str]
    status: ExecutionStatus
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    attempts: int = 1
    capture_path: str | None = None
    error: str | None = None
    meta: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == ExecutionStatus.SUCCESS


class CommandExecutor:
    """Runs external commands safely and uniformly."""

    def __init__(
        self,
        default_timeout_s: float = 600.0,
        default_retry: RetryPolicy | None = None,
    ) -> None:
        self.default_timeout_s = default_timeout_s
        self.default_retry = default_retry or RetryPolicy.none()

    def run(
        self,
        argv: list[str],
        *,
        timeout_s: float | None = None,
        retry: RetryPolicy | None = None,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
        capture_to: str | Path | None = None,
    ) -> ExecutionResult:
        """Execute ``argv`` (an argument vector — never a shell string)."""
        if not argv:
            raise ValueError("argv must be a non-empty list")

        retry = retry or self.default_retry
        timeout = self.default_timeout_s if timeout_s is None else timeout_s

        result: ExecutionResult | None = None
        for attempt in range(1, retry.max_attempts + 1):
            result = self._run_once(argv, timeout, cwd, env, input_text, capture_to)
            result.attempts = attempt

            if result.ok or attempt >= retry.max_attempts or not self._should_retry(result, retry):
                break

            sleep_for = retry.backoff_s * attempt
            _log.warning(
                "Retrying %s (attempt %d/%d) after %s in %.1fs",
                argv[0], attempt, retry.max_attempts, result.status.value, sleep_for,
            )
            time.sleep(sleep_for)

        assert result is not None  # loop runs at least once
        self._log_result(result)
        return result

    # -- internals ----------------------------------------------------------

    def _run_once(
        self,
        argv: list[str],
        timeout: float,
        cwd: str | Path | None,
        env: dict[str, str] | None,
        input_text: str | None,
        capture_to: str | Path | None,
    ) -> ExecutionResult:
        start = time.perf_counter()
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False, by design
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if input_text is not None else None,
                cwd=str(cwd) if cwd else None,
                env=env,
                text=True,
                start_new_session=True,  # own process group for clean tree-kill
            )
        except (FileNotFoundError, PermissionError, OSError) as exc:
            return ExecutionResult(
                argv=list(argv),
                status=ExecutionStatus.SPAWN_ERROR,
                duration_s=round(time.perf_counter() - start, 4),
                error=str(exc),
            )

        timed_out = False
        try:
            stdout, stderr = proc.communicate(input=input_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._terminate(proc)
            stdout, stderr = proc.communicate()

        duration = round(time.perf_counter() - start, 4)

        if timed_out:
            status = ExecutionStatus.TIMEOUT
        elif proc.returncode == 0:
            status = ExecutionStatus.SUCCESS
        else:
            status = ExecutionStatus.NONZERO

        result = ExecutionResult(
            argv=list(argv),
            status=status,
            exit_code=proc.returncode,
            stdout=stdout or "",
            stderr=stderr or "",
            duration_s=duration,
        )

        if capture_to is not None and result.stdout:
            path = Path(capture_to)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(result.stdout, encoding="utf-8")
            result.capture_path = str(path)

        return result

    @staticmethod
    def _terminate(proc: subprocess.Popen) -> None:
        """Terminate the process tree, escalating to SIGKILL if needed."""
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
            try:
                proc.wait(timeout=3)
                return
            except subprocess.TimeoutExpired:
                os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, AttributeError):
            # No process group (e.g. non-POSIX) — fall back to direct kill.
            try:
                proc.kill()
            except ProcessLookupError:
                pass

    @staticmethod
    def _should_retry(result: ExecutionResult, retry: RetryPolicy) -> bool:
        if result.status == ExecutionStatus.TIMEOUT:
            return retry.retry_on_timeout
        if result.status == ExecutionStatus.NONZERO:
            return result.exit_code in retry.retry_on_exit_codes
        if result.status == ExecutionStatus.SPAWN_ERROR:
            return False  # missing binary won't fix itself between attempts
        return False

    @staticmethod
    def _redact(argv: list[str]) -> str:
        return redact_argv(argv)

    def _log_result(self, result: ExecutionResult) -> None:
        _log.info(
            "tool=%s status=%s exit=%s dur=%.3fs attempts=%d out_bytes=%d argv=[%s]",
            Path(result.argv[0]).name,
            result.status.value,
            result.exit_code,
            result.duration_s,
            result.attempts,
            len(result.stdout),
            self._redact(result.argv),
        )
