"""Tests for CommandExecutor (argv-only, no shell)."""

import sys

from reconecoboost.engine import CommandExecutor, ExecutionStatus, RetryPolicy


def test_success_captures_stdout_and_exit_zero():
    ex = CommandExecutor()
    result = ex.run([sys.executable, "-c", "print('hello')"])
    assert result.status == ExecutionStatus.SUCCESS
    assert result.ok
    assert result.exit_code == 0
    assert "hello" in result.stdout


def test_nonzero_exit_is_typed_not_raised():
    ex = CommandExecutor()
    result = ex.run([sys.executable, "-c", "import sys; sys.exit(3)"])
    assert result.status == ExecutionStatus.NONZERO
    assert result.exit_code == 3
    assert not result.ok


def test_timeout_terminates_and_reports():
    ex = CommandExecutor()
    result = ex.run([sys.executable, "-c", "import time; time.sleep(5)"], timeout_s=0.5)
    assert result.status == ExecutionStatus.TIMEOUT
    assert result.duration_s < 5


def test_missing_binary_is_spawn_error():
    ex = CommandExecutor()
    result = ex.run(["definitely-not-a-real-binary-xyz123"])
    assert result.status == ExecutionStatus.SPAWN_ERROR
    assert result.error


def test_retry_attempts_on_configured_exit_code():
    ex = CommandExecutor()
    policy = RetryPolicy(max_attempts=3, backoff_s=0.0, retry_on_exit_codes=(7,))
    result = ex.run([sys.executable, "-c", "import sys; sys.exit(7)"], retry=policy)
    assert result.status == ExecutionStatus.NONZERO
    assert result.attempts == 3


def test_capture_to_writes_file(tmp_path):
    ex = CommandExecutor()
    out = tmp_path / "cap.txt"
    result = ex.run([sys.executable, "-c", "print('data')"], capture_to=out)
    assert out.read_text().strip() == "data"
    assert result.capture_path == str(out)


def test_redaction_masks_sensitive_values():
    redacted = CommandExecutor._redact(["httpx", "-H", "Authorization: Bearer secret"])
    assert "secret" not in redacted
    assert "***" in redacted
