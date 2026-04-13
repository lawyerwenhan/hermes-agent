"""
Layer C Silent Audit Logger

纯静默审计日志，不推送 Telegram，只写入本地文件。
日志位置：~/.hermes/audit/YYYY-MM-DD.log

设计原则：
- 零用户干扰：不输出任何信息到 Telegram/CLI
- 低开销：只记录元信息，不记录 stdout/stderr 内容
- Append-only：每日文件，不可修改
"""

import os
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

# Thread-safe lock for file writes
_write_lock = threading.Lock()


def _get_audit_log_path() -> Path:
    """Get today's audit log file path."""
    from hermes_constants import get_hermes_home
    audit_dir = Path(get_hermes_home()) / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    tz_utc8 = timezone(timedelta(hours=8))
    today = datetime.now(tz_utc8).strftime("%Y-%m-%d")
    return audit_dir / f"{today}.log"


def _get_timestamp() -> str:
    """Get ISO8601 timestamp with +08:00 offset."""
    tz_utc8 = timezone(timedelta(hours=8))
    return datetime.now(tz_utc8).strftime("%Y-%m-%dT%H:%M:%S%z")


def _truncate_cmd(cmd: str, max_len: int = 500) -> str:
    """Truncate command if too long."""
    if len(cmd) <= max_len:
        return cmd
    return cmd[:max_len] + "..."


def log_terminal_command(
    cmd: str,
    exit_code: int,
    pattern: Optional[str] = None,
    blocked: bool = False
) -> None:
    """
    Log a terminal command execution.

    Args:
        cmd: The command that was executed (or attempted)
        exit_code: Exit code (0 for success, -1 for blocked/pre-flight fail, etc.)
        pattern: Pattern ID if blocked by pre-flight or approval system
        blocked: Whether the command was blocked
    """
    try:
        timestamp = _get_timestamp()
        truncated_cmd = _truncate_cmd(cmd)
        pattern_str = pattern if pattern else "-"

        blocked_str = "yes" if blocked else "no"
        log_line = f"{timestamp} | cmd: {truncated_cmd} | exit: {exit_code} | pattern: {pattern_str} | blocked: {blocked_str}\n"

        log_path = _get_audit_log_path()
        with _write_lock:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(log_line)
    except Exception:
        # Silent failure - never let audit logging break the main flow
        pass


def log_file_write(
    path: str,
    exit_code: int,
    pattern: Optional[str] = None,
    blocked: bool = False
) -> None:
    """
    Log a file write operation.

    Args:
        path: The file path being written
        exit_code: Exit code (0 for success, -1 for blocked/pre-flight fail, etc.)
        pattern: Pattern ID if blocked by pre-flight
        blocked: Whether the write was blocked
    """
    try:
        timestamp = _get_timestamp()
        pattern_str = pattern if pattern else "-"

        blocked_str = "yes" if blocked else "no"
        log_line = f"{timestamp} | write: {path} | exit: {exit_code} | pattern: {pattern_str} | blocked: {blocked_str}\n"

        log_path = _get_audit_log_path()
        with _write_lock:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(log_line)
    except Exception:
        # Silent failure
        pass
