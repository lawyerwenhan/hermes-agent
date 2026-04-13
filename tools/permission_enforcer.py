"""
Permission Enforcer - Three-tier permission system for Hermes agent.

Risk axis: reversibility + external audience, NOT technical difficulty.
Green = auto-execute, Yellow = execute + report, Red = must ask with
lawyer-understandable message, Block = auto-refuse without asking.

This runs at the Python code layer, NOT as a prompt. The model cannot
bypass it because it executes before handle_function_call() dispatches.
"""

import fnmatch
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

import yaml

# ── Constants ──────────────────────────────────────────────────────────

GREEN = "green"
YELLOW = "yellow"
RED = "red"
BLOCK = "block"

PERMISSIONS_PATH = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes")) / "permissions.yaml"
AUDIT_DIR = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes")) / "audit"

# Hard redline directories - NEVER write here regardless of config
REDLINE_DIRS = [
    "multi-llm-reviewer",
    "clauseguard",
    "docveil",
    "compass-odi",
    "siactrack",
]


class PermissionEnforcer:
    """Load permissions.yaml and classify operations into green/yellow/red/block."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = Path(config_path) if config_path else PERMISSIONS_PATH
        self.config = self._load_config()
        self._compile_patterns()

    def _load_config(self) -> dict:
        if not self.config_path.exists():
            return {"default": YELLOW}
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {"default": YELLOW}
        except Exception:
            return {"default": YELLOW}

    def _compile_patterns(self):
        """Pre-compile glob patterns for faster matching."""
        self._terminal_green = self._get_patterns("terminal", GREEN)
        self._terminal_yellow = self._get_patterns("terminal", YELLOW)
        self._terminal_red = self._get_patterns("terminal", RED)
        self._terminal_block = self._get_patterns("terminal", BLOCK)

    def _get_patterns(self, category: str, level: str) -> list:
        """Extract pattern list from config."""
        try:
            return self.config.get(category, {}).get(level, [])
        except (AttributeError, TypeError):
            return []

    # ── Terminal command classification ──────────────────────────────

    def classify_terminal(self, command: str) -> Tuple[str, str]:
        """
        Classify a terminal command.
        Returns (level, reason) where level is green/yellow/red/block.
        """
        if not command or not command.strip():
            return GREEN, "empty command"

        cmd = command.strip()

        # Check block first (most restrictive)
        for pattern in self._terminal_block:
            if self._match_command(cmd, pattern):
                level, reason = BLOCK, f"matches blocked pattern: {pattern}"
                self._audit("terminal", cmd, level, reason)
                return level, reason

        # Check hard redlines (rm -rf dangerous paths)
        rmrf_check = self._check_rmrf_redlines(cmd)
        if rmrf_check:
            self._audit("terminal", cmd, rmrf_check[0], rmrf_check[1])
            return rmrf_check

        # Check red
        for pattern in self._terminal_red:
            if self._match_command(cmd, pattern):
                reason = self._human_reason(RED, "terminal", cmd, pattern)
                self._audit("terminal", cmd, RED, reason)
                return RED, reason

        # Check yellow
        for pattern in self._terminal_yellow:
            if self._match_command(cmd, pattern):
                reason = self._human_reason(YELLOW, "terminal", cmd, pattern)
                self._audit("terminal", cmd, YELLOW, reason)
                return YELLOW, reason

        # Check green
        for pattern in self._terminal_green:
            if self._match_command(cmd, pattern):
                reason = self._human_reason(GREEN, "terminal", cmd, pattern)
                self._audit("terminal", cmd, GREEN, reason)
                return GREEN, reason

        # Default
        default = self.config.get("default", YELLOW)
        reason = f"unmatched command, default={default}"
        self._audit("terminal", cmd, default, reason)
        return default, reason

    # ── File write classification ────────────────────────────────────

    def classify_file_write(self, path: str) -> Tuple[str, str]:
        """
        Classify a file write operation by target path.
        Returns (level, reason).
        """
        file_path = Path(path).expanduser().resolve()

        # Hard redline: never write to redline project directories
        for dirname in REDLINE_DIRS:
            redline_path = Path.home() / dirname
            try:
                if str(file_path).startswith(str(redline_path)):
                    reason = f"writing to redline project directory: ~/{dirname}"
                    self._audit("file_write", path, BLOCK, reason)
                    return BLOCK, reason
            except (ValueError, OSError):
                continue

        # Check block paths
        for pattern in self._get_file_patterns("block"):
            if self._match_path(file_path, pattern):
                reason = f"writing to blocked path: {pattern}"
                self._audit("file_write", path, BLOCK, reason)
                return BLOCK, reason

        # Check green paths
        for pattern in self._get_file_paths("green"):
            if self._match_path(file_path, pattern):
                reason = f"writing to safe path"
                self._audit("file_write", path, GREEN, reason)
                return GREEN, reason

        # Check yellow paths
        for pattern in self._get_file_paths("yellow"):
            if self._match_path(file_path, pattern):
                reason = f"writing to config/project path"
                self._audit("file_write", path, YELLOW, reason)
                return YELLOW, reason

        # Check red paths
        for pattern in self._get_file_paths("red"):
            if self._match_path(file_path, pattern):
                reason = f"writing to sensitive path"
                self._audit("file_write", path, RED, reason)
                return RED, reason

        # Default
        default = self.config.get("default", YELLOW)
        reason = f"unmatched path, default={default}"
        self._audit("file_write", path, default, reason)
        return default, reason

    # ── Tool call classification ────────────────────────────────────

    def classify_tool_call(self, tool_name: str, args: dict) -> Tuple[str, str]:
        """
        Classify a tool call by tool name and arguments.
        Returns (level, reason).
        """
        # Build tool:action key (e.g. "cronjob:create", "memory:add")
        tool_key = tool_name
        if "action" in args:
            tool_key = f"{tool_name}:{args['action']}"
        elif "action" in args:
            tool_key = f"{tool_name}:{args.get('action', tool_name)}"

        # Check green tools
        green_tools = self.config.get("tool_call", {}).get(GREEN, [])
        if tool_key in green_tools or tool_name in green_tools:
            reason = f"tool {tool_key} is green-listed"
            self._audit("tool_call", tool_key, GREEN, reason)
            return GREEN, reason

        # Check yellow tools
        yellow_tools = self.config.get("tool_call", {}).get(YELLOW, [])
        if tool_key in yellow_tools or tool_name in yellow_tools:
            reason = f"tool {tool_key} is yellow-listed"
            self._audit("tool_call", tool_key, YELLOW, reason)
            return YELLOW, reason

        # Check red tools
        red_tools = self.config.get("tool_call", {}).get(RED, [])
        if tool_key in red_tools or tool_name in red_tools:
            reason = f"tool {tool_key} modifies persistent state"
            self._audit("tool_call", tool_key, RED, reason)
            return RED, reason

        # Special: terminal tool delegates to terminal classification
        if tool_name == "terminal":
            command = args.get("command", "")
            return self.classify_terminal(command)

        # Special: file tools delegate to file classification
        if tool_name in ("write_file", "patch"):
            path = args.get("path", "")
            return self.classify_file_write(path)

        # Default
        default = self.config.get("default", YELLOW)
        reason = f"unknown tool {tool_key}, default={default}"
        self._audit("tool_call", tool_key, default, reason)
        return default, reason

    # ── Human-readable reasons ──────────────────────────────────────

    REASONS = {
        (RED, "terminal", "git push*"): "这会把你的代码公开推到远程仓库。推完收不回来，其他人都能看到。要继续吗？",
        (RED, "terminal", "git push --force*"): "这会强制推送并覆盖远程历史。极其危险且不可逆。要继续吗？",
        (BLOCK, "terminal", "rm -rf"): "永久删除系统目录，绝对不允许。",
        (BLOCK, "file_write", "redline"): "这是你的客户交付项目目录，绝对不允许修改。",
    }

    def _human_reason(self, level: str, category: str, operation: str, pattern: str) -> str:
        """Generate a lawyer-understandable reason for the classification."""
        key = (level, category, pattern)
        if key in self.REASONS:
            return self.REASONS[key]

        if level == RED:
            if category == "terminal":
                return f"这个操作会对外部产生影响，做了收不回来。要继续吗？"
            return f"这个操作不可逆，需要你确认。"

        if level == YELLOW:
            return f"auto-action: {operation}"

        return f"auto-approved: {operation}"

    # ── Helper methods ──────────────────────────────────────────────

    def _match_command(self, command: str, pattern: str) -> bool:
        """Match a command against a glob pattern."""
        # Normalize: compare just the beginning of the command
        cmd_start = command.split("&&")[0].split(";")[0].split("|")[0].strip()

        # If the command contains compound operators, check if ANY sub-command matches
        sub_commands = re.split(r'(?:&&|;|\|)\s*', command)
        # We match the full command against the pattern (most restrictive)
        if fnmatch.fnmatch(command, pattern):
            return True
        # Also match just the first word + arguments
        if fnmatch.fnmatch(cmd_start, pattern):
            return True
        return False

    def _check_rmrf_redlines(self, command: str) -> Optional[Tuple[str, str]]:
        """Check if command contains rm -rf targeting dangerous paths.
        
        Safe rm -rf targets (tmp, hermes, var/folders) return None (not a block).
        Unsafe rm -rf targets return BLOCK.
        """
        if not re.search(r'rm\s+(-\w*[rf]\w*|--recursive|--force)', command):
            return None

        # Safe rm -rf targets — these are yellow, not block
        safe_prefixes = ['/tmp/', '/var/folders/', '/private/tmp/']
        hermes_prefix = str(Path.home() / '.hermes/')
        
        # Extract what's being deleted
        target_match = re.search(r'rm\s+(?:-\w*\s+|--recursive\s+|--force\s+)+(.+)', command)
        if target_match:
            target = target_match.group(1).strip().strip("'\"")
            target_expanded = Path(target).expanduser().resolve()
            # Check if target is in safe paths
            if str(target_expanded).startswith(hermes_prefix):
                return None  # Safe: hermes directory
            if any(str(target_expanded).startswith(Path(s).resolve().as_posix()) for s in safe_prefixes):
                return None  # Safe: tmp/var
        
        # If we got here, it's rm -rf targeting something we can't verify as safe
        # Block it
        return BLOCK, "permanent deletion outside safe directories"

    def _get_file_paths(self, level: str) -> list:
        """Get file path patterns for a level."""
        try:
            paths = self.config.get("file_write", {}).get(level, {}).get("paths", [])
            if isinstance(paths, list):
                return paths
        except (AttributeError, TypeError):
            pass
        return []

    def _get_file_patterns(self, level: str) -> list:
        """Alias for _get_file_paths."""
        return self._get_file_paths(level)

    def _match_path(self, file_path: Path, pattern: str) -> bool:
        """Match a file path against a glob pattern.
        
        Patterns use ** for recursive matching (e.g. ~/.hermes/scripts/**).
        Strips trailing /** for prefix matching.
        """
        # Strip trailing /** and just use prefix matching
        clean_pattern = pattern.rstrip("/").rstrip("*").rstrip("/").rstrip("*")
        if not clean_pattern:
            clean_pattern = pattern
        expanded = Path(clean_pattern).expanduser().resolve()
        try:
            return str(file_path).startswith(str(expanded) + "/") or str(file_path) == str(expanded)
        except (ValueError, TypeError):
            return False

    # ── Audit logging ───────────────────────────────────────────────

    def _audit(self, operation_type: str, operation: str, level: str, reason: str):
        """Write permission decision to audit log."""
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": operation_type,
            "operation": operation[:200],  # Truncate for safety
            "level": level,
            "reason": reason,
        }
        try:
            log_file = AUDIT_DIR / "permissions.jsonl"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass  # Audit logging is best-effort, never block operations


# ── Module-level singleton ──────────────────────────────────────────

_enforcer: Optional[PermissionEnforcer] = None


def get_enforcer(config_path: Optional[str] = None) -> PermissionEnforcer:
    """Get or create the singleton PermissionEnforcer."""
    global _enforcer
    if _enforcer is None or config_path:
        _enforcer = PermissionEnforcer(config_path=config_path)
    return _enforcer


def classify_terminal(command: str) -> Tuple[str, str]:
    """Convenience function: classify a terminal command."""
    return get_enforcer().classify_terminal(command)


def classify_file_write(path: str) -> Tuple[str, str]:
    """Convenience function: classify a file write."""
    return get_enforcer().classify_file_write(path)


def classify_tool_call(tool_name: str, args: dict) -> Tuple[str, str]:
    """Convenience function: classify a tool call."""
    return get_enforcer().classify_tool_call(tool_name, args)