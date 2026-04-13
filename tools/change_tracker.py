"""
Change Tracker — Layer F: Records code file changes for audit enforcement.

Hooks into file_tools.py and terminal_tool.py to track when code files are
modified, classifying changes as logic/docs/comments/whitespace/mixed.

Stores entries in ~/.hermes/audit/changes.jsonl
Thread-safe via _write_lock (same pattern as audit_logger.py).
"""

import os
import re
import hashlib
import json
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

_write_lock = threading.Lock()

# File extensions classified as documentation (never require audit)
DOCS_EXTENSIONS = {'.md', '.txt', '.rst', '.adoc', '.tex', '.html', '.css'}

# File extensions classified as configuration (always require audit)
CONFIG_EXTENSIONS = {'.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.env'}

# File patterns that are always trivial (never require audit)
TRIVIAL_PATTERNS = {'.gitignore', 'LICENSE', 'COPYING', '.keep', '.placeholder'}


def get_hermes_home() -> Path:
    """Return Hermes home directory."""
    from hermes_constants import get_hermes_home as _get_hermes_home
    return Path(_get_hermes_home())


def _get_changes_path() -> Path:
    """Get the changes log file path."""
    audit_dir = get_hermes_home() / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    return audit_dir / "changes.jsonl"


def _get_timestamp() -> str:
    """Get ISO8601 timestamp with +08:00 offset."""
    tz_utc8 = timezone(timedelta(hours=8))
    return datetime.now(tz_utc8).strftime("%Y-%m-%dT%H:%M:%S%z")


def _hash_content(content: str) -> str:
    """Hash file content for change verification."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]


def classify_change(diff_text: str, file_path: str) -> str:
    """
    Classify a change by type.

    Returns one of: 'docs', 'comments', 'whitespace', 'logic', 'mixed'

    Logic:
    - .md/.txt/.rst etc → 'docs'
    - .json/.yaml/.toml etc → 'config' (treated as 'logic' for audit purposes)
    - Analyze diff lines:
      - If all added lines are whitespace → 'whitespace'
      - If all added lines are comments (#, //, /*) → 'comments'
      - If any added line is logic (code) → 'logic'
      - Mix of both → 'mixed'
    """
    path = Path(file_path)
    ext = path.suffix.lower()
    name = path.name

    # Trivial files never require audit
    if name in TRIVIAL_PATTERNS:
        return 'whitespace'

    # Pure documentation files
    if ext in DOCS_EXTENSIONS:
        return 'docs'

    # Configuration files are always 'logic' (can change behavior)
    if ext in CONFIG_EXTENSIONS:
        return 'logic'

    # No diff text means we can't analyze — assume logic to be safe
    if not diff_text or not diff_text.strip():
        return 'logic'

    logic_lines = 0
    comment_lines = 0
    whitespace_lines = 0
    docstring_lines = 0

    for line in diff_text.split('\n'):
        # Only count added lines (lines starting with +, but not +++ header)
        if not line.startswith('+') or line.startswith('+++'):
            continue
        content = line[1:].strip()

        if not content:
            whitespace_lines += 1
        elif content.startswith('#') or content.startswith('//') or content.startswith('/*') or content.startswith('*'):
            comment_lines += 1
        elif content.startswith('"""') or content.startswith("'''"):
            docstring_lines += 1
        else:
            logic_lines += 1

    # Classification priority: logic > docstring > comment > whitespace
    if logic_lines > 0:
        return 'logic'
    if docstring_lines > 0:
        return 'comments'  # Docstrings are comment-like
    if comment_lines > 0:
        return 'comments'
    if whitespace_lines > 0:
        return 'whitespace'

    # Default: treat unknown as logic (safe side)
    return 'logic'


def record_change(
    file_path: str,
    operation: str,
    diff_text: str = "",
    content_hash: Optional[str] = None,
) -> None:
    """
    Record a file change in the changes log.

    Args:
        file_path: Path to the modified file
        operation: Type of operation ('write_file', 'patch', 'git_commit')
        diff_text: Diff text for classification (empty string = unknown)
        content_hash: Optional hash of file content for verification
    """
    try:
        change_type = classify_change(diff_text, file_path)

        # For write_file without diff, hash the content if provided
        if not content_hash and operation == 'write_file':
            content_hash = _hash_content(diff_text) if diff_text else None

        entry = {
            "timestamp": _get_timestamp(),
            "file": file_path,
            "operation": operation,
            "change_type": change_type,
            "diff_hash": content_hash or "unknown",
            "audited": False,
            "passport_id": None,
        }

        changes_path = _get_changes_path()
        with _write_lock:
            with open(changes_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        # Never let tracking break file operations
        pass


def get_unaudited_logic_changes() -> list:
    """
    Get all logic/config changes that have not been audited.

    Returns list of dicts with file, timestamp, change_type, diff_hash.
    """
    try:
        changes_path = _get_changes_path()
        if not changes_path.exists():
            return []

        unaudited = []
        with _write_lock:
            with open(changes_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if not entry.get("audited", False) and entry.get("change_type") in ("logic", "config"):
                            unaudited.append(entry)
                    except json.JSONDecodeError:
                        continue

        return unaudited
    except Exception:
        return []


def mark_changes_audited(passport_id: str, files_audited: list, diff_hashes: list) -> int:
    """
    Mark matching changes as audited after an audit passport is written.

    Args:
        passport_id: ID of the audit passport
        files_audited: List of file paths that were audited
        diff_hashes: List of diff hashes covered by the audit

    Returns:
        Number of entries updated
    """
    try:
        changes_path = _get_changes_path()
        if not changes_path.exists():
            return 0

        updated = 0
        lines = []
        with _write_lock:
            with open(changes_path, "r", encoding="utf-8") as f:
                for line in f:
                    line_stripped = line.strip()
                    if not line_stripped:
                        continue
                    try:
                        entry = json.loads(line_stripped)
                        # Match by file path or diff hash
                        if (entry.get("file") in files_audited or
                            entry.get("diff_hash") in diff_hashes):
                            if not entry.get("audited", False):
                                entry["audited"] = True
                                entry["passport_id"] = passport_id
                                updated += 1
                        lines.append(json.dumps(entry, ensure_ascii=False))
                    except json.JSONDecodeError:
                        lines.append(line_stripped)

            # Rewrite file with updated entries
            with open(changes_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")

        return updated
    except Exception:
        return 0