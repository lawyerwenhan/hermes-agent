"""
Change Tracker — Layer F: Records code file changes for audit enforcement.

Architecture: State-first + Audit Journal (debate v8 ruling)
- audit_state.json: current audit status for each file (O(1) reads)
- changes.jsonl: append-only audit journal (history, investigation, dispute)
- Writes update BOTH state file and journal
- Reads go to state file only
- Journal replay is emergency repair only, not startup path
- prev_hash chain in journal for tamper evidence
- fcntl-based interprocess locking for concurrent access
"""

import os
import re
import hashlib
import json
import threading
import fcntl
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


def _get_audit_dir() -> Path:
    """Get the audit directory, creating it if needed."""
    audit_dir = get_hermes_home() / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    return audit_dir


def _get_changes_path() -> Path:
    """Get the changes journal file path."""
    return _get_audit_dir() / "changes.jsonl"


def _get_state_path() -> Path:
    """Get the audit state file path."""
    return _get_audit_dir() / "audit_state.json"


def _get_changes_lock_path() -> Path:
    """Get the interprocess lock path for the changes journal."""
    return _get_changes_path().with_suffix(".lock")


def _normalize_file_path(file_path: str) -> str:
    """Normalize a file path consistently across tracking and auditing."""
    return os.path.normpath(os.path.abspath(file_path))


def _get_timestamp() -> str:
    """Get ISO8601 timestamp with +08:00 offset."""
    tz_utc8 = timezone(timedelta(hours=8))
    return datetime.now(tz_utc8).strftime("%Y-%m-%dT%H:%M:%S%z")


def _hash_content(content: str) -> str:
    """Hash file content for change verification."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]


def _compute_prev_hash(changes_path: Path) -> str:
    """Get the hash of the last entry in the journal for chain integrity."""
    try:
        if not changes_path.exists():
            return "genesis"
        last_line = None
        with open(changes_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        if last_line:
            return hashlib.sha256(last_line.encode('utf-8')).hexdigest()[:16]
        return "genesis"
    except Exception:
        return "genesis"


# ---------------------------------------------------------------------------
# State file management (O(1) reads)
# ---------------------------------------------------------------------------

def _read_state() -> dict:
    """Read the current audit state. Returns empty state if file doesn't exist."""
    state_path = _get_state_path()
    try:
        if state_path.exists():
            with open(state_path, "r", encoding="utf-8") as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError):
        pass
    return {"schema_version": 1, "last_updated": "", "files": {}}


def _write_state(state: dict) -> None:
    """Atomically write the audit state file."""
    state_path = _get_state_path()
    tmp_path = state_path.with_suffix(".tmp")
    state["last_updated"] = _get_timestamp()
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, state_path)


def _update_state_entry(file_path: str, change_type: str, diff_hash: str,
                        operation: str, audited: bool = False,
                        passport_id: Optional[str] = None) -> None:
    """Update a single file entry in the state file with interprocess locking."""
    file_path = _normalize_file_path(file_path)
    state_lock = _get_audit_dir() / ".audit_state.lock"
    with open(state_lock, "a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            state = _read_state()
            state["files"][file_path] = {
                "change_type": change_type,
                "diff_hash": diff_hash or "unknown",
                "operation": operation,
                "audited": audited,
                "passport_id": passport_id,
                "last_modified": _get_timestamp(),
            }
            _write_state(state)
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _mark_state_audited(files_audited: list, diff_hashes: list,
                         passport_id: str) -> int:
    """Mark files as audited in the state file with interprocess locking. AND logic.
    
    Checks both the state file (fast path) and the journal (fallback for
    overwritten diff_hashes when the same file is modified multiple times).
    """
    normalized_files = {_normalize_file_path(p): h for p, h in
                        zip(files_audited, diff_hashes)}
    state_lock = _get_audit_dir() / ".audit_state.lock"
    updated = 0
    with open(state_lock, "a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            state = _read_state()
            # Build a journal lookup for diff_hashes that don't match state
            journal_hashes = _build_journal_hash_lookup()
            for file_path, diff_hash in normalized_files.items():
                entry = state["files"].get(file_path)
                if entry and not entry.get("audited", False):
                    # Fast path: state file diff_hash matches
                    if entry.get("diff_hash") == diff_hash:
                        entry["audited"] = True
                        entry["passport_id"] = passport_id
                        updated += 1
                    elif file_path in journal_hashes and diff_hash in journal_hashes[file_path]:
                        # Fallback: diff_hash exists in journal for this file
                        entry["audited"] = True
                        entry["passport_id"] = passport_id
                        updated += 1
            if updated > 0:
                _write_state(state)
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    return updated


def _build_journal_hash_lookup() -> dict:
    """Build a lookup of {normalized_file_path: set_of_diff_hashes} from the journal.
    
    Used by _mark_state_audited as a fallback when the state file's diff_hash
    has been overwritten by a subsequent change to the same file.
    """
    lookup: dict[str, set[str]] = {}
    changes_path = _get_changes_path()
    if not changes_path.exists():
        return lookup
    try:
        with open(changes_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    file_path = _normalize_file_path(entry.get("file", ""))
                    diff_hash = entry.get("diff_hash", "")
                    if file_path and diff_hash:
                        lookup.setdefault(file_path, set()).add(diff_hash)
                except (json.JSONDecodeError, KeyError):
                    continue
    except Exception:
        pass
    return lookup


# ---------------------------------------------------------------------------
# Journal management (append-only audit log)
# ---------------------------------------------------------------------------

def _append_change_entry(changes_path: Path, entry: dict) -> None:
    """Append an entry while holding the interprocess lock."""
    with open(changes_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


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
    Record a file change: update state file (O(1) reads) AND append to journal.

    Args:
        file_path: Path to the modified file
        operation: Type of operation ('write_file', 'patch', 'git_commit', 'terminal_command')
        diff_text: Diff text for classification (empty string = unknown)
        content_hash: Optional hash of file content for verification
    """
    try:
        # Normalize path to avoid duplicate entries
        file_path = _normalize_file_path(file_path)

        change_type = classify_change(diff_text, file_path)

        # For write_file without diff, hash the content if provided
        if not content_hash and operation == 'write_file':
            content_hash = _hash_content(diff_text) if diff_text else None

        diff_hash = content_hash or "unknown"

        # Atomic journal + state update under single interprocess lock
        # Race condition fix: journal and state must be updated atomically
        changes_path = _get_changes_path()
        state_lock = _get_audit_dir() / ".audit_state.lock"
        lock_path = _get_changes_lock_path()

        with _write_lock:
            # Acquire both locks in consistent order to prevent deadlock
            with open(state_lock, "a+", encoding="utf-8") as state_lock_file:
                fcntl.flock(state_lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    with open(lock_path, "a+", encoding="utf-8") as lock_file:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                        try:
                            # 1. Append to journal FIRST
                            prev_hash = _compute_prev_hash(changes_path)
                            entry = {
                                "timestamp": _get_timestamp(),
                                "file": file_path,
                                "operation": operation,
                                "change_type": change_type,
                                "diff_hash": diff_hash,
                                "prev_hash": prev_hash,
                                "audited": False,
                                "passport_id": None,
                            }
                            _append_change_entry(changes_path, entry)

                            # 2. Update state atomically within same lock scope
                            state = _read_state()
                            state["files"][file_path] = {
                                "change_type": change_type,
                                "diff_hash": diff_hash or "unknown",
                                "operation": operation,
                                "audited": False,
                                "passport_id": None,
                                "last_modified": _get_timestamp(),
                            }
                            _write_state(state)
                        finally:
                            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                finally:
                    fcntl.flock(state_lock_file.fileno(), fcntl.LOCK_UN
)
    except Exception:
        # Never let tracking break file operations
        # Log failure for debugging but don't propagate
        import logging
        logging.getLogger("change_tracker").debug(
            "record_change failed for %s", file_path, exc_info=True
        )


def get_unaudited_logic_changes() -> list:
    """
    Get all logic/config changes that have not been audited.
    Reads from audit_state.json (O(1) per file) instead of scanning the journal.

    Returns list of dicts with file, timestamp, change_type, diff_hash.
    """
    try:
        state = _read_state()
        unaudited = []
        for file_path, entry in state.get("files", {}).items():
            if not entry.get("audited", False) and entry.get("change_type") in ("logic", "config"):
                unaudited.append({
                    "file": file_path,
                    "change_type": entry["change_type"],
                    "diff_hash": entry.get("diff_hash", "unknown"),
                    "last_modified": entry.get("last_modified", ""),
                })
        return unaudited
    except Exception:
        return []


def mark_changes_audited(passport_id: str, files_audited: list, diff_hashes: list) -> int:
    """
    Mark matching changes as audited: AND logic (both file AND hash must match).
    Updates BOTH state file and journal.

    Args:
        passport_id: ID of the audit passport
        files_audited: List of file paths that were audited
        diff_hashes: List of diff hashes covered by the audit

    Returns:
        Number of entries updated
    """
    try:
        # 1. Update state file (O(1) operation, with interprocess lock)
        state_updated = _mark_state_audited(files_audited, diff_hashes, passport_id)

        # 2. Journal is APPEND-ONLY — do NOT rewrite it.
        # Audited status is maintained in the state file only.
        # Previous versions rewrote the journal to set audited=True, which
        # broke the prev_hash chain (changing line content invalidates downstream hashes).
        # The state file is the authoritative source for audit status.
        # The journal's audited field is set at creation time and never updated.

        return state_updated
    except Exception:
        return 0


def rebuild_state_from_journal() -> int:
    """
    Emergency repair: rebuild audit_state.json from changes.jsonl.
    Should only be called when state file is missing or corrupted.

    Returns:
        Number of file entries rebuilt.
    """
    try:
        changes_path = _get_changes_path()
        if not changes_path.exists():
            return 0

        state = {"schema_version": 1, "last_updated": "", "files": {}}

        with open(changes_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    file_path = entry.get("file", "")
                    if not file_path:
                        continue
                    # Last entry wins — this is the current state
                    state["files"][file_path] = {
                        "change_type": entry.get("change_type", "logic"),
                        "diff_hash": entry.get("diff_hash", "unknown"),
                        "operation": entry.get("operation", ""),
                        "audited": entry.get("audited", False),
                        "passport_id": entry.get("passport_id"),
                        "last_modified": entry.get("timestamp", ""),
                    }
                except json.JSONDecodeError:
                    continue

        _write_state(state)
        return len(state["files"])
    except Exception:
        return 0


def verify_journal_integrity() -> dict:
    """
    Verify the prev_hash chain in the changes journal.
    Returns dict with 'valid' (bool), 'broken_at' (line number or None),
    and 'total_entries' (int).
    """
    try:
        changes_path = _get_changes_path()
        if not changes_path.exists():
            return {"valid": True, "broken_at": None, "total_entries": 0}

        prev_hash = "genesis"
        line_num = 0
        broken_at = None
        entries_with_prev_hash = 0

        with open(changes_path, "r", encoding="utf-8") as f:
            for line in f:
                line_num += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    entry_prev = entry.get("prev_hash")
                    # v1 entries (no prev_hash) are OK — they predate chain integrity
                    if entry_prev is not None:
                        entries_with_prev_hash += 1
                        if entry_prev != prev_hash:
                            broken_at = line_num
                            break
                    # Compute expected next prev_hash from raw line
                    prev_hash = hashlib.sha256(line.encode('utf-8')).hexdigest()[:16]
                except json.JSONDecodeError:
                    prev_hash = hashlib.sha256(line.encode('utf-8')).hexdigest()[:16]

        # If no entries had prev_hash, the chain is too old to verify — report valid
        if entries_with_prev_hash == 0:
            return {"valid": True, "broken_at": None, "total_entries": line_num,
                    "note": "v1 entries without prev_hash — chain integrity not verifiable"}

        return {
            "valid": broken_at is None,
            "broken_at": broken_at,
            "total_entries": line_num,
            "chained_entries": entries_with_prev_hash,
        }
    except Exception:
        return {"valid": False, "broken_at": None, "total_entries": 0}


def _rewrite_changes_file(changes_path: Path, lines: list) -> None:
    """Atomically rewrite the changes file while holding the interprocess lock."""
    tmp_path = changes_path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        if lines:
            f.write("\n".join(lines) + "\n")
        else:
            f.write("")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, changes_path)