#!/usr/bin/env python3
"""
Health Metrics Module — Records and queries health issues for the harness
engineering system.  Designed to be imported by cron jobs for automated
issue tracking.

Data store: ~/.hermes/health/metrics.jsonl  (append-only JSONL)

Entry schema:
    id           — auto-generated UUID4
    timestamp    — ISO 8601 (UTC)
    fingerprint  — sha256(module_path:error_type:context_or_desc)[:16]
    module_path  — e.g. "tools/terminal_tool.py"
    error_type   — e.g. "syntax_error", "import_error", "logic_bug"
    severity     — "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    description  — human-readable description
    context      — optional extra context
    status       — "OPEN" | "FIXING" | "FIXED" | "CLOSED" | "ESCALATED" | "WONTFIX"
    attempts     — deduplication counter (0 for new, increments on re-hit)
    last_attempt — ISO 8601 timestamp of most recent dedup hit (null if new)

Deduplication:
    Before writing a new entry, check for an OPEN issue with the same
    fingerprint in the last 7 days.  If found, increment its `attempts`
    and update `last_attempt` instead of creating a duplicate.
"""

import json
import hashlib
import threading
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from tools.registry import registry, tool_result, tool_error

_write_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Path helpers (always use get_hermes_home from hermes_constants)
# ---------------------------------------------------------------------------

def _get_hermes_home() -> Path:
    """Return the Hermes home directory via hermes_constants."""
    from hermes_constants import get_hermes_home
    return Path(get_hermes_home())


def _get_health_dir() -> Path:
    """Return the health directory, creating it if needed."""
    health_dir = _get_hermes_home() / "health"
    health_dir.mkdir(parents=True, exist_ok=True)
    return health_dir


def _get_metrics_path() -> Path:
    """Return the metrics.jsonl file path."""
    return _get_health_dir() / "metrics.jsonl"


# ---------------------------------------------------------------------------
# Fingerprint computation
# ---------------------------------------------------------------------------

def _compute_fingerprint(module_path: str, error_type: str, context: str, description: str) -> str:
    """Compute a 16-char fingerprint from sha256 of key fields."""
    source = context or (description[:50] if description else "")
    raw = f"{module_path}:{error_type}:{source}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _compute_context_hash(context: str) -> str:
    """Compute a 12-char hash from context, or empty string if no context."""
    if not context:
        return ""
    return hashlib.sha256(context.encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def record_issue(
    file_path: str,
    error_type: str,
    severity: str,
    description: str,
    context: str = "",
) -> str:
    """
    Record a health issue.  Deduplicates by fingerprint within the last 7 days.

    Args:
        file_path:   Module file path, e.g. "tools/terminal_tool.py"
        error_type:  Error category, e.g. "syntax_error", "import_error"
        severity:    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        description: Human-readable description of the issue
        context:     Optional extra context string

    Returns:
        JSON string with the issue ID (or the existing ID if dedup hit).
    """
    severity = severity.upper()
    if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return tool_error(f"Invalid severity: {severity!r}. Must be CRITICAL|HIGH|MEDIUM|LOW")

    fingerprint = _compute_fingerprint(file_path, error_type, context, description)
    context_hash = _compute_context_hash(context)
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    metrics_path = _get_metrics_path()

    with _write_lock:
        # --- Deduplication check ------------------------------------------------
        existing_id = None
        SevenDays = timedelta(days=7)
        cutoff = now - SevenDays

        if metrics_path.exists():
            with open(metrics_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # Walk backwards so we find the most recent match first
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (
                    entry.get("fingerprint") == fingerprint
                    and entry.get("status") == "OPEN"
                ):
                    # Check timestamp is within 7 days
                    try:
                        ts = datetime.fromisoformat(entry.get("timestamp", ""))
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        if ts >= cutoff:
                            existing_id = entry["id"]
                            break
                    except (ValueError, TypeError):
                        continue

        if existing_id:
            # Update the existing entry by appending an updated copy
            updated = dict(entry)
            updated["attempts"] = updated.get("attempts", 0) + 1
            updated["last_attempt"] = now_iso
            # Re-write to file (append updated entry; consumers should use
            # the latest entry for a given ID)
            with open(metrics_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(updated, ensure_ascii=False) + "\n")
            return tool_result({"id": existing_id, "action": "dedup_update", "attempts": updated["attempts"]})

        # --- New entry -----------------------------------------------------------
        issue_id = str(uuid.uuid4())
        entry = {
            "id": issue_id,
            "timestamp": now_iso,
            "fingerprint": fingerprint,
            "module_path": file_path,
            "error_type": error_type,
            "severity": severity,
            "description": description,
            "context": context,
            "context_hash": context_hash,
            "status": "OPEN",
            "attempts": 0,
            "last_attempt": None,
        }

        with open(metrics_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    return tool_result({"id": issue_id, "action": "created"})


def query_issues(
    status: str = "OPEN",
    severity: Optional[str] = None,
    days: int = 7,
    fingerprint: Optional[str] = None,
) -> str:
    """
    Query health issues from metrics.jsonl.

    Args:
        status:      Filter by issue status (default "OPEN")
        severity:    Filter by severity (optional)
        days:        Look back this many days (default 7)
        fingerprint: Filter by fingerprint (optional)

    Returns:
        JSON string with list of matching issues sorted by timestamp desc.
    """
    metrics_path = _get_metrics_path()
    if not metrics_path.exists():
        return tool_result([])

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)

    # Build a map of id -> latest entry (for dedup entries, we want the
    # most recent version)
    latest_by_id = {}

    with open(metrics_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            entry_id = entry.get("id", "")
            ts_str = entry.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue

            # Always keep the latest version of each ID
            if entry_id not in latest_by_id or ts > latest_by_id[entry_id]["_ts"]:
                entry["_ts"] = ts
                latest_by_id[entry_id] = entry

    # Filter and collect matches
    results = []
    for entry in latest_by_id.values():
        ts = entry.pop("_ts", None)
        if ts is None:
            continue

        # Filter by cutoff date
        if ts < cutoff:
            continue

        # Filter by status
        if status and entry.get("status") != status:
            continue

        # Filter by severity
        if severity and entry.get("severity") != severity.upper():
            continue

        # Filter by fingerprint
        if fingerprint and entry.get("fingerprint") != fingerprint:
            continue

        results.append(entry)

    # Sort by timestamp descending
    results.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return tool_result(results)


def update_issue(issue_id: str, **kwargs) -> str:
    """
    Update an existing issue by ID.

    Appends a new entry with the same ID but updated fields.  Consumers
    should treat the latest entry for a given ID as the current state.

    Common kwargs:
        status      — "OPEN" → "FIXING" → "FIXED" → "CLOSED", or "ESCALATED"/"WONTFIX"
        description — updated description
        attempts    — override attempts count
        context     — updated context

    Returns:
        JSON string with success=True on success.
    """
    metrics_path = _get_metrics_path()

    # Find the latest entry for this ID
    latest_entry = None

    with _write_lock:
        if not metrics_path.exists():
            return tool_error(f"Issue {issue_id!r} not found")

        with open(metrics_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("id") == issue_id:
                    latest_entry = entry

        if latest_entry is None:
            return tool_error(f"Issue {issue_id!r} not found")

        # Apply updates
        updated = dict(latest_entry)
        for key in ("status", "description", "attempts", "context"):
            if key in kwargs:
                updated[key] = kwargs[key]

        updated["timestamp"] = datetime.now(timezone.utc).isoformat()

        # If status changed, update context_hash if context changed
        if "context" in kwargs:
            updated["context_hash"] = _compute_context_hash(kwargs["context"])

        with open(metrics_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(updated, ensure_ascii=False) + "\n")

    return tool_result({"id": issue_id, "action": "updated", "updated_fields": list(kwargs.keys())})


def get_health_summary() -> str:
    """
    Get a summary of current health issues.

    Returns:
        JSON string with:
            open_by_severity: {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N}
            total_open: N
            recently_fixed: N (issues fixed in last 7 days)
            escalated: N (issues escalated in last 7 days)
    """
    metrics_path = _get_metrics_path()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=7)

    summary = {
        "open_by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "total_open": 0,
        "recently_fixed": 0,
        "escalated": 0,
    }

    if not metrics_path.exists():
        return tool_result(summary)

    # Build latest-by-id map
    latest_by_id = {}
    with open(metrics_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            entry_id = entry.get("id", "")
            ts_str = entry.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue

            if entry_id not in latest_by_id or ts > latest_by_id[entry_id]["_ts"]:
                entry["_ts"] = ts
                latest_by_id[entry_id] = entry

    for entry in latest_by_id.values():
        ts = entry.get("_ts")
        if ts is None or ts < cutoff:
            continue

        status = entry.get("status", "")
        severity = entry.get("severity", "")

        if status == "OPEN":
            summary["total_open"] += 1
            if severity in summary["open_by_severity"]:
                summary["open_by_severity"][severity] += 1
        elif status == "FIXED":
            summary["recently_fixed"] += 1
        elif status == "ESCALATED":
            summary["escalated"] += 1

    return tool_result(summary)


# ---------------------------------------------------------------------------
# Requirements check
# ---------------------------------------------------------------------------

def check_requirements() -> bool:
    """Health metrics module has no external dependencies — always available."""
    return True


# =============================================================================
# Registry — OpenAI function-calling schemas
# =============================================================================

RECORD_ISSUE_SCHEMA = {
    "name": "record_issue",
    "description": (
        "Record a health issue in the metrics log. Deduplicates identical "
        "issues within 7 days by incrementing an attempts counter. "
        "Returns the issue ID."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Module file path, e.g. 'tools/terminal_tool.py'",
            },
            "error_type": {
                "type": "string",
                "description": "Error category: syntax_error, import_error, logic_bug, etc.",
            },
            "severity": {
                "type": "string",
                "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                "description": "Severity level of the issue.",
            },
            "description": {
                "type": "string",
                "description": "Human-readable description of the issue.",
            },
            "context": {
                "type": "string",
                "description": "Optional extra context or detail about the issue.",
            },
        },
        "required": ["file_path", "error_type", "severity", "description"],
    },
}

QUERY_ISSUES_SCHEMA = {
    "name": "query_issues",
    "description": (
        "Query health issues from the metrics log. Filters by status, "
        "severity, days, and fingerprint. Returns list of matching issues "
        "sorted by timestamp descending."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "description": "Filter by issue status (default: OPEN).",
                "default": "OPEN",
            },
            "severity": {
                "type": "string",
                "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                "description": "Filter by severity level (optional).",
            },
            "days": {
                "type": "integer",
                "description": "Look back this many days (default: 7).",
                "default": 7,
            },
            "fingerprint": {
                "type": "string",
                "description": "Filter by fingerprint (optional).",
            },
        },
        "required": [],
    },
}

UPDATE_ISSUE_SCHEMA = {
    "name": "update_issue",
    "description": (
        "Update an existing health issue by ID. Common updates: change "
        "status (OPEN→FIXING→FIXED→CLOSED or ESCALATED/WONTFIX), update "
        "description, or override attempts count."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "issue_id": {
                "type": "string",
                "description": "The UUID of the issue to update.",
            },
            "status": {
                "type": "string",
                "enum": ["OPEN", "FIXING", "FIXED", "CLOSED", "ESCALATED", "WONTFIX"],
                "description": "New status for the issue.",
            },
            "description": {
                "type": "string",
                "description": "Updated description.",
            },
            "attempts": {
                "type": "integer",
                "description": "Override the attempts counter.",
            },
            "context": {
                "type": "string",
                "description": "Updated context string.",
            },
        },
        "required": ["issue_id"],
    },
}

GET_HEALTH_SUMMARY_SCHEMA = {
    "name": "get_health_summary",
    "description": (
        "Get a summary of current health issues: open issues by severity, "
        "total open, recently fixed (last 7 days), and escalated count."
    ),
    "parameters": {
        "type": "object",
        "properties": {},
        "required": [],
    },
}

# --- Register all tools ---

registry.register(
    name="record_issue",
    toolset="health",
    schema=RECORD_ISSUE_SCHEMA,
    handler=lambda args, **kw: record_issue(
        file_path=args["file_path"],
        error_type=args["error_type"],
        severity=args["severity"],
        description=args["description"],
        context=args.get("context", ""),
    ),
    check_fn=check_requirements,
    emoji="🩺",
    permission_level="write",
)

registry.register(
    name="query_issues",
    toolset="health",
    schema=QUERY_ISSUES_SCHEMA,
    handler=lambda args, **kw: query_issues(
        status=args.get("status", "OPEN"),
        severity=args.get("severity"),
        days=args.get("days", 7),
        fingerprint=args.get("fingerprint"),
    ),
    check_fn=check_requirements,
    emoji="🔍",
    permission_level="read",
)

registry.register(
    name="update_issue",
    toolset="health",
    schema=UPDATE_ISSUE_SCHEMA,
    handler=lambda args, **kw: update_issue(
        issue_id=args["issue_id"],
        status=args.get("status"),
        description=args.get("description"),
        attempts=args.get("attempts"),
        context=args.get("context"),
    ),
    check_fn=check_requirements,
    emoji="🔧",
    permission_level="write",
)

registry.register(
    name="get_health_summary",
    toolset="health",
    schema=GET_HEALTH_SUMMARY_SCHEMA,
    handler=lambda args, **kw: get_health_summary(),
    check_fn=check_requirements,
    emoji="📊",
    permission_level="read",
)