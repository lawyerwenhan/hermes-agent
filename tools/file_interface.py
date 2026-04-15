
"""
File Interface for Subagent Data Passing

When upstream produces structured data >500 chars, it writes to a file
and passes {__hermes_file_ref: "/path/to/file"} in the context field.
The delegate_tool handler detects this key and reads the file content
into the child agent's context.

Standard metadata format for subagent output files.
"""

import json
import os
import time
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


def get_task_output_dir() -> str:
    """Return the directory for subagent task outputs."""
    from hermes_constants import get_hermes_home
    base = os.path.join(get_hermes_home(), "task-outputs")
    os.makedirs(base, exist_ok=True)
    return base


def write_task_output(
    payload: Any,
    task_id: str,
    upstream_skill: str,
    content_type: str = "result",
    ttl_hours: int = 24,
) -> str:
    """Write a structured task output file.
    
    Returns the file path written.
    """
    output_dir = get_task_output_dir()
    filename = f"{task_id}_{upstream_skill}_{content_type}.json"
    filepath = os.path.join(output_dir, filename)
    
    envelope = {
        "_hermes_meta": {
            "task_id": task_id,
            "upstream_skill": upstream_skill,
            "type": content_type,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ttl_hours": ttl_hours,
        },
        "payload": payload,
    }
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(envelope, f, ensure_ascii=False, indent=2)
    
    return filepath


def read_task_output(filepath: str) -> Optional[Dict[str, Any]]:
    """Read a task output file. Returns None if file doesn't exist or is invalid."""
    if not os.path.isfile(filepath):
        logger.warning("Task output file not found: %s", filepath)
        return None
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read task output %s: %s", filepath, exc)
        return None


def resolve_file_refs(context: str) -> str:
    """If context contains __hermes_file_ref, read the file and merge content.
    
    The context string may contain a JSON object with __hermes_file_ref key.
    If found, the referenced file content is read and appended to context.
    If context is plain text (no JSON), it's returned as-is.
    """
    if not context or not context.strip():
        return context
    
    # Try to detect __hermes_file_ref in the context
    # Two patterns:
    # 1. Entire context is a JSON with __hermes_file_ref
    # 2. Context contains the key inline
    
    file_ref = None
    remaining_context = context
    
    try:
        parsed = json.loads(context)
        if isinstance(parsed, dict) and "__hermes_file_ref" in parsed:
            file_ref = parsed["__hermes_file_ref"]
            # Remove the key from context, keep other fields
            remaining = {k: v for k, v in parsed.items() if k != "__hermes_file_ref"}
            remaining_context = json.dumps(remaining, ensure_ascii=False) if remaining else ""
    except (json.JSONDecodeError, ValueError):
        # Not JSON — check for inline __hermes_file_ref pattern
        import re
        match = re.search(r'"__hermes_file_ref"\s*:\s*"([^"]+)"', context)
        if match:
            file_ref = match.group(1)
    
    if not file_ref:
        return context
    
    file_content = read_task_output(file_ref)
    if file_content is None:
        logger.warning("__hermes_file_ref pointed to invalid file: %s", file_ref)
        return context
    
    # Merge file content into context
    payload = file_content.get("payload", {})
    payload_str = json.dumps(payload, ensure_ascii=False, indent=2) if isinstance(payload, (dict, list)) else str(payload)
    
    meta = file_content.get("_hermes_meta", {})
    upstream = meta.get("upstream_skill", "unknown")
    
    merged = remaining_context
    if merged.strip():
        merged += f"\n\n[FILE REF: {file_ref}]\n[FROM: {upstream}]\n{payload_str}"
    else:
        merged = f"[FILE REF: {file_ref}]\n[FROM: {upstream}]\n{payload_str}"
    
    return merged


def cleanup_task_files(task_id: str) -> int:
    """Remove all task output files for a given task_id. Returns count deleted."""
    output_dir = get_task_output_dir()
    if not os.path.isdir(output_dir):
        return 0
    
    deleted = 0
    for fname in os.listdir(output_dir):
        if fname.startswith(f"{task_id}_"):
            try:
                os.remove(os.path.join(output_dir, fname))
                deleted += 1
            except OSError:
                pass
    return deleted


def cleanup_expired_files() -> int:
    """Remove task output files older than their TTL. Returns count deleted."""
    output_dir = get_task_output_dir()
    if not os.path.isdir(output_dir):
        return 0
    
    now = time.time()
    deleted = 0
    
    for fname in os.listdir(output_dir):
        fpath = os.path.join(output_dir, fname)
        if not fname.endswith(".json"):
            continue
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            meta = data.get("_hermes_meta", {})
            created_str = meta.get("created_at", "")
            ttl = meta.get("ttl_hours", 24)
            if created_str:
                created_ts = time.mktime(time.strptime(created_str, "%Y-%m-%dT%H:%M:%SZ"))
                if now - created_ts > ttl * 3600:
                    os.remove(fpath)
                    deleted += 1
        except (json.JSONDecodeError, OSError, ValueError):
            # If we can't parse it and it's >48h old by mtime, clean it
            try:
                mtime = os.path.getmtime(fpath)
                if now - mtime > 48 * 3600:
                    os.remove(fpath)
                    deleted += 1
            except OSError:
                pass
    
    return deleted
