"""
Audit Guard — Layer F: Enforces audit requirement before git commit.

When a git commit is detected in terminal commands, checks whether any
logic/file changes have been audited. If unaudited logic changes exist,
blocks the commit and provides instructions for running the audit.

Trivial changes (docs, comments, whitespace) are auto-passed.
"""

import re
import json
from typing import Tuple, Optional

# Pattern to detect git commit commands
_GIT_COMMIT_PATTERN = re.compile(
    r'\bgit\s+commit\b',
    re.IGNORECASE
)


def is_git_commit(command: str) -> bool:
    """Check if a command is a git commit."""
    return bool(_GIT_COMMIT_PATTERN.search(command))


def check_audit_requirement(command: str) -> Tuple[bool, Optional[str]]:
    """
    Check if a git commit command requires audit before proceeding.

    Args:
        command: The terminal command to check

    Returns:
        (approved, reason): 
        - (True, None) if approved (no logic changes, or all audited)
        - (False, reason_string) if blocked (unaudited logic changes)
    """
    if not is_git_commit(command):
        return True, None

    try:
        from tools.change_tracker import get_unaudited_logic_changes
        unaudited = get_unaudited_logic_changes()
    except Exception:
        # If change_tracker is unavailable, allow through (fail open)
        return True, None

    if not unaudited:
        # No unaudited logic changes — approve
        return True, None

    # There are unaudited logic changes
    files = [c.get("file", "?") for c in unaudited[:5]]
    file_list = "\n".join("  - " + f for f in files)
    if len(unaudited) > 5:
        file_list += f"\n  ... and {len(unaudited) - 5} more"

    reason = (
        "Audit required before commit — {} logic change(s) need Claude Code audit:\n"
        "{}\n\n"
        "Run audit first:\n"
        "  bash ~/.hermes/scripts/ask-claude.sh \"Audit these files and report findings\"\n\n"
        "Trivial changes (docs, comments, whitespace) are auto-passed and do not need audit."
    ).format(len(unaudited), file_list)

    return False, reason


def format_audit_block_message(command: str, reason: str) -> str:
    """Format the audit block message for terminal output."""
    import json
    return json.dumps({
        "output": "",
        "exit_code": -1,
        "error": reason,
        "status": "audit_required",
        "command": command,
    }, ensure_ascii=False)
