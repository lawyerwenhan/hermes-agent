"""
Audit Guard — Layer F: Enforces audit requirement before git commit.

When a git commit is detected in terminal commands, checks whether any
logic/file changes have been audited. If unaudited logic changes exist,
blocks the commit and provides instructions for running the audit.

Trivial changes (docs, comments, whitespace) are auto-passed.
"""

import json
import shlex
from typing import Optional, Tuple


def _is_env_assignment(token: str) -> bool:
    """Return True for shell-style VAR=value prefixes."""
    if "=" not in token or token.startswith("="):
        return False
    name, _value = token.split("=", 1)
    return bool(name) and name.replace("_", "a").isalnum() and not name[0].isdigit()


def _consume_env_prefix(tokens: list[str], index: int) -> int:
    """Skip leading env assignments and optional `env` wrapper."""
    while index < len(tokens) and _is_env_assignment(tokens[index]):
        index += 1

    if index < len(tokens) and tokens[index] == "env":
        index += 1
        while index < len(tokens):
            token = tokens[index]
            if token == "--":
                index += 1
                break
            if token.startswith("-"):
                index += 1
                continue
            if _is_env_assignment(token):
                index += 1
                continue
            break
        while index < len(tokens) and _is_env_assignment(tokens[index]):
            index += 1

    return index


def _is_git_commit_command(command: str) -> bool:
    """Return True only when the parsed shell command is `git ... commit`."""
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return False

    if not tokens:
        return False

    index = _consume_env_prefix(tokens, 0)
    if index >= len(tokens) or tokens[index] != "git":
        return False

    index += 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return False
        if token == "commit":
            return True
        if not token.startswith("-"):
            return False

        if token == "--no-pager":
            index += 1
            continue
        if token == "-c":
            index += 2
            continue
        if token == "-C":
            index += 2
            continue
        if token.startswith("--git-dir="):
            index += 1
            continue
        if token == "--git-dir":
            index += 2
            continue
        if token.startswith("--work-tree="):
            index += 1
            continue
        if token == "--work-tree":
            index += 2
            continue
        return False

    return False


def is_git_commit(command: str) -> bool:
    """Check if a command is an actual git commit invocation."""
    return _is_git_commit_command(command)


def _test_git_commit_detection() -> None:
    """Sanity-check parser behavior for the supported git commit forms."""
    cases = {
        'git commit -m "message"': True,
        "git -c core.editor=true commit": True,
        "git --no-pager commit -m x": True,
        "git --git-dir=/foo commit": True,
        "echo git commit": False,
        'python -c "print(\\"git commit\\")"': False,
        "git log --oneline": False,
        "git status": False,
        "git show HEAD": False,
        "env VAR=1 git --no-pager commit -m x": True,
    }

    for command, expected in cases.items():
        actual = _is_git_commit_command(command)
        assert actual is expected, f"{command!r}: expected {expected}, got {actual}"


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
