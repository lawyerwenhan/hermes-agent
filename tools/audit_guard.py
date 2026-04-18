"""
Audit Guard — Layer F: Enforces audit requirement before git commit.

When a git commit is detected in terminal commands, checks whether any
logic/file changes have been audited. If unaudited logic changes exist,
blocks the commit and provides instructions for running the audit.

Trivial changes (docs, comments, whitespace) are auto-passed.
"""

# Path fix for cron/standalone runs - ensure hermes-agent root is importable
import sys
from pathlib import Path
HERMES_AGENT_ROOT = Path(__file__).parent.parent
if str(HERMES_AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(HERMES_AGENT_ROOT))

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

    # Command substitution bypass detection
    # Detect patterns like: bash -c "git commit", sh -c "git commit", eval "git commit"
    # Also detect: $(echo git commit), `echo git commit`
    for token in tokens:
        lowered = token.lower()
        # Detect bash/sh/zsh with -c flag (executes command string)
        if lowered in ('bash', 'sh', 'zsh', 'dash', 'ksh'):
            idx = tokens.index(token)
            if idx + 1 < len(tokens) and tokens[idx + 1] == '-c':
                # This is a shell execution with -c flag - potential bypass
                # Verify if the command string after -c contains git commit
                if idx + 2 < len(tokens):
                    inner_cmd = tokens[idx + 2]
                    if 'git' in inner_cmd and 'commit' in inner_cmd:
                        return True
                return False
        # Detect eval command
        if lowered == 'eval':
            idx = tokens.index(token)
            if idx + 1 < len(tokens):
                inner_cmd = tokens[idx + 1]
                if 'git' in inner_cmd and 'commit' in inner_cmd:
                    return True
            return False
        # Detect $() or backtick command substitution markers
        if '$(' in token or '`' in token:
            # Potential command substitution - contains git commit?
            if 'git' in token and 'commit' in token:
                return True

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
    except Exception as exc:
        return False, (
            "Audit check failed while evaluating commit safety: "
            f"{type(exc).__name__}: {exc}. Commit blocked."
        )

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
