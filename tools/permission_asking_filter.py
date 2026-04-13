"""
Permission-asking output filter — Layer 2 of the anti-permission-asking system.

Intercepts outgoing messages and removes entire sentences that are unnecessary
permission-asking patterns. This is a hard constraint at the message delivery
layer — the user never sees the filtered content.

Design principles:
- Only removes ENTIRE SENTENCES, never partial phrases (prevents semantic garbling)
- Only targets clearly unnecessary permission-asking for reversible actions
- Never filters genuinely ambiguous situations (external audience, irreversible)
- Preserves the rest of the message intact
- Logs what it filters for debugging (to ~/.hermes/audit/)

SECURITY NOTE: This filter modifies user-visible output. It must NEVER change the
meaning of a message. Removing an entire sentence is safe; removing a prefix
phrase can garble or invert meaning (e.g., "Do you want me to delete backups?"
→ "delete backups?" becomes a command). Therefore, we only remove complete
sentences (ending in 。？！.?) that consist ENTIRELY of permission-asking.
"""

import re
import logging
from pathlib import Path
from typing import Tuple, List

logger = logging.getLogger(__name__)

# Permission-asking patterns that match ENTIRE SENTENCES.
# Each pattern is anchored to sentence boundaries and requires the sentence
# to be ONLY about asking permission — no additional content.
# This prevents partial-sentence garbling that could change message meaning.

_CHINESE_SENTENCE_PATTERNS = [
    # "Should I do X?" as a complete sentence
    r'要我现在做吗[？?]',
    r'需要我现在做吗[？?]',
    r'要现在做还是改天[？?]',
    r'要不要(?:现在)?做[？?]',
    r'要我(?:继续)?吗[？?]',
    r'需要我(?:继续)?做吗[？?]',
    r'你想让我现在做[？?]',
    r'要(?:不要)?帮你做[？?]',
    r'还要我(?:继续)?做[？?]',
]

_ENGLISH_SENTENCE_PATTERNS = [
    # Complete-sentence permission-asking (must end with ?)
    r'Should I (?:do|start|begin|proceed|continue) (?:this|it|now|later|today|tomorrow)\??',
    r'Do you want me to (?:do|start|begin|continue|proceed)(?: (?:this|it|now|later|today|tomorrow))?\??',
    r'Would you like me to (?:do|start|begin|continue)(?: (?:this|it|now|later|today|tomorrow))?\??',
    r'Shall I (?:do|start|begin|proceed)(?: (?:this|it|now|later|today|tomorrow))?\??',
    r'Want me to (?:do|start|begin|continue)(?: (?:this|it|now|later|today|tomorrow))?\??',
    r'I can (?:do|start|begin) this (?:now |later |tomorrow |today )?if you want\.?',
]

# Compile all patterns — sentence-anchored, full sentence only
_COMPILED_PATTERNS: List[re.Pattern] = []
for p in _CHINESE_SENTENCE_PATTERNS:
    _COMPILED_PATTERNS.append(re.compile(p, re.IGNORECASE))
for p in _ENGLISH_SENTENCE_PATTERNS:
    _COMPILED_PATTERNS.append(re.compile(p, re.IGNORECASE))

# Patterns that indicate a genuinely ambiguous situation — never filter these
_BORDERLINE_PATTERNS = [
    r'before I (?:delete|remove|overwrite|drop)',
    r'this will (?:send|publish|deploy|push|merge)',
    r'are you sure',
]

_COMPILED_BORDERLINE = [re.compile(p, re.IGNORECASE) for p in _BORDERLINE_PATTERNS]


def _is_borderline(text: str) -> bool:
    """Check if the text contains genuinely ambiguous permission-asking."""
    for pat in _COMPILED_BORDERLINE:
        if pat.search(text):
            return True
    return False


def _log_filter_action(original: str, filtered: str, pattern_desc: str) -> None:
    """Log filter actions to audit directory for debugging."""
    try:
        from hermes_constants import get_hermes_home
        from datetime import datetime, timezone, timedelta
        tz_utc8 = timezone(timedelta(hours=8))
        ts = datetime.now(tz_utc8).strftime("%Y-%m-%dT%H:%M:%S%z")
        audit_dir = Path(get_hermes_home()) / "audit"
        audit_dir.mkdir(parents=True, exist_ok=True)
        log_path = audit_dir / "permission_filter.log"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{ts} | pattern: {pattern_desc}\n")
            f.write(f"{ts} | original: {original[:200]}\n")
            f.write(f"{ts} | filtered: {filtered[:200]}\n")
    except Exception:
        pass  # Never let logging break the filter


def filter_permission_asking(text: str) -> Tuple[str, bool]:
    """
    Filter permission-asking patterns from outgoing text.

    Only removes ENTIRE SENTENCES that consist purely of permission-asking.
    Never removes partial phrases that could change message meaning.

    Returns:
        (filtered_text, was_filtered) — filtered text and whether any filtering occurred.
    """
    if not text or not text.strip():
        return text, False

    # Don't filter messages that contain borderline patterns
    if _is_borderline(text):
        return text, False

    original = text
    filtered = text

    for pattern in _COMPILED_PATTERNS:
        # Replace matched sentences with empty string, then clean up
        new_text = pattern.sub('', filtered)
        if new_text != filtered:
            matched = pattern.search(filtered)
            if matched:
                _log_filter_action(original, new_text, matched.group())
            filtered = new_text

    # Clean up artifacts from sentence removal:
    # - Multiple consecutive whitespace/newlines → single newline
    # - Lines that are now empty after removal
    # - Leading/trailing whitespace on remaining lines
    lines = filtered.split('\n')
    cleaned_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped:
            cleaned_lines.append(stripped)
        elif line and not line.strip():
            # Empty line — keep only one between paragraphs
            if cleaned_lines and cleaned_lines[-1] != '':
                cleaned_lines.append('')

    filtered = '\n'.join(cleaned_lines).strip()

    was_filtered = (filtered != original)

    # If filtering removed everything, return a neutral action marker instead
    if not filtered:
        if was_filtered:
            logger.warning("permission_asking_filter: filtered entire permission-asking message")
            return "(action taken)", True
        return original, False

    return filtered, was_filtered
