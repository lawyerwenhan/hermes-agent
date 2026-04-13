"""
Permission-asking output filter — Layer 2 of the anti-permission-asking system.

Intercepts outgoing messages and removes or transforms permission-asking patterns
that should have been actions instead. This is a hard constraint at the message
delivery layer — the user never sees the filtered content.

This does NOT replace the system prompt rules (Layer 1). It's a safety net for
when the model ignores soft constraints.

Design principles:
- Only removes/transforms, never adds content
- Only targets clearly unnecessary permission-asking for reversible actions
- Never filters genuinely ambiguous situations (external audience, irreversible)
- Preserves the rest of the message intact
- Logs what it filters for debugging (to ~/.hermes/audit/)
"""

import re
import os
from pathlib import Path
from typing import Tuple

# Permission-asking patterns to filter
# Each pattern: (regex, replacement)
# Replacement:
#   - "" means remove the sentence entirely
#   - A string means replace with that string
#   - None means this is a borderline case — log but don't filter
_ASKING_PATTERNS = [
    # Chinese patterns (Vince's primary language)
    (r'要我现在做吗[？?]', ''),
    (r'需要我现在做吗[？?]', ''),
    (r'要现在做还是改天[？?]', ''),
    (r'要不要(?:现在)?做[？?]', ''),
    (r'要(?:不要)?(?:我)?帮你做[？?]', ''),
    (r'你想让我现在做[？?]', ''),
    (r'需要我(?:继续)?做吗[？?]', ''),
    (r'要我(?:继续)?吗[？?]', ''),
    # English patterns
    (r'[Ss]hould I (?:do|start|begin|proceed|continue) ',
     ''),
    (r'[Dd]o you want me to ',
     ''),
    (r'[Ww]ould you like me to ',
     ''),
    (r'[Aa]re you sure you want me to ',
     ''),
    (r'[Ss]hall I ',
     ''),
    (r'[Ww]ant me to ',
     ''),
    (r'[Ii] can (?:do|start|begin) this (?:now |later |tomorrow |today )?if you want\.?', ''),
]

# Patterns that indicate a genuinely ambiguous situation — log but don't filter
_BORDERLINE_PATTERNS = [
    r'are you sure',  # Could be a genuine safety check
    r'before I (?:delete|remove|overwrite)',  # Genuinely irreversible
    r'this will (?:send|publish|deploy)',  # External audience
]

# Compile patterns once
_COMPILED_ASKING = [(re.compile(p, re.IGNORECASE), r) for p, r in _ASKING_PATTERNS]
_COMPILED_BORDERLINE = [re.compile(p, re.IGNORECASE) for p in _BORDERLINE_PATTERNS]


def _is_borderline(text: str) -> bool:
    """Check if the text contains genuinely ambiguous permission-asking."""
    for pat in _COMPILED_BORDERLINE:
        if pat.search(text):
            return True
    return False


def _log_filter_action(original: str, filtered: str, pattern_matched: str) -> None:
    """Log filter actions to audit directory for debugging."""
    try:
        from hermes_constants import get_hermes_home
        audit_dir = Path(get_hermes_home()) / "audit"
        audit_dir.mkdir(parents=True, exist_ok=True)
        log_path = audit_dir / "permission_filter.log"

        from datetime import datetime, timezone, timedelta
        tz_utc8 = timezone(timedelta(hours=8))
        ts = datetime.now(tz_utc8).strftime("%Y-%m-%dT%H:%M:%S%z")

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{ts} | filtered | pattern: {pattern_matched[:80]}\n")
            f.write(f"{ts} | original_snippet | {original[:200]}\n")
            f.write(f"{ts} | filtered_snippet | {filtered[:200]}\n")
    except Exception:
        pass  # Never let logging break the filter


def filter_permission_asking(text: str) -> Tuple[str, bool]:
    """
    Filter permission-asking patterns from outgoing text.

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

    for pattern, replacement in _COMPILED_ASKING:
        new_text = pattern.sub(replacement, filtered)
        if new_text != filtered:
            _log_filter_action(original, new_text, pattern.pattern)
            filtered = new_text

    # Clean up artifacts: double spaces, trailing/leading whitespace on lines
    filtered = re.sub(r'  +', ' ', filtered)
    filtered = re.sub(r'\n{3,}', '\n\n', filtered)
    filtered = filtered.strip()

    was_filtered = (filtered != original)
    return filtered, was_filtered