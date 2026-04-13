"""
Audit Passport — Records Claude Code audit sessions for Layer F enforcement.

When ask-claude.sh completes an audit, it calls record_audit_passport() to
create an entry in ~/.hermes/audit/passports.jsonl

This passport is then checked by audit_guard.py before allowing git commit
of logic changes.
"""

import json
import hmac
import hashlib
import os
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional

_write_lock = threading.Lock()


def _get_hmac_key() -> bytes:
    """Get HMAC key derived from machine identity. Stable across restarts."""
    import hashlib
    # Derive from username + hostname — stable, no file dependency
    import getpass
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    import socket
    hostname = socket.gethostname()
    # Combine with a fixed salt for Hermes audit passports
    identity = f"hermes-audit:{user}@{hostname}".encode("utf-8")
    return hashlib.sha256(identity).digest()


def _get_passports_path() -> Path:
    """Get the passports log file path."""
    from hermes_constants import get_hermes_home
    audit_dir = Path(get_hermes_home()) / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    return audit_dir / "passports.jsonl"


def _get_timestamp() -> str:
    """Get ISO8601 timestamp with +08:00 offset."""
    tz_utc8 = timezone(timedelta(hours=8))
    return datetime.now(tz_utc8).strftime("%Y-%m-%dT%H:%M:%S%z")


def _sign_passport(entry: dict) -> str:
    """Create HMAC signature for passport integrity."""
    key = _get_hmac_key()
    sign_data = "{}|{}|{}".format(
        entry.get("passport_id", ""),
        entry.get("timestamp", ""),
        "|".join(sorted(entry.get("files_audited", [])))
    )
    return hmac.new(key, sign_data.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def verify_passport_signature(entry: dict) -> bool:
    """Verify that a passport entry has a valid HMAC signature."""
    try:
        stored_sig = entry.get("signature", "")
        if not stored_sig:
            return False
        expected_sig = _sign_passport(entry)
        return hmac.compare_digest(stored_sig, expected_sig)
    except Exception:
        return False


def record_audit_passport(
    passport_id: str,
    files_audited: List[str],
    diff_hashes_covered: List[str],
    audit_tool: str = "claude-code",
    adversarial_prompt: bool = True,
    severity_findings: Optional[dict] = None,
) -> str:
    """Record an audit passport entry."""
    try:
        entry = {
            "timestamp": _get_timestamp(),
            "passport_id": passport_id,
            "files_audited": sorted(files_audited),
            "diff_hashes_covered": sorted(diff_hashes_covered),
            "audit_tool": audit_tool,
            "adversarial_prompt": adversarial_prompt,
            "severity_findings": severity_findings or {},
        }
        entry["signature"] = _sign_passport(entry)

        passports_path = _get_passports_path()
        with _write_lock:
            with open(passports_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        try:
            from tools.change_tracker import mark_changes_audited
            mark_changes_audited(passport_id, files_audited, diff_hashes_covered)
        except Exception:
            pass

        return passport_id
    except Exception:
        return passport_id


def get_recent_passports(limit: int = 50) -> list:
    """Get the N most recent audit passports."""
    try:
        passports_path = _get_passports_path()
        if not passports_path.exists():
            return []
        passports = []
        with _write_lock:
            with open(passports_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        passports.append(entry)
                    except json.JSONDecodeError:
                        continue
        passports.reverse()
        return passports[:limit]
    except Exception:
        return []


def is_change_audited(file_path: str, diff_hash: Optional[str] = None) -> bool:
    """Check if a specific file change has been covered by a recent audit passport."""
    try:
        passports = get_recent_passports(limit=20)
        for passport in passports:
            if not verify_passport_signature(passport):
                continue
            if file_path in passport.get("files_audited", []):
                return True
            if diff_hash and diff_hash in passport.get("diff_hashes_covered", []):
                return True
        return False
    except Exception:
        return False
