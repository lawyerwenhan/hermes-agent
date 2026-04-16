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
import secrets
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional

_write_lock = threading.Lock()


def _get_audit_dir() -> Path:
    """Get the audit state directory under the active HERMES_HOME."""
    from hermes_constants import get_hermes_home

    audit_dir = Path(get_hermes_home()) / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    return audit_dir


def _normalize_file_path(file_path: str) -> str:
    """Normalize file paths consistently with change_tracker."""
    return os.path.normpath(os.path.abspath(file_path))


def _get_hmac_key() -> bytes:
    """Get the persisted audit HMAC key, creating it on first use."""
    secret_path = _get_audit_dir() / ".audit_secret"

    with _write_lock:
        while True:
            try:
                key = secret_path.read_bytes()
                if key:
                    os.chmod(secret_path, 0o600)
                    return key
            except FileNotFoundError:
                pass

            key = secrets.token_bytes(32)
            try:
                fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(key)
            finally:
                os.chmod(secret_path, 0o600)
            return key


def _get_passports_path() -> Path:
    """Get the passports log file path."""
    return _get_audit_dir() / "passports.jsonl"


def _get_timestamp() -> str:
    """Get ISO8601 timestamp with +08:00 offset."""
    tz_utc8 = timezone(timedelta(hours=8))
    return datetime.now(tz_utc8).strftime("%Y-%m-%dT%H:%M:%S%z")


def _normalize_string_list(values: Optional[List[str]]) -> List[str]:
    """Normalize list-like passport fields into sorted strings."""
    if not values:
        return []
    return sorted(str(value) for value in values)


def _build_v1_sign_data(entry: dict) -> str:
    """Build the legacy HMAC payload for backward-compatible verification."""
    return "{}|{}|{}".format(
        entry.get("passport_id", ""),
        entry.get("timestamp", ""),
        "|".join(_normalize_string_list(entry.get("files_audited", []))),
    )


def _build_v2_sign_data(entry: dict) -> str:
    """Build the canonical HMAC payload for v2 passports."""
    sign_payload = {
        "version": "v2",
        "passport_id": entry.get("passport_id", ""),
        "timestamp": entry.get("timestamp", ""),
        "files_audited": _normalize_string_list(entry.get("files_audited", [])),
        "diff_hashes_covered": _normalize_string_list(entry.get("diff_hashes_covered", [])),
        "audit_tool": entry.get("audit_tool", ""),
        "adversarial_prompt": entry.get("adversarial_prompt", False),
    }
    return json.dumps(sign_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sign_passport(entry: dict) -> str:
    """Create HMAC signature for passport integrity."""
    key = _get_hmac_key()
    version = entry.get("version")
    sign_data = _build_v2_sign_data(entry) if version == "v2" else _build_v1_sign_data(entry)
    return hmac.new(key, sign_data.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def verify_passport_signature(entry: dict) -> bool:
    """Verify that a passport entry has a valid HMAC signature."""
    try:
        stored_sig = entry.get("signature", "")
        if not stored_sig:
            return False
        version = entry.get("version")
        if version not in (None, "v1", "v2"):
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
            "version": "v2",
            "timestamp": _get_timestamp(),
            "passport_id": passport_id,
            "files_audited": sorted(_normalize_file_path(path) for path in files_audited),
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
        import logging
        logging.getLogger("audit_passport").error("Failed to record audit passport", exc_info=True)
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
        normalized_path = _normalize_file_path(file_path)
        passports = get_recent_passports(limit=20)
        for passport in passports:
            if not verify_passport_signature(passport):
                continue
            normalized_files = {_normalize_file_path(path) for path in passport.get("files_audited", [])}
            if normalized_path in normalized_files:
                return True
            if diff_hash and diff_hash in passport.get("diff_hashes_covered", []):
                return True
        return False
    except Exception:
        return False
