import stat

from tools import audit_passport


def _legacy_signature(entry: dict, key: bytes) -> str:
    sign_data = "{}|{}|{}".format(
        entry.get("passport_id", ""),
        entry.get("timestamp", ""),
        "|".join(sorted(entry.get("files_audited", []))),
    )
    return audit_passport.hmac.new(
        key, sign_data.encode("utf-8"), audit_passport.hashlib.sha256
    ).hexdigest()[:32]


def test_v2_signature_covers_security_fields(monkeypatch):
    key = b"test-key-material-32-bytes-long!!"
    monkeypatch.setattr(audit_passport, "_get_hmac_key", lambda: key)

    entry = {
        "version": "v2",
        "passport_id": "pp-123",
        "timestamp": "2026-04-13T12:00:00+0800",
        "files_audited": ["b.py", "a.py"],
        "diff_hashes_covered": ["diff-b", "diff-a"],
        "audit_tool": "claude-code",
        "adversarial_prompt": True,
    }
    entry["signature"] = audit_passport._sign_passport(entry)

    assert audit_passport.verify_passport_signature(entry) is True

    tampered_diff_hashes = dict(entry)
    tampered_diff_hashes["diff_hashes_covered"] = ["other-diff"]
    assert audit_passport.verify_passport_signature(tampered_diff_hashes) is False

    tampered_tool = dict(entry)
    tampered_tool["audit_tool"] = "manual"
    assert audit_passport.verify_passport_signature(tampered_tool) is False

    tampered_prompt = dict(entry)
    tampered_prompt["adversarial_prompt"] = False
    assert audit_passport.verify_passport_signature(tampered_prompt) is False


def test_v2_signature_is_deterministic_for_list_order(monkeypatch):
    key = b"test-key-material-32-bytes-long!!"
    monkeypatch.setattr(audit_passport, "_get_hmac_key", lambda: key)

    entry_a = {
        "version": "v2",
        "passport_id": "pp-123",
        "timestamp": "2026-04-13T12:00:00+0800",
        "files_audited": ["b.py", "a.py"],
        "diff_hashes_covered": ["diff-b", "diff-a"],
        "audit_tool": "claude-code",
        "adversarial_prompt": True,
    }
    entry_b = {
        "version": "v2",
        "passport_id": "pp-123",
        "timestamp": "2026-04-13T12:00:00+0800",
        "files_audited": ["a.py", "b.py"],
        "diff_hashes_covered": ["diff-a", "diff-b"],
        "audit_tool": "claude-code",
        "adversarial_prompt": True,
    }

    assert audit_passport._sign_passport(entry_a) == audit_passport._sign_passport(entry_b)


def test_verify_passport_signature_accepts_legacy_unversioned_passport(monkeypatch):
    key = b"legacy-test-key-material-32-bytes"
    monkeypatch.setattr(audit_passport, "_get_hmac_key", lambda: key)

    legacy_entry = {
        "passport_id": "pp-legacy",
        "timestamp": "2026-04-13T12:00:00+0800",
        "files_audited": ["b.py", "a.py"],
        "diff_hashes_covered": ["diff-a"],
        "audit_tool": "claude-code",
        "adversarial_prompt": True,
    }
    legacy_entry["signature"] = _legacy_signature(legacy_entry, key)

    assert audit_passport.verify_passport_signature(legacy_entry) is True


def test_get_hmac_key_persists_secret_with_strict_permissions(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))

    key1 = audit_passport._get_hmac_key()
    key2 = audit_passport._get_hmac_key()
    secret_path = tmp_path / "hermes-home" / "audit" / ".audit_secret"

    assert secret_path.exists()
    assert key1 == key2 == secret_path.read_bytes()
    assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600
