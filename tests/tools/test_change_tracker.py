"""Tests for change_tracker and audit passport path normalization behavior."""

import json
import os
from pathlib import Path

from tools.audit_passport import is_change_audited, record_audit_passport
from tools.change_tracker import (
    _get_changes_path,
    _read_state,
    mark_changes_audited,
    record_change,
)


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_mark_changes_audited_requires_file_and_diff_hash(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    first_path = tmp_path / "foo.py"
    second_path = tmp_path / "bar.py"
    first_path.write_text("print('one')\n", encoding="utf-8")
    second_path.write_text("print('two')\n", encoding="utf-8")

    record_change(str(first_path), "write_file", "print('one')\n", "hash-a")
    record_change(str(first_path), "write_file", "print('two')\n", "hash-b")
    record_change(str(second_path), "write_file", "print('three')\n", "hash-a")

    updated = mark_changes_audited("passport-1", [str(first_path)], ["hash-a"])

    assert updated == 1

    # Audit status is maintained in the state file (authoritative source).
    # Journal is append-only; its audited field is set at creation time and never updated.
    state = _read_state()
    first_entry = state["files"].get(str(first_path.resolve()))
    assert first_entry is not None, f"Expected state entry for {first_path.resolve()}, got: {list(state['files'].keys())}"
    assert first_entry["audited"] is True
    assert first_entry["passport_id"] == "passport-1"


def test_record_change_accepts_source_kwarg(tmp_path, monkeypatch):
    """Regression: record_change must accept source= without raising TypeError.

    The ``source`` kwarg was added after callers started passing it (see
    the recurring ``TypeError: record_change() got an unexpected keyword
    argument 'source'`` between 2026-04-13 and 2026-04-17). This test locks
    the signature so future refactors cannot silently remove it.
    """
    monkeypatch.chdir(tmp_path)

    target = tmp_path / "foo.py"
    target.write_text("print('one')\n", encoding="utf-8")

    # Must not raise — this is the regression guard.
    record_change(
        str(target),
        operation="terminal",
        diff_text="ls -la",
        source="terminal",
    )


def test_record_change_persists_source_in_journal_and_state(tmp_path, monkeypatch):
    """The source tag is written to both the journal entry and state entry.

    Without persistence the kwarg would be accepted but useless — callers
    would think attribution was being tracked when it wasn't.
    """
    monkeypatch.chdir(tmp_path)

    target = tmp_path / "foo.py"
    target.write_text("print('one')\n", encoding="utf-8")

    record_change(
        str(target),
        operation="write_file",
        diff_text="print('one')\n",
        content_hash="hash-src",
        source="write_file",
    )

    # Journal: find the entry we just wrote and assert source is recorded.
    entries = _read_jsonl(_get_changes_path())
    matching = [e for e in entries if e.get("diff_hash") == "hash-src"]
    assert matching, "record_change did not append a journal entry"
    assert matching[-1].get("source") == "write_file"

    # State file: the latest entry for this path carries the source tag.
    state = _read_state()
    state_entry = state["files"].get(str(target.resolve()))
    assert state_entry is not None
    assert state_entry.get("source") == "write_file"


def test_audit_passport_path_checks_use_normalized_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    target = tmp_path / "nested" / ".." / "nested" / "file.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("print('ok')\n", encoding="utf-8")

    raw_path = str(tmp_path / "nested" / ".." / "nested" / "file.py")
    normalized_path = str((tmp_path / "nested" / "file.py").resolve())

    record_audit_passport("passport-1", [raw_path], ["hash-1"])

    assert is_change_audited(normalized_path) is True
