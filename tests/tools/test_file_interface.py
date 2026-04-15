"""Tests for tools.file_interface — file-based subagent context passing."""

import json
import os
import time
import tempfile
import pytest

# Isolate HERMES_HOME
@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    os.makedirs(str(tmp_path / ".hermes"), exist_ok=True)


def _fi():
    """Import file_interface fresh (respects HERMES_HOME)."""
    from tools.file_interface import (
        write_task_output,
        read_task_output,
        resolve_file_refs,
        cleanup_task_files,
        cleanup_expired_files,
        get_task_output_dir,
    )
    return write_task_output, read_task_output, resolve_file_refs, cleanup_task_files, cleanup_expired_files, get_task_output_dir


class TestWriteAndRead:
    def test_roundtrip(self):
        write, read, *_ = _fi()
        path = write({"key": "value"}, "task-1", "brainstorm", "decision")
        assert os.path.isfile(path)

        data = read(path)
        assert data is not None
        assert data["payload"] == {"key": "value"}
        meta = data["_hermes_meta"]
        assert meta["task_id"] == "task-1"
        assert meta["upstream_skill"] == "brainstorm"
        assert meta["type"] == "decision"

    def test_read_nonexistent(self):
        _, read, *_ = _fi()
        assert read("/tmp/nonexistent_hermes_12345.json") is None

    def test_read_corrupt(self):
        _, read, *_ = _fi()
        from tools.file_interface import get_task_output_dir
        corrupt = os.path.join(get_task_output_dir(), "bad.json")
        with open(corrupt, "w") as f:
            f.write("not json{{{")
        assert read(corrupt) is None


class TestResolveFileRefs:
    def test_json_context_with_file_ref(self):
        write, _, resolve, *_ = _fi()
        path = write({"big": "data" * 200}, "t1", "skill_a", "result")

        context = json.dumps({"__hermes_file_ref": path, "extra": "info"})
        resolved = resolve(context)
        assert "[FILE REF:" in resolved
        assert "skill_a" in resolved
        assert '"big"' in resolved

    def test_plain_text_context_unchanged(self):
        _, _, resolve, *_ = _fi()
        assert resolve("just some text") == "just some text"

    def test_empty_context(self):
        _, _, resolve, *_ = _fi()
        assert resolve("") == ""
        assert resolve(None) is None

    def test_invalid_file_ref_falls_back(self):
        _, _, resolve, *_ = _fi()
        context = json.dumps({"__hermes_file_ref": "/tmp/no_such_file.json"})
        resolved = resolve(context)
        # Should fall back to original context since file doesn't exist
        assert "__hermes_file_ref" in resolved


class TestCleanup:
    def test_cleanup_by_task_id(self):
        write, _, _, cleanup, *_ = _fi()
        write("data1", "abc-1", "s1", "r1")
        write("data2", "abc-1", "s1", "r2")
        write("data3", "xyz-2", "s2", "r3")

        deleted = cleanup("abc-1")
        assert deleted == 2

        # xyz-2 should still exist
        _, _, _, _, _, get_dir = _fi()
        remaining = [f for f in os.listdir(get_dir()) if f.startswith("xyz")]
        assert len(remaining) == 1

    def test_cleanup_expired_files(self):
        write, _, _, _, cleanup_expired, get_dir = _fi()
        # Write a file with TTL=0 (already expired)
        path = write("expired", "exp-1", "s1", "r1", ttl_hours=0)
        # Set mtime to 2 days ago so the fallback also catches it
        old_time = time.time() - 48 * 3600
        os.utime(path, (old_time, old_time))

        # Write a fresh file (should NOT be cleaned)
        write("fresh", "fresh-1", "s1", "r1", ttl_hours=24)

        deleted = cleanup_expired()
        # The 0-hour TTL file should be cleaned, fresh one should remain
        assert deleted >= 1

    def test_cleanup_no_dir(self):
        _, _, _, _, cleanup_expired, _ = _fi()
        # Should not crash when dir doesn't exist
        assert cleanup_expired() == 0