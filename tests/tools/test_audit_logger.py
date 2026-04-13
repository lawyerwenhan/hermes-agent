"""Tests for audit_logger escaping."""

import os
from pathlib import Path

from tools.audit_logger import log_file_write, log_terminal_command


def test_log_terminal_command_escapes_control_characters(monkeypatch):
    log_terminal_command("echo hi\nforged\rline\tend", 0, pattern="pat\ntern", blocked=True)

    hermes_home = Path(os.environ["HERMES_HOME"])
    log_file = next((hermes_home / "audit").glob("*.log"))
    contents = log_file.read_text(encoding="utf-8")
    assert "echo hi\\nforged\\rline\\tend" in contents
    assert "pat\\ntern" in contents
    assert "echo hi\nforged" not in contents


def test_log_file_write_escapes_control_characters(monkeypatch):
    log_file_write("file\nname\rx\tz", 0, pattern="pat\ntern", blocked=False)

    hermes_home = Path(os.environ["HERMES_HOME"])
    log_file = next((hermes_home / "audit").glob("*.log"))
    contents = log_file.read_text(encoding="utf-8")
    assert "file\\nname\\rx\\tz" in contents
    assert "pat\\ntern" in contents
    assert "file\nname" not in contents
