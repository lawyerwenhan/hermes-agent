"""Regression tests for sudo detection and sudo password handling."""

import json
from types import SimpleNamespace

import tools.terminal_tool as terminal_tool


def setup_function():
    terminal_tool._cached_sudo_password = ""


def teardown_function():
    terminal_tool._cached_sudo_password = ""


def test_searching_for_sudo_does_not_trigger_rewrite(monkeypatch):
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)

    command = "rg --line-number --no-heading --with-filename 'sudo' . | head -n 20"
    transformed, sudo_stdin = terminal_tool._transform_sudo_command(command)

    assert transformed == command
    assert sudo_stdin is None


def test_printf_literal_sudo_does_not_trigger_rewrite(monkeypatch):
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)

    command = "printf '%s\\n' sudo"
    transformed, sudo_stdin = terminal_tool._transform_sudo_command(command)

    assert transformed == command
    assert sudo_stdin is None


def test_non_command_argument_named_sudo_does_not_trigger_rewrite(monkeypatch):
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)

    command = "grep -n sudo README.md"
    transformed, sudo_stdin = terminal_tool._transform_sudo_command(command)

    assert transformed == command
    assert sudo_stdin is None


def test_actual_sudo_command_uses_configured_password(monkeypatch):
    monkeypatch.setenv("SUDO_PASSWORD", "testpass")
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)

    transformed, sudo_stdin = terminal_tool._transform_sudo_command("sudo apt install -y ripgrep")

    assert transformed == "sudo -S -p '' apt install -y ripgrep"
    assert sudo_stdin == "testpass\n"


def test_actual_sudo_after_leading_env_assignment_is_rewritten(monkeypatch):
    monkeypatch.setenv("SUDO_PASSWORD", "testpass")
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)

    transformed, sudo_stdin = terminal_tool._transform_sudo_command("DEBUG=1 sudo whoami")

    assert transformed == "DEBUG=1 sudo -S -p '' whoami"
    assert sudo_stdin == "testpass\n"


def test_explicit_empty_sudo_password_tries_empty_without_prompt(monkeypatch):
    monkeypatch.setenv("SUDO_PASSWORD", "")
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")

    def _fail_prompt(*_args, **_kwargs):
        raise AssertionError("interactive sudo prompt should not run for explicit empty password")

    monkeypatch.setattr(terminal_tool, "_prompt_for_sudo_password", _fail_prompt)

    transformed, sudo_stdin = terminal_tool._transform_sudo_command("sudo true")

    assert transformed == "sudo -S -p '' true"
    assert sudo_stdin == "\n"


def test_cached_sudo_password_is_used_when_env_is_unset(monkeypatch):
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)
    terminal_tool._cached_sudo_password = "cached-pass"

    transformed, sudo_stdin = terminal_tool._transform_sudo_command("echo ok && sudo whoami")

    assert transformed == "echo ok && sudo -S -p '' whoami"
    assert sudo_stdin == "cached-pass\n"


def test_terminal_tool_tracks_git_detected_file_changes_on_success(monkeypatch, tmp_path):
    config = {
        "env_type": "local",
        "docker_image": "",
        "singularity_image": "",
        "modal_image": "",
        "daytona_image": "",
        "cwd": str(tmp_path),
        "timeout": 30,
    }
    dummy_env = SimpleNamespace(env={}, execute=lambda *_args, **_kwargs: {"output": "ok", "returncode": 0})
    tracker_calls = []

    monkeypatch.setattr(terminal_tool, "_get_env_config", lambda: config)
    monkeypatch.setattr(terminal_tool, "_start_cleanup_thread", lambda: None)
    monkeypatch.setattr(terminal_tool, "_check_all_guards", lambda *_args, **_kwargs: {"approved": True})
    monkeypatch.setattr(terminal_tool, "_terminal_tracking_repo_root", lambda _cwd: tmp_path)
    monkeypatch.setattr(terminal_tool, "_capture_git_porcelain", lambda _cwd: "")
    monkeypatch.setattr(
        terminal_tool,
        "_track_terminal_side_file_changes",
        lambda **kwargs: tracker_calls.append(kwargs),
    )
    monkeypatch.setitem(terminal_tool._active_environments, "default", dummy_env)
    monkeypatch.setitem(terminal_tool._last_activity, "default", 0.0)

    try:
        result = json.loads(terminal_tool.terminal_tool(command="python -c 'print(1)'"))
    finally:
        terminal_tool._active_environments.pop("default", None)
        terminal_tool._last_activity.pop("default", None)

    assert result["exit_code"] == 0
    assert tracker_calls == [{
        "command": "python -c 'print(1)'",
        "cwd": str(tmp_path),
        "git_state_before": "",
    }]


def test_terminal_tool_skips_git_tracking_on_failed_command(monkeypatch, tmp_path):
    config = {
        "env_type": "local",
        "docker_image": "",
        "singularity_image": "",
        "modal_image": "",
        "daytona_image": "",
        "cwd": str(tmp_path),
        "timeout": 30,
    }
    dummy_env = SimpleNamespace(env={}, execute=lambda *_args, **_kwargs: {"output": "nope", "returncode": 2})

    monkeypatch.setattr(terminal_tool, "_get_env_config", lambda: config)
    monkeypatch.setattr(terminal_tool, "_start_cleanup_thread", lambda: None)
    monkeypatch.setattr(terminal_tool, "_check_all_guards", lambda *_args, **_kwargs: {"approved": True})
    monkeypatch.setattr(terminal_tool, "_terminal_tracking_repo_root", lambda _cwd: tmp_path)
    monkeypatch.setattr(terminal_tool, "_capture_git_porcelain", lambda _cwd: "")

    def _fail_if_called(**_kwargs):
        raise AssertionError("tracking should not run for non-zero exits")

    monkeypatch.setattr(terminal_tool, "_track_terminal_side_file_changes", _fail_if_called)
    monkeypatch.setitem(terminal_tool._active_environments, "default", dummy_env)
    monkeypatch.setitem(terminal_tool._last_activity, "default", 0.0)

    try:
        result = json.loads(terminal_tool.terminal_tool(command="python -c 'raise SystemExit(2)'"))
    finally:
        terminal_tool._active_environments.pop("default", None)
        terminal_tool._last_activity.pop("default", None)

    assert result["exit_code"] == 2
