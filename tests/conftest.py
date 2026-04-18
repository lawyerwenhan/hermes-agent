"""Shared fixtures for the hermes-agent test suite.

IMPORTANT: the module-level block below runs before pytest collects
any tests (and before any test module is imported), so modules that
cache ``HERMES_HOME`` at import time (e.g. ``run_agent._hermes_home``
and the logger wired up by ``hermes_logging.setup_logging``) resolve
the tmp path instead of writing to the real ``~/.hermes/logs/`` —
which is what caused pytest runs to dump hundreds of fixture-induced
ERROR lines into production ``errors.log``.
"""

import asyncio
import atexit
import os
import shutil
import signal
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ─── Session-wide HERMES_HOME isolation ────────────────────────────────────
# Done at *module import time* (before any test module is collected) so
# that modules which snapshot ``HERMES_HOME`` / ``get_hermes_home()`` at
# import time (e.g. ``run_agent._hermes_home``) and loggers that wire up
# ``errors.log`` via ``hermes_logging.setup_logging`` cannot leak writes
# to the real ``~/.hermes/logs/errors.log`` on the host.
#
# Each pytest-xdist worker process re-runs this block, which is the
# correct behaviour — every worker gets its own isolated fake home.
_SESSION_FAKE_HOME = Path(tempfile.mkdtemp(prefix="hermes-pytest-home-"))
for _sub in ("sessions", "cron", "memories", "skills", "logs", "plugins"):
    (_SESSION_FAKE_HOME / _sub).mkdir(parents=True, exist_ok=True)
os.environ["HERMES_HOME"] = str(_SESSION_FAKE_HOME)

# Best-effort cleanup on interpreter exit. Not critical — ``tempfile``
# dirs are under /tmp and cleaned by the OS — but keeps runs tidy.
@atexit.register
def _cleanup_session_fake_home() -> None:
    try:
        shutil.rmtree(_SESSION_FAKE_HOME, ignore_errors=True)
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _isolate_hermes_home(tmp_path, monkeypatch):
    """Redirect HERMES_HOME to a per-test temp dir so tests never write to ~/.hermes/.

    Note: a *session-wide* fake ``HERMES_HOME`` is already installed at
    conftest import time (see module-level block above). This fixture
    additionally narrows the scope to a per-test tmp dir so tests that
    inspect ``HERMES_HOME``-rooted files see a clean slate. Module-level
    caches (``run_agent._hermes_home``, logging handlers) stay bound to
    the session-wide fake home — which is still outside ``~/.hermes/``
    so the production ``errors.log`` is safe either way.
    """
    fake_home = tmp_path / "hermes_test"
    fake_home.mkdir()
    (fake_home / "sessions").mkdir()
    (fake_home / "cron").mkdir()
    (fake_home / "memories").mkdir()
    (fake_home / "skills").mkdir()
    monkeypatch.setenv("HERMES_HOME", str(fake_home))
    # Reset plugin singleton so tests don't leak plugins from ~/.hermes/plugins/
    try:
        import hermes_cli.plugins as _plugins_mod
        monkeypatch.setattr(_plugins_mod, "_plugin_manager", None)
    except Exception:
        pass
    # Tests should not inherit the agent's current gateway/messaging surface.
    # Individual tests that need gateway behavior set these explicitly.
    monkeypatch.delenv("HERMES_SESSION_PLATFORM", raising=False)
    monkeypatch.delenv("HERMES_SESSION_CHAT_ID", raising=False)
    monkeypatch.delenv("HERMES_SESSION_CHAT_NAME", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
    # Avoid making real calls during tests if this key is set in the env files
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)


@pytest.fixture()
def tmp_dir(tmp_path):
    """Provide a temporary directory that is cleaned up automatically."""
    return tmp_path


@pytest.fixture()
def mock_config():
    """Return a minimal hermes config dict suitable for unit tests."""
    return {
        "model": "test/mock-model",
        "toolsets": ["terminal", "file"],
        "max_turns": 10,
        "terminal": {
            "backend": "local",
            "cwd": "/tmp",
            "timeout": 30,
        },
        "compression": {"enabled": False},
        "memory": {"memory_enabled": False, "user_profile_enabled": False},
        "command_allowlist": [],
    }


# ── Global test timeout ─────────────────────────────────────────────────────
# Kill any individual test that takes longer than 30 seconds.
# Prevents hanging tests (subprocess spawns, blocking I/O) from stalling the
# entire test suite.

def _timeout_handler(signum, frame):
    raise TimeoutError("Test exceeded 30 second timeout")

@pytest.fixture(autouse=True)
def _ensure_current_event_loop(request):
    """Provide a default event loop for sync tests that call get_event_loop().

    Python 3.11+ no longer guarantees a current loop for plain synchronous tests.
    A number of gateway tests still use asyncio.get_event_loop().run_until_complete(...).
    Ensure they always have a usable loop without interfering with pytest-asyncio's
    own loop management for @pytest.mark.asyncio tests.
    """
    if request.node.get_closest_marker("asyncio") is not None:
        yield
        return

    try:
        loop = asyncio.get_event_loop_policy().get_event_loop()
    except RuntimeError:
        loop = None

    created = loop is None or loop.is_closed()
    if created:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    try:
        yield
    finally:
        if created and loop is not None:
            try:
                loop.close()
            finally:
                asyncio.set_event_loop(None)


@pytest.fixture(autouse=True)
def _enforce_test_timeout():
    """Kill any individual test that takes longer than 30 seconds.
    SIGALRM is Unix-only; skip on Windows."""
    if sys.platform == "win32":
        yield
        return
    old = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(30)
    yield
    signal.alarm(0)
    signal.signal(signal.SIGALRM, old)
